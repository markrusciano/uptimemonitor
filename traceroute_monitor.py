import subprocess
import sqlite3
import time
import argparse
import logging
import signal
import sys
from datetime import datetime, timedelta
import json  # For data serialization

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,  # Set to logging.DEBUG for more verbosity
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("traceroute_monitor.log"),  # Log to a file
        logging.StreamHandler()  # Log to console
    ]
)

# Database connection
DB_PATH = 'traceroute.db'

# Signal handler to safely exit the script
def handle_exit_signal(signum, frame):
    logging.info("Received signal to stop, exiting the script safely.")
    sys.exit(0)

# Register signal handlers for SIGINT (Ctrl+C) and SIGTERM
signal.signal(signal.SIGINT, handle_exit_signal)  # Handle Ctrl+C
signal.signal(signal.SIGTERM, handle_exit_signal)  # Handle kill command

# Function to run traceroute
def run_traceroute(ip_address, connection_name, interface, verbose=False):
    logging.info(f"Running traceroute on {interface} for {connection_name} to {ip_address}")
    try:
        result = subprocess.run(
            ['sudo', 'mtr', '--report', '--report-cycles', '1', '-I', interface, ip_address],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        output = result.stdout

        if result.returncode != 0:
            logging.error(f"Traceroute on {interface} failed: {result.stderr}")
            return None, None

        if verbose:
            print(f"\nFull mtr output for {connection_name} ({interface}):\n{output}")

        # Extract packet loss for hops after the first hop
        packet_loss = []
        lines = output.splitlines()[2:]  # Skip the first two header lines of the mtr output
        for line in lines[1:]:  # Skip the first hop
            columns = line.split()
            if len(columns) >= 3:
                hostname = columns[1]
                if hostname == '???':
                    logging.debug(f"Skipping line with '???' hostname: {line}")
                    continue  # Skip this line
                loss_str = columns[2]
                try:
                    loss_value = float(loss_str.strip('%'))
                    # Ensure packet loss is within 0% to 100%
                    if 0 <= loss_value <= 100:
                        packet_loss.append(loss_value)
                    else:
                        logging.warning(f"Ignoring out-of-range packet loss value: {loss_value}% in line: {line}")
                except ValueError:
                    logging.warning(f"Could not parse loss value '{loss_str}' in line: {line}")
            else:
                logging.warning(f"Unexpected line format: {line}")
        
        # Calculate the average packet loss after the first hop
        if packet_loss:
            avg_loss = sum(packet_loss) / len(packet_loss)
            logging.debug(f"Calculated average packet loss after the first hop: {avg_loss:.2f}%")
        else:
            avg_loss = None
            logging.warning(f"No valid packet loss data found for {interface}")
        
        return avg_loss, output  # Return both average loss and full output

    except Exception as e:
        logging.exception(f"Exception occurred during traceroute: {e}")
        return None, None

# Function to save results to SQLite database
def save_to_db(connection_name, target_ip, packet_loss):
    if packet_loss is None:
        logging.warning(f"No packet loss data to save for {connection_name} targeting {target_ip}")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = int(time.time())
        cursor.execute(
            "INSERT INTO traceroute_results (timestamp, connection_name, target_ip, packet_loss) VALUES (?, ?, ?, ?)",
            (timestamp, connection_name, target_ip, packet_loss)
        )
        conn.commit()
        logging.info(f"Saved packet loss data to DB for {connection_name}: {packet_loss:.2f}%")
        conn.close()

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    except Exception as e:
        logging.exception(f"Error saving data to database: {e}")

# Function to retrieve packet loss data for all connections merged by timestamp
def get_combined_packet_loss_data(connection_names):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        one_week_ago = int(time.time()) - (60 * 60 * 24 * 7)  # 1 week ago in UNIX timestamp

        # Retrieve data for all connections
        data = {}
        for connection_name in connection_names:
            cursor.execute("""
                SELECT timestamp, packet_loss FROM traceroute_results
                WHERE timestamp >= ? AND connection_name = ?
                ORDER BY timestamp ASC
            """, (one_week_ago, connection_name))
            data[connection_name] = cursor.fetchall()

        conn.close()

        # Merge data by timestamp
        combined_data = {}
        for connection_name in connection_names:
            for timestamp, packet_loss in data[connection_name]:
                if 0 <= packet_loss <= 100:
                    if timestamp not in combined_data:
                        combined_data[timestamp] = {}
                    combined_data[timestamp][connection_name] = packet_loss
                else:
                    logging.warning(f"Ignoring out-of-range packet loss value: {packet_loss}% at timestamp {timestamp}")

        # Convert combined data to sorted lists
        sorted_timestamps = sorted(combined_data.keys())
        times = [datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') for ts in sorted_timestamps]
        isp1_losses = []
        isp2_losses = []

        isp1_name = connection_names[0]
        isp2_name = connection_names[1]

        for ts in sorted_timestamps:
            isp1_losses.append(combined_data[ts].get(isp1_name, None))
            isp2_losses.append(combined_data[ts].get(isp2_name, None))

        return times, isp1_losses, isp2_losses

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return [], [], []
    except Exception as e:
        logging.exception(f"Error retrieving combined data from database: {e}")
        return [], [], []

# Function to calculate average packet loss for a specific time window
def get_average_packet_loss(time_window, connection_name):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        current_time = int(time.time())
        time_threshold = current_time - (time_window * 60)  # Convert minutes to seconds
        cursor.execute("""
            SELECT AVG(packet_loss) FROM traceroute_results
            WHERE timestamp >= ? AND connection_name = ?
        """, (time_threshold, connection_name))
        result = cursor.fetchone()[0]
        conn.close()
        if result is not None:
            logging.info(f"Calculated average packet loss for {connection_name} over the last {time_window} minutes: {result:.2f}%")
            return result
        else:
            logging.info(f"No data available for {connection_name} over the last {time_window} minutes.")
            return 0

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return 0
    except Exception as e:
        logging.exception(f"Error calculating average packet loss: {e}")
        return 0

# Function to generate HTML content with combined packet loss data and graph
def generate_html(connection_names):
    try:
        # Get combined data
        times, isp1_losses, isp2_losses = get_combined_packet_loss_data(connection_names)

        # Prepare averages for each connection
        averages_data = {}
        for connection_name in connection_names:
            averages = {
                "last_15_min": get_average_packet_loss(15, connection_name),
                "last_30_min": get_average_packet_loss(30, connection_name),
                "last_hour": get_average_packet_loss(60, connection_name),
                "last_day": get_average_packet_loss(60 * 24, connection_name),
                "last_week": get_average_packet_loss(60 * 24 * 7, connection_name)
            }
            averages_data[connection_name] = averages

        # JSON encode the data for JavaScript
        times_json = json.dumps(times)
        isp1_losses_json = json.dumps(isp1_losses)
        isp2_losses_json = json.dumps(isp2_losses)
        isp1_name = connection_names[0]
        isp2_name = connection_names[1]

        # Prepare the HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Packet Loss Monitoring</title>
            <!-- Include Chart.js from CDN -->
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <!-- Include modern CSS framework (Bootstrap) -->
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
            <style>
                body {{
                    background-color: #f8f9fa;
                    padding: 20px;
                }}
                h1 {{
                    margin-bottom: 30px;
                }}
                .card {{
                    margin-bottom: 30px;
                }}
                .table td, .table th {{
                    vertical-align: middle;
                }}
                .chart-container {{
                    position: relative;
                    height: 500px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="text-center">Packet Loss Monitoring</h1>
                <div class="card">
                    <div class="card-header">
                        <h2>Packet Loss Comparison</h2>
                    </div>
                    <div class="card-body">
                        <h3>Average Packet Loss</h3>
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Time Period</th>
                                    <th>{isp1_name} Packet Loss (%)</th>
                                    <th>{isp2_name} Packet Loss (%)</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Last 15 minutes</td>
                                    <td>{averages_data[isp1_name]['last_15_min']:.2f}</td>
                                    <td>{averages_data[isp2_name]['last_15_min']:.2f}</td>
                                </tr>
                                <tr>
                                    <td>Last 30 minutes</td>
                                    <td>{averages_data[isp1_name]['last_30_min']:.2f}</td>
                                    <td>{averages_data[isp2_name]['last_30_min']:.2f}</td>
                                </tr>
                                <tr>
                                    <td>Last hour</td>
                                    <td>{averages_data[isp1_name]['last_hour']:.2f}</td>
                                    <td>{averages_data[isp2_name]['last_hour']:.2f}</td>
                                </tr>
                                <tr>
                                    <td>Last day</td>
                                    <td>{averages_data[isp1_name]['last_day']:.2f}</td>
                                    <td>{averages_data[isp2_name]['last_day']:.2f}</td>
                                </tr>
                                <tr>
                                    <td>Last week</td>
                                    <td>{averages_data[isp1_name]['last_week']:.2f}</td>
                                    <td>{averages_data[isp2_name]['last_week']:.2f}</td>
                                </tr>
                            </tbody>
                        </table>
                        <h3>Packet Loss Over Time</h3>
                        <div class="chart-container">
                            <canvas id="packetLossChart"></canvas>
                        </div>
                    </div>
                </div>
                <!-- JavaScript to render the chart -->
                <script>
                    const ctx = document.getElementById('packetLossChart').getContext('2d');
                    const packetLossChart = new Chart(ctx, {{
                        type: 'line',
                        data: {{
                            labels: {times_json},
                            datasets: [
                                {{
                                    label: '{isp1_name} Packet Loss (%)',
                                    data: {isp1_losses_json},
                                    borderColor: 'orange',
                                    backgroundColor: 'rgba(255, 165, 0, 0.2)',
                                    fill: false,
                                    tension: 0.1,
                                }},
                                {{
                                    label: '{isp2_name} Packet Loss (%)',
                                    data: {isp2_losses_json},
                                    borderColor: 'red',
                                    backgroundColor: 'rgba(255, 0, 0, 0.2)',
                                    fill: false,
                                    tension: 0.1,
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    max: 100,
                                    title: {{
                                        display: true,
                                        text: 'Packet Loss (%)'
                                    }}
                                }},
                                x: {{
                                    display: true,
                                    title: {{
                                        display: true,
                                        text: 'Time'
                                    }},
                                    ticks: {{
                                        maxTicksLimit: 10,
                                        autoSkip: true
                                    }}
                                }}
                            }},
                            interaction: {{
                                mode: 'index',
                                intersect: false,
                            }},
                            plugins: {{
                                tooltip: {{
                                    mode: 'index',
                                    intersect: false,
                                }},
                                legend: {{
                                    display: true,
                                    position: 'top',
                                }}
                            }}
                        }}
                    }});
                </script>
                <p class="text-muted"><em>
                Disclaimer: This site, <strong>zentrostatus.com</strong>, is an independent, third-party resource created to track internet connectivity and packet loss statistics for personal and educational purposes. It is not affiliated with or endorsed by <strong>Zentro</strong> or any related company. All data provided on this site is collected through public and legal methods, and the results displayed are intended solely for informational purposes. Results are isolated to one point in the network and are not representative of network performance as a whole. This site does not claim to represent the official status or performance of Zentro's services.
                </em></p>
            </div>
        </body>
        </html>
        """

        with open("index.html", "w") as f:
            f.write(html_content)
        logging.info("HTML file generated successfully.")

    except Exception as e:
        logging.exception("Failed to generate HTML file")

if __name__ == "__main__":
    # Use argparse to accept command-line arguments
    parser = argparse.ArgumentParser(description='Run traceroutes and log packet loss.')
    parser.add_argument('--interfaces', required=True, nargs=2, help='Two network interfaces to use (e.g., eth0 eth1)')
    parser.add_argument('--target', required=True, help='Target IP address for traceroute')
    parser.add_argument('--connection-names', required=True, nargs=2, help='Connection names for the database entry for each interface')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output to see full mtr output')
    args = parser.parse_args()

    target_ip = args.target
    interfaces = args.interfaces
    connection_names = args.connection_names
    verbose = args.verbose

    logging.info("Starting traceroute monitoring script")
    logging.info(f"Target IP: {target_ip}, Interfaces: {interfaces}")

    # Ensure the database and table exist
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traceroute_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            connection_name TEXT,
            target_ip TEXT,
            packet_loss REAL
        )
    """)
    conn.commit()
    conn.close()

    # Run traceroutes every second for both interfaces
    while True:
        for i in range(2):  # Run for both interfaces
            interface = interfaces[i]
            connection_name = connection_names[i]

            packet_loss, mtr_output = run_traceroute(target_ip, connection_name, interface, verbose=verbose)
            save_to_db(connection_name, target_ip, packet_loss)
        
        # Generate the HTML file after every traceroute run
        generate_html(connection_names)

        time.sleep(1)  # Wait for 1 second before running the next set of traceroutes
