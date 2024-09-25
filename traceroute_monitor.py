import subprocess
import re
import sqlite3
import time
import argparse
import logging
import signal
import sys
from datetime import datetime, timedelta

# Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,  # Set to logging.INFO to reduce verbosity
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
                loss_str = columns[2]
                try:
                    loss_value = float(loss_str.strip('%'))
                    packet_loss.append(loss_value)
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

# Function to generate HTML content with packet loss averages
def generate_html(connection_names):
    try:
        html_content = f"""
        <html>
        <head>
            <title>Traceroute and Packet Loss Averages</title>
            <style>
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid black; padding: 8px; text-align: center; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Packet Loss Averages</h1>
        """

        for connection_name in connection_names:
            averages = {
                "last_15_min": get_average_packet_loss(15, connection_name),
                "last_30_min": get_average_packet_loss(30, connection_name),
                "last_hour": get_average_packet_loss(60, connection_name),
                "last_day": get_average_packet_loss(60 * 24, connection_name),
                "last_week": get_average_packet_loss(60 * 24 * 7, connection_name)
            }

            html_content += f"""
            <h2>{connection_name}</h2>
            <table>
                <tr>
                    <th>Time Period</th>
                    <th>Average Packet Loss (%)</th>
                </tr>
                <tr>
                    <td>Last 15 minutes</td>
                    <td>{averages['last_15_min']:.2f}</td>
                </tr>
                <tr>
                    <td>Last 30 minutes</td>
                    <td>{averages['last_30_min']:.2f}</td>
                </tr>
                <tr>
                    <td>Last hour</td>
                    <td>{averages['last_hour']:.2f}</td>
                </tr>
                <tr>
                    <td>Last day</td>
                    <td>{averages['last_day']:.2f}</td>
                </tr>
                <tr>
                    <td>Last week</td>
                    <td>{averages['last_week']:.2f}</td>
                </tr>
            </table>
            """

        # Add the legal disclaimer at the bottom
        html_content += """
            <p><em>
            Disclaimer: This site, <strong>zentrostatus.com</strong>, is an independent, third-party resource created to track internet connectivity and packet loss statistics for personal and educational purposes. It is not affiliated with or endorsed by <strong>Zentro</strong> or any related company. All data provided on this site is collected through public and legal methods, and the results displayed are intended solely for informational purposes. This site does not claim to represent the official status or performance of Zentro's services.

            If you are a representative of Zentro and have any concerns or inquiries about the content, please contact us at [Your Contact Email], and we will promptly address your request.
            </em></p>
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
