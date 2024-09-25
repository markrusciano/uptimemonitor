#!/bin/bash

# Navigate to the project directory
cd ~/dev/uptimemonitor  # Replace with your actual path

# Add changes to git
git add index.html

# Commit the changes
git commit -m "Automated update of index.html"

# Push to GitHub
git push origin main  # Replace 'main' with your branch name if different
