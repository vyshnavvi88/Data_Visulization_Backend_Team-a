import os
import sys
import subprocess
import time
import webbrowser
import threading

# Define paths
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BACKEND_DIR, "..", "Data_Visulization_Frontend_Team-a"))

# Fallback: if Frontend is not in sibling directory, use the absolute path from your current setup
if not os.path.exists(FRONTEND_DIR):
    FRONTEND_DIR = r"c:\Data_Visulization_Frontend_Team-a"

print("=" * 60)
print("STARTING SECURITY DASHBOARD PROJECT")
print("=" * 60)

print(f"Backend Directory : {BACKEND_DIR}")
print(f"Frontend Directory: {FRONTEND_DIR}")
print("-" * 60)

# 1. Build Vite Frontend Production Bundle
print("Building Vite Frontend production bundle...")
try:
    subprocess.run("npm run build", cwd=FRONTEND_DIR, shell=True, check=True)
    print("Frontend built successfully.")
except subprocess.CalledProcessError as e:
    print("Failed to build frontend:", e)
    sys.exit(1)

# 2. Add backend folder to path and import Flask app
sys.path.insert(0, os.path.join(BACKEND_DIR, "backend"))
from app import app

# 3. Start browser opener thread
def open_browser():
    time.sleep(1.5)
    print("-" * 60)
    print("PROJECT STARTED SUCCESSFULLY!")
    print("App URL: http://localhost:5000 (Frontend & Backend unified on a single port)")
    print("-" * 60)
    print("Opening default browser to dashboard...")
    webbrowser.open("http://localhost:5000")

threading.Thread(target=open_browser, daemon=True).start()

# 4. Start Flask server in the main thread
print("Starting Flask server...")
app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
