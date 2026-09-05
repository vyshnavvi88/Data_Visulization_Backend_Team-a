import os
import subprocess
import time
import sys
import webbrowser

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

# 1. Start backend process
print("Starting Flask Backend server...")
backend_cmd = [sys.executable, os.path.join(BACKEND_DIR, "backend", "app.py")]
backend_process = subprocess.Popen(
    backend_cmd,
    cwd=BACKEND_DIR,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

# 2. Start frontend process (Vite server on port 3000)
print("Starting Vite Frontend server (on port 3000)...")
frontend_cmd = "npx vite --port=3000"
frontend_process = subprocess.Popen(
    frontend_cmd,
    cwd=FRONTEND_DIR,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

# Wait a few seconds for servers to start
print("Waiting for servers to initialize...")
time.sleep(4)

# 3. Print URLs and open browser
frontend_url = "http://localhost:3000"
print("-" * 60)
print("PROJECT STARTED SUCCESSFULLY!")
print(f"Frontend URL: {frontend_url}")
print(f"Backend URL : http://localhost:5000")
print("-" * 60)
print("Opening default browser to dashboard...")
webbrowser.open(frontend_url)

print("\nPress Ctrl+C to terminate both servers.")

try:
    while True:
        # Check backend
        if backend_process.poll() is not None:
            print("Backend process terminated unexpectedly.")
            break
        # Check frontend
        if frontend_process.poll() is not None:
            print("Frontend process terminated unexpectedly.")
            break
        time.sleep(1)
except KeyboardInterrupt:
    print("\nTerminating processes...")
finally:
    # Kill process trees cleanly to prevent orphaned nodes on Windows
    if sys.platform == "win32":
        try:
            subprocess.run(f"taskkill /F /T /PID {backend_process.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        try:
            subprocess.run(f"taskkill /F /T /PID {frontend_process.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    else:
        try:
            backend_process.terminate()
        except Exception:
            pass
        try:
            frontend_process.terminate()
        except Exception:
            pass
    print("Processes stopped. Goodbye!")
