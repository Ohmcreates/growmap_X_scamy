"""
Scam Spotter (Growmap x Scamy) — Unified System Launcher
Launches MySQL database verification, Flask backend (port 5001), 
Vite frontend (port 3500), opens the browser, and cleanly manages shutdown.
"""

import os
import sys
import time
import signal
import subprocess
import webbrowser
import urllib.request
from typing import Optional

BACKEND_PORT = 5001
FRONTEND_PORT = 3500
BACKEND_HEALTH_URL = f"http://127.0.0.1:{BACKEND_PORT}/health"
FRONTEND_URL = f"http://localhost:{FRONTEND_PORT}"

backend_proc: Optional[subprocess.Popen] = None
frontend_proc: Optional[subprocess.Popen] = None

def print_banner():
    banner = f"""
================================================================================
  🛡️  SCAM SPOTTER (Growmap x Scamy) — FULL-STACK SYSTEM LAUNCHER
================================================================================
  Author: Subham Moharana (aryavartsubhammoharana)
  Problem Statement: SETU 2026 PS-01 (Explainable Scam Detection System)
================================================================================
"""
    print(banner)

def init_database():
    print("[1/4] Checking MySQL Database connection & tables...")
    try:
        from db import init_db
        init_db()
        print("      ✓ MySQL database & tables verified (users, user_sessions, scan_records).")
    except Exception as e:
        print(f"      ⚠️  MySQL Notice: {e}")
        print("      Continuing with client-side & in-memory evaluation.")

def check_url_active(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=0.8) as resp:
            return resp.status in (200, 304)
    except Exception:
        return False

def start_backend():
    global backend_proc
    print(f"\n[2/4] Starting Flask Backend API on port {BACKEND_PORT}...")
    
    if check_url_active(BACKEND_HEALTH_URL):
        print(f"      ✓ Backend API already active at {BACKEND_HEALTH_URL}")
        return

    # Start app.py using current python executable
    backend_proc = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Wait for backend to be ready
    max_wait = 15
    start_time = time.time()
    ready = False
    
    while time.time() - start_time < max_wait:
        if backend_proc.poll() is not None:
            out, _ = backend_proc.communicate()
            print(f"      ❌ Backend failed to start:\n{out}")
            sys.exit(1)
        if check_url_active(BACKEND_HEALTH_URL):
            ready = True
            break
        time.sleep(0.5)
            
    if ready:
        print(f"      ✓ Backend API ready at {BACKEND_HEALTH_URL}")
    else:
        print(f"      ⚠️ Backend started (PID {backend_proc.pid}), waiting for traffic.")

def start_frontend():
    global frontend_proc
    print(f"\n[3/4] Starting Vite Frontend on port {FRONTEND_PORT}...")
    
    if check_url_active(FRONTEND_URL):
        print(f"      ✓ Frontend Dev Server already active at {FRONTEND_URL}")
        return

    # Use npx vite on Windows/Linux
    cmd = "npx vite"
    frontend_proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Wait for frontend to respond
    max_wait = 15
    start_time = time.time()
    ready = False
    
    while time.time() - start_time < max_wait:
        if frontend_proc.poll() is not None:
            out, _ = frontend_proc.communicate()
            print(f"      ❌ Frontend failed to start:\n{out}")
            sys.exit(1)
        if check_url_active(FRONTEND_URL):
            ready = True
            break
        time.sleep(0.5)
            
    if ready:
        print(f"      ✓ Frontend Dev Server ready at {FRONTEND_URL}")
    else:
        print(f"      ✓ Frontend process started (PID {frontend_proc.pid}).")

def kill_proc(proc: Optional[subprocess.Popen]):
    if not proc or proc.poll() is not None:
        return
    try:
        if sys.platform == 'win32':
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            proc.terminate()
            proc.wait(timeout=2)
    except Exception:
        pass

def cleanup(sig=None, frame=None):
    print("\n\n[*] Shutting down servers cleanly...")
    kill_proc(backend_proc)
    kill_proc(frontend_proc)
    print("[*] All servers stopped. Thank you for using Scam Spotter!")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    print_banner()
    init_database()
    start_backend()
    start_frontend()
    
    print("\n[4/4] Opening Scam Spotter in your browser...")
    try:
        webbrowser.open(FRONTEND_URL)
        print(f"      ✓ Browser opened at {FRONTEND_URL}")
    except Exception:
        print(f"      Open {FRONTEND_URL} manually in your browser.")
        
    print("\n" + "=" * 80)
    print("  🚀 SYSTEM STATUS: FULL-STACK ACTIVE & RUNNING")
    print(f"  • Frontend:   {FRONTEND_URL}")
    print(f"  • Backend:    http://127.0.0.1:{BACKEND_PORT}")
    print(f"  • Health API: {BACKEND_HEALTH_URL}")
    print("=" * 80)
    print("  Press Ctrl+C at any time to gracefully terminate both servers.\n")
    
    # Keep main alive while child processes run
    try:
        while True:
            time.sleep(1)
            # Monitor process health
            if backend_proc and backend_proc.poll() is not None:
                print("\n[!] Backend process ended unexpectedly.")
                break
            if frontend_proc and frontend_proc.poll() is not None:
                print("\n[!] Frontend process ended unexpectedly.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()
