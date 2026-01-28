#!/usr/bin/env python3
# installer.py
import subprocess
import sys
import os

def install_dependencies():
    print("[*] Installing ShadowForge dependencies...")
    
    requirements = [
        'flask',
        'pycryptodome',
        'requests'
    ]
    
    for package in requirements:
        print(f"[*] Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
    
    print("[✓] All dependencies installed!")
    
    # Create necessary directories
    os.makedirs('builds', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('downloads', exist_ok=True)
    
    print("[✓] Directories created!")
    print("\n[+] To start the C2 server: python server.py")
    print("[+] Web interface: http://localhost:5000")

if __name__ == '__main__':
    install_dependencies()