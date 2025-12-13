"""
Setup script for Advanced Network Anomaly Detection System
Automated installation and configuration
Author: Aryan Pravin Sahu
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header():
    """Print installation header"""
    print("=" * 70)
    print("ADVANCED NETWORK ANOMALY DETECTION SYSTEM")
    print("AI-Powered Cybersecurity Research Platform")
    print("Author: Aryan Pravin Sahu | IIT Ropar")
    print("=" * 70)

def check_python_version():
    """Check if Python version is compatible"""
    print("\n1. Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"   ERROR: Python {version.major}.{version.minor} detected")
        print("   This system requires Python 3.8 or higher")
        print("   Please install Python 3.8+ from https://python.org")
        return False
    
    print(f"   ✓ Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def check_pip():
    """Check if pip is available"""
    print("\n2. Checking pip installation...")
    
    try:
        import pip
        print("   ✓ pip is available")
        return True
    except ImportError:
        print("   ERROR: pip not found")
        print("   Please install pip: python -m ensurepip --upgrade")
        return False

def create_virtual_environment():
    """Create virtual environment"""
    print("\n3. Setting up virtual environment...")
    
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("   ✓ Virtual environment already exists")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("   ✓ Virtual environment created successfully")
        return True
    except subprocess.CalledProcessError:
        print("   ERROR: Failed to create virtual environment")
        return False

def get_activation_command():
    """Get the correct activation command for the platform"""
    system = platform.system().lower()
    
    if system == "windows":
        return "venv\\Scripts\\activate"
    else:
        return "source venv/bin/activate"

def install_requirements():
    """Install required packages"""
    print("\n4. Installing required packages...")
    
    # Determine pip executable path
    system = platform.system().lower()
    if system == "windows":
        pip_path = "venv\\Scripts\\pip"
    else:
        pip_path = "venv/bin/pip"
    
    # Check if requirements.txt exists
    if not Path("requirements.txt").exists():
        print("   ERROR: requirements.txt not found")
        return False
    
    try:
        # Upgrade pip first
        print("   Upgrading pip...")
        subprocess.run([pip_path, "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        
        # Install requirements
        print("   Installing packages (this may take a few minutes)...")
        result = subprocess.run([pip_path, "install", "-r", "requirements.txt"], 
                              check=True, capture_output=True, text=True)
        
        print("   ✓ All packages installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"   ERROR: Package installation failed")
        print(f"   Error details: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        return False

def test_installation():
    """Test if the installation works"""
    print("\n5. Testing installation...")
    
    # Determine python executable path
    system = platform.system().lower()
    if system == "windows":
        python_path = "venv\\Scripts\\python"
    else:
        python_path = "venv/bin/python"
    
    try:
        # Test basic imports
        test_script = """
import numpy as np
import pandas as pd
import sklearn
import tensorflow as tf
import flask
print("All core packages imported successfully")
"""
        
        result = subprocess.run([python_path, "-c", test_script], 
                              check=True, capture_output=True, text=True)
        
        print("   ✓ Core packages test passed")
        
        # Test system components
        if Path("src/core/network_capture.py").exists():
            test_component = """
import sys
sys.path.append('src')
from core.network_capture import NetworkCapture
print("System components loaded successfully")
"""
            result = subprocess.run([python_path, "-c", test_component], 
                                  check=True, capture_output=True, text=True)
            print("   ✓ System components test passed")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"   ERROR: Installation test failed")
        print(f"   Error: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        return False

def create_run_scripts():
    """Create convenient run scripts"""
    print("\n6. Creating run scripts...")
    
    system = platform.system().lower()
    
    if system == "windows":
        # Windows batch file
        batch_content = """@echo off
echo Starting Advanced Network Anomaly Detection System...
call venv\\Scripts\\activate
python src\\web\\app.py
pause
"""
        with open("run_system.bat", "w") as f:
            f.write(batch_content)
        print("   ✓ Created run_system.bat for Windows")
        
    else:
        # Unix shell script
        shell_content = """#!/bin/bash
echo "Starting Advanced Network Anomaly Detection System..."
source venv/bin/activate
python src/web/app.py
"""
        with open("run_system.sh", "w") as f:
            f.write(shell_content)
        
        # Make executable
        os.chmod("run_system.sh", 0o755)
        print("   ✓ Created run_system.sh for Unix/Linux/macOS")

def print_success_message():
    """Print success message with instructions"""
    system = platform.system().lower()
    activation_cmd = get_activation_command()
    
    print("\n" + "=" * 70)
    print("INSTALLATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    
    print("\nTo start the system:")
    print("\nOption 1 - Use run script:")
    if system == "windows":
        print("   Double-click: run_system.bat")
        print("   Or in Command Prompt: run_system.bat")
    else:
        print("   In terminal: ./run_system.sh")
    
    print("\nOption 2 - Manual start:")
    print(f"   1. Activate environment: {activation_cmd}")
    print("   2. Start system: python src/web/app.py")
    print("   3. Open browser: http://localhost:5000")
    
    print("\nSystem Features:")
    print("   • Basic Anomaly Detection")
    print("   • Advanced Ensemble Learning")
    print("   • AI Threat Intelligence")
    print("   • Explainable AI Analysis")
    print("   • Attack Simulations")
    print("   • Real-time Processing")
    
    print("\nFor help:")
    print("   • Read INSTALLATION.md for detailed instructions")
    print("   • Check README.md for system overview")
    print("   • Visit /research page for methodology")
    
    print("\n" + "=" * 70)

def main():
    """Main installation function"""
    print_header()
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    if not check_pip():
        sys.exit(1)
    
    # Setup environment
    if not create_virtual_environment():
        sys.exit(1)
    
    # Install packages
    if not install_requirements():
        print("\nTroubleshooting tips:")
        print("1. Ensure you have internet connection")
        print("2. Try running: pip install --upgrade pip")
        print("3. On Windows, you might need Visual C++ Build Tools")
        print("4. Check INSTALLATION.md for detailed troubleshooting")
        sys.exit(1)
    
    # Test installation
    if not test_installation():
        print("\nInstallation test failed. Please check:")
        print("1. All packages installed correctly")
        print("2. Virtual environment is working")
        print("3. Check INSTALLATION.md for troubleshooting")
        sys.exit(1)
    
    # Create convenience scripts
    create_run_scripts()
    
    # Success message
    print_success_message()

if __name__ == "__main__":
    main()