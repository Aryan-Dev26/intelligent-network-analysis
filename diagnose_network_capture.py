#!/usr/bin/env python3
"""
Network Capture Diagnostic Tool
Helps diagnose why network capture might not be working
"""

import sys
import os
sys.path.append('src')

def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_scapy():
    """Check if Scapy is available and working"""
    try:
        from scapy.all import sniff
        return True, "Scapy is installed and available"
    except ImportError:
        return False, "Scapy is not installed. Install with: pip install scapy"
    except Exception as e:
        return False, f"Scapy error: {e}"

def check_network_interfaces():
    """Check available network interfaces"""
    try:
        import psutil
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    interfaces.append((name, addr.address))
        return True, interfaces
    except Exception as e:
        return False, f"Error checking interfaces: {e}"

def test_real_capture():
    """Test if real network capture can be initialized"""
    try:
        from core.real_network_capture import RealNetworkCapture, SCAPY_AVAILABLE
        
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available for real capture"
        
        capture = RealNetworkCapture()
        return True, "RealNetworkCapture initialized successfully"
    except Exception as e:
        return False, f"RealNetworkCapture error: {e}"

def main():
    print("=" * 60)
    print("NETWORK CAPTURE DIAGNOSTIC TOOL")
    print("=" * 60)
    print()
    
    # Check 1: Administrator privileges
    print("1. Checking administrator privileges...")
    has_admin = check_admin_privileges()
    print(f"   Administrator privileges: {'✓ YES' if has_admin else '✗ NO'}")
    if not has_admin:
        print("   → Real packet capture requires administrator privileges")
        print("   → Use run_as_admin.bat or restart as administrator")
    print()
    
    # Check 2: Scapy availability
    print("2. Checking Scapy installation...")
    scapy_ok, scapy_msg = check_scapy()
    print(f"   Scapy status: {'✓' if scapy_ok else '✗'} {scapy_msg}")
    print()
    
    # Check 3: Network interfaces
    print("3. Checking network interfaces...")
    interfaces_ok, interfaces_data = check_network_interfaces()
    if interfaces_ok:
        print("   Available interfaces:")
        for name, ip in interfaces_data:
            print(f"     - {name}: {ip}")
    else:
        print(f"   ✗ {interfaces_data}")
    print()
    
    # Check 4: Real capture initialization
    print("4. Testing real network capture...")
    capture_ok, capture_msg = test_real_capture()
    print(f"   Real capture: {'✓' if capture_ok else '✗'} {capture_msg}")
    print()
    
    # Summary and recommendations
    print("=" * 60)
    print("SUMMARY AND RECOMMENDATIONS")
    print("=" * 60)
    
    if has_admin and scapy_ok and capture_ok:
        print("✓ All checks passed! Real network capture should work.")
    else:
        print("Issues found:")
        if not has_admin:
            print("  • Run as administrator for real packet capture")
        if not scapy_ok:
            print("  • Install Scapy: pip install scapy")
        if not capture_ok:
            print("  • Check network interface permissions")
        
        print("\nAlternatives:")
        print("  • Use simulation mode (run_system.bat)")
        print("  • Run as administrator (run_as_admin.bat)")
    
    print("\nFor demonstration purposes, simulation mode works without admin privileges.")
    print("Real packet capture is only needed for production network monitoring.")

if __name__ == "__main__":
    main()