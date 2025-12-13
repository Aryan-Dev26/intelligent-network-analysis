#!/usr/bin/env python3
"""
Fix monitoring state issues
This script helps resolve the "monitoring already active" error
"""

import requests
import json

def check_current_state():
    """Check the current monitoring state"""
    print("🔍 Checking current monitoring state...")
    
    try:
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status', 'unknown')
            print(f"   Current status: {status}")
            
            if status == 'active':
                stats = data.get('capture_stats', {})
                print(f"   Total packets: {stats.get('total_packets', 0)}")
                print(f"   Monitoring duration: {stats.get('capture_duration', 'unknown')}")
            
            return status
        else:
            print(f"   Error: HTTP {response.status_code}")
            return 'error'
            
    except Exception as e:
        print(f"   Error: {e}")
        return 'error'

def reset_monitoring_state():
    """Reset the monitoring state"""
    print("\n🔄 Resetting monitoring state...")
    
    try:
        response = requests.post('http://localhost:5000/api/reset_monitoring_state', 
                               json={}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Success: {data.get('message')}")
            return True
        else:
            print(f"   ❌ Error: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error message: {error_data.get('message')}")
            except:
                print(f"   Raw response: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_start_monitoring():
    """Test starting monitoring after reset"""
    print("\n🚀 Testing monitoring start...")
    
    try:
        response = requests.post('http://localhost:5000/api/start_real_monitoring',
                               json={
                                   'consent_granted': True,
                                   'duration': 300
                               }, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                print("   ✅ Monitoring started successfully!")
                return True
            else:
                print(f"   ⚠️  Start result: {data.get('message')}")
                return False
        else:
            print(f"   ❌ Error: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    print("🔧 Monitoring State Fix Tool")
    print("=" * 40)
    print("This tool fixes the 'monitoring already active' error")
    print()
    
    # Step 1: Check current state
    current_state = check_current_state()
    
    # Step 2: Reset if needed
    if current_state in ['active', 'error']:
        print("\n💡 Resetting state to fix any issues...")
        reset_success = reset_monitoring_state()
        
        if reset_success:
            # Step 3: Test starting monitoring
            print("\n🧪 Testing if monitoring can now start...")
            start_success = test_start_monitoring()
            
            if start_success:
                print("\n" + "=" * 40)
                print("✅ SUCCESS!")
                print("The monitoring state has been fixed.")
                print("\n🌐 In your browser:")
                print("1. Refresh the page")
                print("2. Try clicking 'Start Real Monitoring'")
                print("3. It should work without the 'already active' error")
            else:
                print("\n" + "=" * 40)
                print("⚠️  PARTIAL SUCCESS")
                print("State was reset but monitoring still has issues.")
                print("Check the server console for error messages.")
        else:
            print("\n❌ Failed to reset state.")
    else:
        print("\n✅ State appears to be inactive already.")
        print("Try starting monitoring from the web interface.")
    
    print("\n🔧 If you still have issues:")
    print("1. Restart the web server")
    print("2. Run as administrator for real packet capture")
    print("3. Use the 'Reset UI' button in the web interface")

if __name__ == "__main__":
    main()