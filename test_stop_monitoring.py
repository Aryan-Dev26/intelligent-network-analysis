#!/usr/bin/env python3
"""
Test the stop monitoring functionality
"""

import requests
import time
import json

def test_stop_monitoring():
    """Test the stop monitoring API endpoint"""
    
    base_url = "http://localhost:5000"
    
    print("🧪 Testing Stop Monitoring Functionality")
    print("=" * 50)
    
    # Test 1: Check if server is running
    print("1. Testing server connectivity...")
    try:
        response = requests.get(f"{base_url}/api/real_monitoring_stats", timeout=5)
        print(f"   ✓ Server is running (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Server not accessible: {e}")
        print("   Make sure the web application is running on localhost:5000")
        return False
    
    # Test 2: Check current monitoring status
    print("\n2. Checking current monitoring status...")
    try:
        response = requests.get(f"{base_url}/api/real_monitoring_stats", timeout=5)
        data = response.json()
        
        if data.get('status') == 'active':
            print("   ✓ Monitoring is currently active")
            is_monitoring = True
        elif data.get('status') == 'inactive':
            print("   ℹ️  Monitoring is currently inactive")
            is_monitoring = False
        else:
            print(f"   ⚠️  Unknown monitoring status: {data.get('status')}")
            is_monitoring = False
            
    except Exception as e:
        print(f"   ❌ Error checking status: {e}")
        is_monitoring = False
    
    # Test 3: Test stop monitoring API
    print("\n3. Testing stop monitoring API...")
    try:
        response = requests.get(f"{base_url}/api/stop_real_monitoring", timeout=10)
        print(f"   Response status code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   Response data: {json.dumps(data, indent=2)}")
            
            if data.get('status') in ['success', 'warning']:
                print("   ✓ Stop monitoring API responded successfully")
                return True
            else:
                print(f"   ❌ API returned error: {data.get('message')}")
                return False
        else:
            print(f"   ❌ HTTP error: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error details: {error_data}")
            except:
                print(f"   Raw response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("   ❌ Request timed out - API might be hanging")
        return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Network error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

def test_ui_elements():
    """Test if the UI elements exist and are properly configured"""
    
    print("\n4. Testing UI elements (manual check needed)...")
    print("   Please verify in your browser:")
    print("   • Stop Monitoring button exists")
    print("   • Button is enabled when monitoring is active")
    print("   • Button shows 'Stopping...' when clicked")
    print("   • Console shows debug messages when clicked")
    print("   • Status changes to 'Inactive' after stopping")
    
    print("\n   To check browser console:")
    print("   1. Open browser developer tools (F12)")
    print("   2. Go to Console tab")
    print("   3. Click Stop Monitoring button")
    print("   4. Look for debug messages starting with 'Stop monitoring button clicked'")

def main():
    success = test_stop_monitoring()
    
    if success:
        print("\n" + "=" * 50)
        print("✅ Stop monitoring API is working correctly!")
        print("\nIf the button still doesn't work in the browser:")
        print("1. Check browser console for JavaScript errors")
        print("2. Verify the button is enabled (not grayed out)")
        print("3. Try refreshing the page")
        print("4. Make sure monitoring was actually started first")
    else:
        print("\n" + "=" * 50)
        print("❌ Stop monitoring API has issues!")
        print("\nTroubleshooting steps:")
        print("1. Make sure the web server is running")
        print("2. Check server console for error messages")
        print("3. Verify the API endpoint exists")
        print("4. Try restarting the web application")
    
    test_ui_elements()

if __name__ == "__main__":
    main()