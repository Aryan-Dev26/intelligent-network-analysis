#!/usr/bin/env python3
"""
Debug the backend state to understand the monitoring issue
"""

import requests
import json

def force_reset_via_api():
    """Force reset the backend state"""
    print("🔄 Force resetting backend state...")
    
    try:
        response = requests.post('http://localhost:5000/api/reset_monitoring_state', 
                               json={}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Reset successful: {data.get('message')}")
            return True
        else:
            print(f"   ❌ Reset failed: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Reset error: {e}")
        return False

def try_start_with_force():
    """Try to start monitoring with force restart"""
    print("\n🚀 Attempting to start with force restart...")
    
    try:
        response = requests.post('http://localhost:5000/api/start_real_monitoring',
                               json={
                                   'consent_granted': True,
                                   'duration': 300,
                                   'force_restart': True  # This should bypass the "already active" check
                               }, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   Status: {data.get('status')}")
            print(f"   Message: {data.get('message')}")
            
            if data.get('status') == 'success':
                print("   ✅ Force start successful!")
                return True
            else:
                print(f"   ⚠️  Force start issue: {data.get('message')}")
                return False
        else:
            print(f"   ❌ HTTP Error: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error details: {error_data}")
            except:
                print(f"   Raw response: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Request error: {e}")
        return False

def inject_test_data():
    """Inject test anomalies to make sure the system works"""
    print("\n🧪 Injecting test anomalies...")
    
    try:
        response = requests.post('http://localhost:5000/api/inject_test_anomalies',
                               json={}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Injection successful: {data.get('message')}")
            print(f"   Anomalies injected: {data.get('anomalies_injected')}")
            return True
        else:
            print(f"   ❌ Injection failed: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Injection error: {e}")
        return False

def check_final_state():
    """Check the final state after all operations"""
    print("\n📊 Checking final state...")
    
    try:
        # Check monitoring stats
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   Monitoring status: {data.get('status')}")
            
            if data.get('status') == 'active':
                security = data.get('security_analysis', {})
                print(f"   Suspicious packets: {security.get('suspicious_packets', 0)}")
                print(f"   Risk indicators: {security.get('risk_indicators', {})}")
        
        # Check anomaly details
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   Total anomalies: {data.get('total_anomalies', 0)}")
            
            if data.get('total_anomalies', 0) > 0:
                print("   ✅ Anomalies are visible!")
                return True
        
        return False
        
    except Exception as e:
        print(f"   ❌ State check error: {e}")
        return False

def main():
    print("🔧 Backend State Debug & Fix Tool")
    print("=" * 50)
    print("This tool will force fix the monitoring state issue")
    print()
    
    # Step 1: Force reset
    print("Step 1: Force reset backend state")
    reset_success = force_reset_via_api()
    
    # Step 2: Try force start
    print("\nStep 2: Force start monitoring")
    start_success = try_start_with_force()
    
    # Step 3: Inject test data
    print("\nStep 3: Inject test anomalies")
    inject_success = inject_test_data()
    
    # Step 4: Check final state
    print("\nStep 4: Verify everything is working")
    final_success = check_final_state()
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    if start_success and inject_success and final_success:
        print("✅ SUCCESS! Everything is now working!")
        print("\n🌐 In your browser:")
        print("1. Refresh the page (F5)")
        print("2. You should see monitoring as 'Active'")
        print("3. Suspicious packets should be > 0")
        print("4. Anomaly details should be visible")
    elif start_success:
        print("✅ Monitoring started but may need anomalies")
        print("Try running: python inject_via_api.py")
    else:
        print("❌ Still having issues")
        print("\n🔧 Try these steps:")
        print("1. Restart the web server")
        print("2. Run the server as administrator")
        print("3. Check server console for error messages")
    
    print(f"\nResults: Reset={reset_success}, Start={start_success}, Inject={inject_success}, Final={final_success}")

if __name__ == "__main__":
    main()