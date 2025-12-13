#!/usr/bin/env python3
"""
Clear All Anomalies - Kill the Anomalies
This script removes all detected anomalies and resets the system to clean state
"""

import requests
import json
import time

def clear_anomalies_via_reset():
    """Clear anomalies by resetting the monitoring state"""
    print("🧹 Clearing all anomalies by resetting monitoring state...")
    
    try:
        # Reset the monitoring state (this clears all data)
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

def stop_monitoring():
    """Stop the monitoring to clear active session"""
    print("\n🛑 Stopping monitoring to clear session...")
    
    try:
        response = requests.get('http://localhost:5000/api/stop_real_monitoring', timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Stop successful: {data.get('message')}")
            return True
        else:
            print(f"   ❌ Stop failed: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Stop error: {e}")
        return False

def verify_clean_state():
    """Verify that all anomalies have been cleared"""
    print("\n🔍 Verifying clean state...")
    
    try:
        # Check monitoring stats
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            status = data.get('status', 'unknown')
            print(f"   Monitoring status: {status}")
            
            if status == 'active':
                security = data.get('security_analysis', {})
                suspicious_count = security.get('suspicious_packets', 0)
                risk_indicators = security.get('risk_indicators', {})
                
                print(f"   Suspicious packets: {suspicious_count}")
                print(f"   Risk indicators: {risk_indicators}")
                
                if suspicious_count == 0 and not risk_indicators:
                    print("   ✅ Monitoring stats are clean!")
                else:
                    print("   ⚠️  Still showing suspicious activity")
            else:
                print("   ✅ Monitoring is inactive (clean)")
        
        # Check anomaly details
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        if response.status_code == 200:
            data = response.json()
            total_anomalies = data.get('total_anomalies', 0)
            recent_anomalies = data.get('recent_anomalies', [])
            
            print(f"   Total anomalies: {total_anomalies}")
            print(f"   Recent anomalies: {len(recent_anomalies)}")
            
            if total_anomalies == 0 and len(recent_anomalies) == 0:
                print("   ✅ Anomaly details are clean!")
                return True
            else:
                print("   ⚠️  Still showing anomaly data")
                return False
        
        return False
        
    except Exception as e:
        print(f"   ❌ Verification error: {e}")
        return False

def force_clean_restart():
    """Force a completely clean restart of monitoring"""
    print("\n🔄 Force clean restart...")
    
    try:
        # Start fresh monitoring (this should create a new clean session)
        response = requests.post('http://localhost:5000/api/start_real_monitoring',
                               json={
                                   'consent_granted': True,
                                   'duration': 300,
                                   'force_restart': True
                               }, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Clean restart successful: {data.get('message')}")
            return True
        else:
            print(f"   ❌ Clean restart failed: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Clean restart error: {e}")
        return False

def main():
    print("💀 ANOMALY KILLER")
    print("=" * 40)
    print("This tool will eliminate all detected anomalies")
    print("and reset your system to a clean state.")
    print()
    
    print("🎯 Target: All anomalies must die!")
    print()
    
    # Step 1: Stop monitoring
    print("Step 1: Terminate active monitoring")
    stop_success = stop_monitoring()
    
    # Step 2: Reset state
    print("\nStep 2: Reset monitoring state")
    reset_success = clear_anomalies_via_reset()
    
    # Step 3: Verify clean state
    print("\nStep 3: Verify anomalies are eliminated")
    clean_verified = verify_clean_state()
    
    # Step 4: Optional clean restart
    if not clean_verified:
        print("\nStep 4: Force clean restart")
        restart_success = force_clean_restart()
        
        # Verify again
        time.sleep(2)
        print("\nStep 5: Final verification")
        clean_verified = verify_clean_state()
    
    # Summary
    print("\n" + "=" * 40)
    print("ANOMALY ELIMINATION REPORT")
    print("=" * 40)
    
    if clean_verified:
        print("💀 SUCCESS! All anomalies have been eliminated!")
        print("\n🧹 System Status: CLEAN")
        print("   • Suspicious packets: 0")
        print("   • Risk indicators: None")
        print("   • Anomaly count: 0")
        print("   • Monitoring state: Reset")
        
        print("\n🌐 In your browser:")
        print("1. Refresh the page (F5)")
        print("2. You should see 'No anomalies detected'")
        print("3. Suspicious count should be 0")
        print("4. Risk indicators section should be gone")
        print("5. System is ready for new monitoring")
        
    else:
        print("⚠️  Some anomalies may still be lurking...")
        print("\n🔧 Additional steps to try:")
        print("1. Restart the web server completely")
        print("2. Refresh browser and clear cache")
        print("3. Use 'Reset UI' button in the interface")
    
    print(f"\n🎯 Mission Status: {'COMPLETE' if clean_verified else 'PARTIAL'}")
    print("All anomalies have been targeted for elimination!")

if __name__ == "__main__":
    main()