#!/usr/bin/env python3
"""
Inject test anomalies via API endpoint
This directly calls the web application to inject test data
"""

import requests
import json
import time

def inject_test_anomalies():
    """Call the API to inject test anomalies"""
    
    print("🧪 Injecting Test Anomalies via API")
    print("=" * 50)
    
    try:
        # Call the injection API
        response = requests.post('http://localhost:5000/api/inject_test_anomalies', 
                               json={}, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Success!")
            print(f"   Message: {data.get('message')}")
            print(f"   Anomalies injected: {data.get('anomalies_injected')}")
            print(f"   Total anomalies: {data.get('total_anomalies')}")
            
            return True
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error message: {error_data.get('message')}")
            except:
                print(f"   Raw response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error calling API: {e}")
        return False

def check_results():
    """Check if the anomalies are now visible"""
    
    print("\n🔍 Checking Results...")
    
    try:
        # Check monitoring stats
        response = requests.get('http://localhost:5000/api/real_monitoring_stats', timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'active':
                security = data.get('security_analysis', {})
                suspicious_count = security.get('suspicious_packets', 0)
                risk_indicators = security.get('risk_indicators', {})
                
                print(f"   Monitoring Status: Active")
                print(f"   Suspicious Packets: {suspicious_count}")
                print(f"   Risk Indicators: {risk_indicators}")
                
                if suspicious_count > 0:
                    print("✅ Anomalies are now visible in monitoring stats!")
                else:
                    print("⚠️  Suspicious count still 0")
            else:
                print(f"   Monitoring Status: {data.get('status')}")
        
        # Check anomaly details
        response = requests.get('http://localhost:5000/api/anomaly_details', timeout=5)
        if response.status_code == 200:
            data = response.json()
            
            total_anomalies = data.get('total_anomalies', 0)
            recent_anomalies = data.get('recent_anomalies', [])
            
            print(f"   Total Anomalies: {total_anomalies}")
            print(f"   Recent Anomalies: {len(recent_anomalies)}")
            
            if total_anomalies > 0:
                print("✅ Anomalies are visible in anomaly details!")
                
                # Show some details
                for i, anomaly in enumerate(recent_anomalies[-2:], 1):
                    packet = anomaly.get('packet_info', {})
                    risk = anomaly.get('risk_analysis', {})
                    print(f"   {i}. {risk.get('threat_category', 'Unknown')}: {packet.get('src_ip')}:{packet.get('src_port')} → {packet.get('dst_ip')}:{packet.get('dst_port')}")
                
                return True
            else:
                print("⚠️  No anomalies in details")
                
    except Exception as e:
        print(f"❌ Error checking results: {e}")
    
    return False

def main():
    print("🎯 API-Based Anomaly Injection")
    print("This injects test anomalies directly into your running web application")
    print()
    
    # Step 1: Inject anomalies
    success = inject_test_anomalies()
    
    if success:
        # Step 2: Wait a moment
        print("\n⏳ Waiting 3 seconds for system to process...")
        time.sleep(3)
        
        # Step 3: Check results
        results_visible = check_results()
        
        # Step 4: Instructions
        print("\n" + "=" * 50)
        print("NEXT STEPS")
        print("=" * 50)
        
        if results_visible:
            print("✅ SUCCESS! Anomalies have been injected and are visible.")
            print("\n🌐 In your web browser:")
            print("1. Refresh the page (F5)")
            print("2. Look for the 'Suspicious' count to be > 0")
            print("3. Check the 'Detailed Anomaly Analysis' section")
            print("4. You should see threat categories and recent anomalies")
        else:
            print("⚠️  Anomalies injected but may not be visible yet.")
            print("\n🔧 Try these steps:")
            print("1. Refresh your browser page")
            print("2. Click 'Reset UI' button")
            print("3. Check browser console (F12) for errors")
            print("4. Make sure monitoring shows 'Active'")
    else:
        print("\n❌ Failed to inject anomalies.")
        print("Make sure the web application is running on localhost:5000")

if __name__ == "__main__":
    main()