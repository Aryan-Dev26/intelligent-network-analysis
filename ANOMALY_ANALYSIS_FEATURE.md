# Detailed Anomaly Analysis Feature

## Overview
Added comprehensive anomaly tracking to help you understand exactly **what's causing port scan alerts** and **why they're being detected**.

## New Features Added

### 1. Detailed Anomaly Logging
Every suspicious packet now generates a detailed record including:
- **Packet Information**: Source/destination IPs and ports, protocol, flags, size
- **Process Information**: Which application/service is responsible
- **Risk Analysis**: Threat category, risk score, specific indicators
- **Context**: Internal vs external traffic, port classification, timing
- **Human-Readable Explanation**: Why the packet was flagged as suspicious

### 2. Process Identification
The system now attempts to identify which process is responsible for each anomaly:
```
Process: chrome.exe (PID: 1234)
Command: chrome.exe --type=renderer
```

### 3. Threat Categorization
Anomalies are automatically categorized:
- **Port Scan**: Potential scanning activity
- **Malicious Service**: Connections to known bad ports
- **Stealth Attack**: Advanced scanning techniques
- **Protocol Anomaly**: Invalid packet structures
- **Data Exfiltration**: Unusually large packets

### 4. Real-Time Anomaly Dashboard
The web interface now shows:
- **Live anomaly count** and categories
- **Recent anomaly details** with full context
- **Process involvement** statistics
- **Export functionality** for detailed reports

### 5. Comprehensive Reporting
Export detailed JSON reports containing:
- Complete anomaly timeline
- Process analysis
- Risk indicator statistics
- Threat category breakdown

## How to Use

### 1. Web Dashboard
- Start your monitoring system as administrator
- The dashboard will automatically show anomaly details
- Look for the "🚨 Detailed Anomaly Analysis" section
- Click "📄 Export Detailed Report" for full analysis

### 2. Command Line Analysis
```bash
# View current anomaly details
python view_anomaly_details.py

# Monitor live anomalies
python view_anomaly_details.py
# Choose option 2 for live monitoring
```

### 3. API Access
```bash
# Get anomaly details via API
curl http://localhost:5000/api/anomaly_details

# Export anomaly report
curl http://localhost:5000/api/export_anomaly_report
```

## Understanding Your Port Scan Alerts

When you see "PORT SCAN DETECTED", the system now tells you:

### Example Output:
```
🚨 ANOMALY DETECTED #1
  Type: Port Scan
  Source: 192.168.1.55:54321
  Destination: 40.74.79.222:443
  Process: StartMenuExperienceHost.exe (PID: 2468)
  Explanation: SYN packet to non-standard service port 443

💡 Why Flagged: Windows Start Menu connecting to Microsoft servers
🔧 Process: StartMenuExperienceHost.exe - Windows Start Menu
📍 Direction: Internal → External
⏰ Time: 18:57:45
```

### Common False Positives You'll See:
1. **StartMenuExperienceHost.exe** - Windows Start Menu updates
2. **svchost.exe** - Windows system services
3. **chrome.exe/firefox.exe** - Browser connections
4. **OneDrive.exe** - Cloud sync services

### Real Threats Look Like:
1. **Unknown processes** connecting to suspicious ports
2. **External IPs** scanning your internal network
3. **Rapid sequential** connections to multiple ports
4. **Stealth scan techniques** (FIN scans, invalid flags)

## Benefits

### Before:
- ❌ "PORT SCAN DETECTED" with no context
- ❌ No way to know if it's legitimate or malicious
- ❌ Difficult to tune detection sensitivity

### After:
- ✅ **Detailed explanation** of what was detected
- ✅ **Process identification** to understand the source
- ✅ **Context information** to assess legitimacy
- ✅ **Historical analysis** to identify patterns
- ✅ **Export capabilities** for security reporting

## Next Steps

1. **Run your system as administrator** to get real packet capture
2. **Monitor the anomaly details** to understand your network patterns
3. **Review false positives** and consider whitelisting legitimate processes
4. **Export reports** for security documentation
5. **Tune detection sensitivity** based on your environment

This feature transforms your network monitoring from basic alerting to **comprehensive security analysis** with full context and actionability.