"""
Web Dashboard for Network Anomaly Detection
Simple Flask app to display ML results
Author: [Aryan Pravin Sahu]
"""

from flask import Flask, render_template
import sys
import os


sys.path.append(os.path.join(os.path.dirname(__file__),'..'))

from core.network_capture import NetworkCapture
from core.data_processor import DataProcessor
from core.anomaly_detector import BasicAnomalyDetector

app = Flask(__name__)

@app.route('/')
def dashboard():
    """Main dashboard showing ML results"""


    print("Running network analysis for dashboard...")


    capture = NetworkCapture()
    capture.start_monitoring()
    capture.simulate_packet_capture(50)


    processor = DataProcessor()
    processor.load_from_capture(capture)
    processor.clean_data()
    features = processor.extract_features()


    detector = BasicAnomalyDetector()
    detector.train(features)
    results = detector.detect_anomalies(features)


    dashboard_data = {
        'total_packets': results['total_packets'],
        'anomalies_found': results['anomalies_found'],
        'anomaly_rate': round(results['anomaly_rate'], 1),
        'status': 'success',
        'message': 'Analysis completed successfully'
    }

    return render_template('index.html', data=dashboard_data)

if __name__ == '__main__':
    print("🌐 Starting Network Analysis Dashboard...")
    print("📊 Visit: http://localhost:5000")
    app.run(debug=True)