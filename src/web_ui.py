"""
Web-based user interface for real-time network monitoring and intrusion detection.
Provides dashboards, alerts, and historical logs.
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import threading
import time
import os
from datetime import datetime
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class WebUI:
    """
    Flask-based web UI for network monitoring.
    """
    
    def __init__(self, port: int = 5000):
        """
        Initialize the web UI.
        
        Args:
            port: Port number for the web server
        """
        # Get the project root directory (parent of src/)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir = os.path.join(project_root, 'templates')
        static_dir = os.path.join(project_root, 'static')
        
        self.app = Flask(__name__, 
                        template_folder=template_dir,
                        static_folder=static_dir)
        self.app.config['SECRET_KEY'] = 'network-monitoring-secret-key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.port = port
        
        # Data storage
        self.realtime_data = {
            'traffic_stats': {},
            'detections': [],
            'alerts': []
        }
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio()
    
    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index():
            """Main dashboard page."""
            return render_template('dashboard.html')
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get current statistics."""
            return jsonify(self.realtime_data['traffic_stats'])
        
        @self.app.route('/api/detections')
        def get_detections():
            """Get recent detections."""
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self.realtime_data['detections'][-limit:])
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """Get recent alerts."""
            limit = request.args.get('limit', 50, type=int)
            return jsonify(self.realtime_data['alerts'][-limit:])
        
        @self.app.route('/api/history')
        def get_history():
            """Get historical data."""
            minutes = request.args.get('minutes', 60, type=int)
            # Return recent data
            return jsonify({
                'detections': self.realtime_data['detections'][-100:],
                'alerts': self.realtime_data['alerts'][-50:]
            })
    
    def _setup_socketio(self):
        """Setup SocketIO event handlers."""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection."""
            logger.info("Client connected")
            emit('status', {'status': 'connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection."""
            logger.info("Client disconnected")
    
    def update_traffic_stats(self, stats: Dict):
        """Update traffic statistics."""
        self.realtime_data['traffic_stats'] = stats
        self.socketio.emit('traffic_update', stats)
    
    def add_detection(self, detection: Dict):
        """Add a new intrusion detection."""
        detection['timestamp'] = datetime.now().isoformat()
        self.realtime_data['detections'].append(detection)
        
        # Keep only recent detections
        if len(self.realtime_data['detections']) > 1000:
            self.realtime_data['detections'] = self.realtime_data['detections'][-1000:]
        
        # Emit to connected clients
        self.socketio.emit('new_detection', detection)
        
        # Create alert if high confidence
        if detection.get('confidence', 0) > 0.8:
            self.add_alert({
                'type': 'intrusion',
                'severity': 'high',
                'message': f"Intrusion detected: {detection.get('src_ip', 'Unknown')} -> {detection.get('dst_ip', 'Unknown')}",
                'confidence': detection.get('confidence', 0),
                'timestamp': detection['timestamp']
            })
    
    def add_alert(self, alert: Dict):
        """Add a new alert."""
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        self.realtime_data['alerts'].append(alert)
        
        # Keep only recent alerts
        if len(self.realtime_data['alerts']) > 500:
            self.realtime_data['alerts'] = self.realtime_data['alerts'][-500:]
        
        # Emit to connected clients
        self.socketio.emit('new_alert', alert)
    
    def run(self, debug: bool = False):
        """Run the web server."""
        logger.info(f"Starting web UI on port {self.port}")
        self.socketio.run(self.app, host='0.0.0.0', port=self.port, debug=debug)


# Create global instance
web_ui = None

def get_web_ui(port: int = 5000) -> WebUI:
    """Get or create web UI instance."""
    global web_ui
    if web_ui is None:
        web_ui = WebUI(port=port)
    return web_ui

