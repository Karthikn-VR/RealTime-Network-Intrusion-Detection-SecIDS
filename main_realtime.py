"""
Main entry point for real-time intrusion detection and network monitoring system.
"""
import logging
import signal
import sys
import threading
import time
import socket
from src.realtime_monitor import RealtimeMonitor
from src.web_ui import get_web_ui

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Main function to start the monitoring system."""
    logger.info("=" * 60)
    logger.info("Wireshark-Powered Real-Time Intrusion Detection System")
    logger.info("=" * 60)
    
    # Initialize monitor
    monitor = RealtimeMonitor(
        interface=None,  # Auto-detect interface
        tshark_path='C:\\Program Files\\Wireshark\\tshark.exe',
        model_path='models/SecIDS-CNN.h5',
        web_ui_port=5000,
        flow_timeout=5,
        detection_interval=5.0
    )
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("\nShutting down...")
        monitor.stop_monitoring()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("Starting continual learning scheduler...")
        monitor.start_continual_learning()
        logger.info("Starting real-time monitoring...")
        monitor.start_monitoring()
        web_ui = get_web_ui(port=5000)
        def _run_ui():
            try:
                web_ui.run(debug=False)
            except Exception as e:
                logger.error(f"Web UI error: {e}")
        def _port_free(p):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('0.0.0.0', p))
                s.close()
                return True
            except OSError:
                s.close()
                return False
        if _port_free(5000):
            logger.info("Starting web UI on http://localhost:5000")
            logger.info("Press Ctrl+C to stop")
            ui_thread = threading.Thread(target=_run_ui, daemon=True)
            ui_thread.start()
        else:
            logger.info("Web UI already running, continuing monitoring")
        while True:
            time.sleep(1)
        
    except KeyboardInterrupt:
        logger.info("\nReceived interrupt signal")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        monitor.stop_monitoring()
        logger.info("System stopped")


if __name__ == "__main__":
    main()
