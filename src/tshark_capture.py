"""
Enhanced Wireshark/tshark packet capture module.
Uses tshark command-line interface for reliable packet capture.
"""
import subprocess
import json
import pandas as pd
import time
import logging
from typing import Optional, Dict, List
import os
import threading
from queue import Queue

logger = logging.getLogger(__name__)


class TsharkCapture:
    """
    Real-time packet capture using tshark command-line interface.
    """
    
    def __init__(self, interface: Optional[str] = None,
                 tshark_path: str = 'C:\\Program Files\\Wireshark\\tshark.exe',
                 capture_filter: str = ''):
        """
        Initialize tshark capture.
        
        Args:
            interface: Network interface name (None for default)
            tshark_path: Path to tshark executable
            capture_filter: BPF filter string (e.g., 'tcp port 80')
        """
        self.interface = interface
        self.tshark_path = tshark_path
        self.capture_filter = capture_filter
        self.is_capturing = False
        self.process = None
        self.packet_queue = Queue()
        self.capture_thread = None
    
    def _find_interface(self) -> Optional[str]:
        """Find available network interface."""
        try:
            cmd = [self.tshark_path, '-D']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines:
                    preferred = None
                    for line in lines:
                        if '(Wi-Fi)' in line or '(Wi‑Fi)' in line:
                            preferred = line
                            break
                    target = preferred or next((l for l in lines if 'Loopback' not in l and 'etwdump' not in l), lines[0])
                    parts = target.split()
                    interface = parts[1] if len(parts) > 1 else target
                    logger.info(f"Found interface: {interface}")
                    return interface
        except Exception as e:
            logger.warning(f"Could not auto-detect interface: {e}")
        
        return None
    
    def _parse_packet(self, packet_json: Dict) -> Optional[Dict]:
        """
        Parse a packet from tshark JSON output.
        
        Args:
            packet_json: JSON object from tshark
            
        Returns:
            Parsed packet dictionary
        """
        try:
            layers = packet_json.get('layers', {}) or packet_json.get('_source', {}).get('layers', {})
            frame_layer = layers.get('frame', {}) or layers.get('frame_frame', {})
            frame_time = frame_layer.get('frame_time_epoch') or frame_layer.get('frame_frame_time_epoch')
            if isinstance(frame_time, list):
                frame_time = frame_time[0]
            try:
                timestamp = float(frame_time)
            except Exception:
                timestamp = time.time()
            frame_len = frame_layer.get('frame_len') or frame_layer.get('frame_frame_len')
            if isinstance(frame_len, list):
                frame_len = frame_len[0]
            try:
                length = int(frame_len)
            except Exception:
                length = 0
            ip_layer = layers.get('ip', {}) or layers.get('ip_ip', {})
            src_ip = ip_layer.get('ip_src') or ip_layer.get('ip_ip_src')
            dst_ip = ip_layer.get('ip_dst') or ip_layer.get('ip_ip_dst')
            if isinstance(src_ip, list):
                src_ip = src_ip[0]
            if isinstance(dst_ip, list):
                dst_ip = dst_ip[-1]
            src_port = None
            dst_port = None
            protocol = 'UNKNOWN'
            tcp_layer = layers.get('tcp', {}) or layers.get('tcp_tcp', {})
            if tcp_layer:
                protocol = 'TCP'
                ports = tcp_layer.get('tcp_port') or tcp_layer.get('tcp_tcp_port')
                if isinstance(ports, list) and len(ports) >= 2:
                    src_port, dst_port = ports[0], ports[1]
                else:
                    src_port = tcp_layer.get('tcp_srcport') or tcp_layer.get('tcp_tcp_srcport')
                    dst_port = tcp_layer.get('tcp_dstport') or tcp_layer.get('tcp_tcp_dstport')
                flags = tcp_layer.get('tcp_flags') or tcp_layer.get('tcp_tcp_flags')
                if isinstance(flags, list):
                    flags = flags[0]
                try:
                    tcp_flags_val = int(flags)
                except Exception:
                    try:
                        tcp_flags_val = int(flags, 16)
                    except Exception:
                        tcp_flags_val = 0
            else:
                tcp_flags_val = 0
            udp_layer = layers.get('udp', {}) or layers.get('udp_udp', {})
            if udp_layer and protocol == 'UNKNOWN':
                protocol = 'UDP'
                src_port = udp_layer.get('udp_srcport') or udp_layer.get('udp_udp_srcport')
                dst_port = udp_layer.get('udp_dstport') or udp_layer.get('udp_udp_dstport')
            direction = 'forward'
            packet = {
                'timestamp': timestamp,
                'length': length,
                'src_ip': (src_ip or '0.0.0.0'),
                'dst_ip': (dst_ip or '0.0.0.0'),
                'src_port': int(src_port) if src_port else 0,
                'dst_port': int(dst_port) if dst_port else 0,
                'protocol': protocol,
                'tcp_flags': tcp_flags_val,
                'direction': direction
            }
            return packet
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _capture_worker(self):
        """Worker thread for capturing packets."""
        interface = self.interface or self._find_interface()
        if not interface:
            logger.error("No network interface available")
            return
        
        # Build tshark command
        cmd = [
            self.tshark_path,
            '-i', interface,
            '-l',
            '-T', 'ek'
        ]
        
        if self.capture_filter:
            cmd.extend(['-f', self.capture_filter])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            while self.is_capturing:
                if self.process.poll() is not None:
                    break
                
                line = self.process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    packet_json = json.loads(line)
                    packet = self._parse_packet(packet_json)
                    if packet:
                        self.packet_queue.put(packet)
                except json.JSONDecodeError:
                    continue
        
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)
    
    def start_capture(self):
        """Start capturing packets."""
        if self.is_capturing:
            logger.warning("Capture already running")
            return
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
        self.capture_thread.start()
        logger.info("Started packet capture")
    
    def stop_capture(self):
        """Stop capturing packets."""
        self.is_capturing = False
        if self.process:
            self.process.terminate()
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Stopped packet capture")
    
    def get_packets(self, timeout: float = 1.0) -> List[Dict]:
        """
        Get captured packets.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of packet dictionaries
        """
        packets = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                packet = self.packet_queue.get(timeout=0.1)
                packets.append(packet)
            except:
                break
        
        return packets
    
    def capture_duration(self, duration: int, output_file: Optional[str] = None) -> pd.DataFrame:
        """
        Capture packets for a specified duration.
        
        Args:
            duration: Duration in seconds
            output_file: Optional CSV file to save packets
            
        Returns:
            DataFrame with captured packets
        """
        self.start_capture()
        
        all_packets = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            packets = self.get_packets(timeout=1.0)
            all_packets.extend(packets)
        
        self.stop_capture()
        
        if all_packets:
            df = pd.DataFrame(all_packets)
            if output_file:
                df.to_csv(output_file, index=False)
            return df
        
        return pd.DataFrame()
