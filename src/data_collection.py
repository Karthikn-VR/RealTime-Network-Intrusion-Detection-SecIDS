import pyshark
import pandas as pd
from threading import Thread, Event
import time
import asyncio

class DataCollector:
    def __init__(self, interface=r'\Device\NPF_{2AE8090C-C286-4E01-BDDB-DF4B99B98F96}', 
                 capture_duration=60, 
                 tshark_path='C:\\Program Files\\Wireshark\\tshark.exe'):
        self.interface = interface
        self.capture_duration = capture_duration
        self.packets = []
        self.tshark_path = tshark_path
        self.capture = None
        self.stop_event = Event()

    def _capture(self, packet):
        try:
            packet_data = {
                'timestamp': float(packet.sniff_time.timestamp()),
                'length': int(packet.length),
                'protocol': packet.highest_layer
            }
            self.packets.append(packet_data)
        except AttributeError as e:
            print(f"Skipping malformed packet: {e}")

    def _capture_thread(self):
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface, 
                tshark_path=self.tshark_path,
                only_summaries=False
            )
            self.capture.apply_on_packets(self._capture, timeout=self.capture_duration)
        except Exception as e:
            print(f"Capture thread error: {e}")
        finally:
            self.stop_event.set()

    def capture_traffic_sync(self, output_file='data/captured_traffic.csv'):
        print(f"Capturing traffic for {self.capture_duration} seconds...")
        
        start_time = time.time()
        capture_thread = Thread(target=self._capture_thread)
        capture_thread.start()
        
        # Wait for capture to complete or timeout
        self.stop_event.wait(self.capture_duration + 5)
        
        if capture_thread.is_alive():
            print("Capture timeout reached, stopping...")
            if self.capture:
                self.capture.close()
            capture_thread.join(timeout=1)
        
        elapsed = time.time() - start_time
        print(f"Captured {len(self.packets)} packets in {elapsed:.2f} seconds")
        
        if self.packets:
            df = pd.DataFrame(self.packets)
            df.to_csv(output_file, index=False)
            return df
        return pd.DataFrame()

    async def capture_traffic(self, output_file='data/captured_traffic.csv'):
        try:
            loop = asyncio.get_event_loop()
            df = await loop.run_in_executor(None, self.capture_traffic_sync, output_file)
            return df
        except Exception as e:
            print(f"Async capture error: {e}")
            return pd.DataFrame()

if __name__ == "__main__":
    async def test():
        collector = DataCollector(capture_duration=30)
        traffic_data = await collector.capture_traffic()
        print(traffic_data.head() if not traffic_data.empty else "No packets captured")

    asyncio.run(test())