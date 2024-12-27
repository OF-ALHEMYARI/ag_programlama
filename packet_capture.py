from scapy.all import sniff, IP, TCP
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='network_traffic.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def packet_callback(packet):
    """Callback function to process captured packets"""
    if IP in packet and TCP in packet:
        try:
            # Extract packet information
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Log packet information
            log_message = f"TCP Traffic - Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}"
            if dst_port == 5000 or src_port == 5000:  # Our application port
                logging.info(log_message)
                
            # Additional analysis for application packets
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                if b'HTTP' in payload:
                    logging.info(f"HTTP Request detected: {payload[:100]}")
                elif b'websocket' in payload.lower():
                    logging.info(f"WebSocket traffic detected")
                    
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

def start_capture(interface="any"):
    """Start packet capture on specified interface"""
    try:
        logging.info(f"Starting packet capture on interface: {interface}")
        # Filter for our application traffic (port 5000)
        sniff(
            iface=interface,
            filter="tcp port 5000",
            prn=packet_callback,
            store=0
        )
    except Exception as e:
        logging.error(f"Error starting packet capture: {str(e)}")

if __name__ == "__main__":
    start_capture()
