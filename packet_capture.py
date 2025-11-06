"""
Network Packet Capture Module
Uses Scapy to capture and parse network packets
"""

import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, ARP
from scapy.error import Scapy_Exception
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

class PacketCapture:
    """Network packet capture and parsing"""
    
    def __init__(self, interface='eth0'):
        """
        Initialize packet capture
        
        Args:
            interface: Network interface to capture from
        """
        self.interface = interface
        self.logger = logging.getLogger(__name__)
        self.captured_packets = []
        self.packet_buffer = []
        self.start_time = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'unique_ips': set(),
            'unique_ports': set()
        }
    
    def packet_handler(self, packet):
        """
        Handle captured packets
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = self.parse_packet(packet)
            if packet_info:
                self.packet_buffer.append(packet_info)
                self.update_stats(packet_info)
                
                # Buffer management
                if len(self.packet_buffer) >= 1000:
                    self.captured_packets.extend(self.packet_buffer)
                    self.packet_buffer = []
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
    
    def parse_packet(self, packet):
        """
        Parse packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Parsed packet information
        """
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload_size': 0,
            'payload_data': None
        }
        
        # Check if packet has IP layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['protocol'] = ip_layer.proto
            
            # Add IPs to statistics
            self.stats['unique_ips'].add(ip_layer.src)
            self.stats['unique_ips'].add(ip_layer.dst)
            
            # Parse protocol-specific information
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = tcp_layer.flags
                
                self.stats['tcp_packets'] += 1
                self.stats['unique_ports'].add(tcp_layer.sport)
                self.stats['unique_ports'].add(tcp_layer.dport)
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
                
                self.stats['udp_packets'] += 1
                self.stats['unique_ports'].add(udp_layer.sport)
                self.stats['unique_ports'].add(udp_layer.dport)
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                self.stats['icmp_packets'] += 1
                
            else:
                self.stats['other_packets'] += 1
            
            # Extract payload information
            if Raw in packet:
                payload = packet[Raw].load
                packet_info['payload_size'] = len(payload)
                packet_info['payload_data'] = payload[:100]  # Store first 100 bytes
        
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            arp_layer = packet[ARP]
            packet_info['src_ip'] = arp_layer.psrc
            packet_info['dst_ip'] = arp_layer.pdst
            
        self.stats['total_packets'] += 1
        
        return packet_info
    
    def update_stats(self, packet_info):
        """Update packet statistics"""
        # Additional statistics can be added here
        pass
    
    def capture_packets(self, duration=60, filter_expression=None):
        """
        Capture network packets for specified duration
        
        Args:
            duration: Capture duration in seconds
            filter_expression: BPF filter expression (optional)
            
        Returns:
            list: Captured packets information
        """
        self.logger.info(f"Starting packet capture on {self.interface} for {duration} seconds")
        self.start_time = datetime.now()
        
        try:
            # Clear previous captures
            self.captured_packets = []
            self.packet_buffer = []
            
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=duration,
                filter=filter_expression,
                store=0  # Don't store packets in memory
            )
            
            # Add remaining packets in buffer
            if self.packet_buffer:
                self.captured_packets.extend(self.packet_buffer)
            
            capture_time = datetime.now() - self.start_time
            self.logger.info(f"Packet capture completed in {capture_time.total_seconds():.2f} seconds")
            self.logger.info(f"Total packets captured: {len(self.captured_packets)}")
            self.logger.info(f"Statistics: {self.get_capture_stats()}")
            
            return self.captured_packets
            
        except Scapy_Exception as e:
            self.logger.error(f"Scapy error during capture: {str(e)}")
            if "WinPcap" in str(e) or "Npcap" in str(e):
                self.logger.error("Please ensure WinPcap/Npcap is installed on Windows")
            return []
        except PermissionError:
            self.logger.error("Permission denied. Run with administrator/sudo privileges.")
            return []
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")
            return []
    
    def get_capture_stats(self):
        """Get packet capture statistics"""
        stats = self.stats.copy()
        stats['unique_ip_count'] = len(stats['unique_ips'])
        stats['unique_port_count'] = len(stats['unique_ports'])
        
        # Remove sets for JSON serialization
        del stats['unique_ips']
        del stats['unique_ports']
        
        return stats
    
    def get_interface_info(self):
        """Get network interface information"""
        try:
            from scapy.all import get_if_list, get_if_addr
            
            interfaces = get_if_list()
            interface_info = {}
            
            for iface in interfaces:
                try:
                    addr = get_if_addr(iface)
                    interface_info[iface] = addr
                except:
                    interface_info[iface] = "No IP assigned"
            
            return interface_info
            
        except ImportError:
            self.logger.warning("Could not import scapy network functions")
            return {}
    
    def set_interface(self, interface):
        """Set network interface for capture"""
        self.interface = interface
        self.logger.info(f"Network interface set to: {interface}")
    
    def save_capture(self, filename):
        """Save captured packets to file"""
        try:
            import json
            
            capture_data = {
                'interface': self.interface,
                'capture_time': self.start_time.isoformat() if self.start_time else None,
                'total_packets': len(self.captured_packets),
                'statistics': self.get_capture_stats(),
                'packets': self.captured_packets[:1000]  # Save first 1000 packets
            }
            
            with open(filename, 'w') as f:
                json.dump(capture_data, f, indent=2, default=str)
            
            self.logger.info(f"Capture saved to {filename}")
            
        except Exception as e:
            self.logger.error(f"Error saving capture: {str(e)}")
    
    def load_capture(self, filename):
        """Load captured packets from file"""
        try:
            import json
            
            with open(filename, 'r') as f:
                capture_data = json.load(f)
            
            self.captured_packets = capture_data.get('packets', [])
            self.stats = capture_data.get('statistics', {})
            
            self.logger.info(f"Capture loaded from {filename}")
            return self.captured_packets
            
        except Exception as e:
            self.logger.error(f"Error loading capture: {str(e)}")
            return []