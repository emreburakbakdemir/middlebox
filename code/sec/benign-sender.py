#!/usr/bin/env python3
import socket
import random
import time
import threading
from scapy.all import IP, TCP, send
import argparse

class EnhancedTrafficGenerator:
    def __init__(self, target_ip='10.0.0.21'):
        self.target_ip = target_ip
        self.running = False
        self.packet_count = 0
    
    def generate_realistic_tcp_options(self):
        """Generate realistic TCP option combinations found in normal traffic"""
        option_sets = [
            # Common browser patterns
            [('MSS', 1460), ('SAckOK', ''), ('Timestamp', (random.randint(1000000, 9999999), 0)), ('NOP', None), ('WScale', 7)],
            [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('SAckOK', ''), ('Timestamp', (random.randint(1000000, 9999999), 0))],
            
            # Mobile/embedded patterns
            [('MSS', 1400), ('SAckOK', ''), ('WScale', 6)],
            [('MSS', 1360), ('NOP', None), ('NOP', None), ('SAckOK', '')],
            
            # Server patterns
            [('MSS', 1460), ('SAckOK', ''), ('Timestamp', (random.randint(1000000, 9999999), 0)), ('WScale', 14)],
            [('MSS', 8960), ('NOP', None), ('WScale', 7), ('SAckOK', ''), ('Timestamp', (random.randint(1000000, 9999999), 0))],
            
            # Legacy systems
            [('MSS', 1460)],
            [('MSS', 1460), ('SAckOK', '')],
            
            # Load balancer patterns
            [('MSS', 1460), ('NOP', None), ('NOP', None), ('Timestamp', (random.randint(1000000, 9999999), 0)), ('SAckOK', ''), ('WScale', 9)]
        ]
        return random.choice(option_sets)
    
    def realistic_syn_generator(self):
        """Generate SYN packets with realistic option patterns"""
        common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5432, 3306, 27017]
        
        while self.running:
            port = random.choice(common_ports)
            options = self.generate_realistic_tcp_options()
            
            try:
                pkt = IP(dst=self.target_ip)/TCP(
                    dport=port, 
                    flags='S', 
                    options=options,
                    sport=random.randint(32768, 65535)
                )
                send(pkt, verbose=0)
                self.packet_count += 1
                
                # Realistic timing patterns
                if random.random() < 0.3:  # 30% chance of burst
                    time.sleep(random.uniform(0.01, 0.1))
                else:
                    time.sleep(random.uniform(0.1, 2.0))
                    
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    def web_browsing_syn_pattern(self):
        """Simulate web browsing SYN patterns"""
        web_ports = [80, 443, 8080, 8443]
        
        while self.running:
            # Simulate page load with multiple connections
            connections = random.randint(3, 12)  # Modern browsers open multiple connections
            
            for _ in range(connections):
                port = random.choice(web_ports)
                options = self.generate_realistic_tcp_options()
                
                pkt = IP(dst=self.target_ip)/TCP(
                    dport=port,
                    flags='S',
                    options=options,
                    sport=random.randint(32768, 65535)
                )
                send(pkt, verbose=0)
                self.packet_count += 1
                time.sleep(random.uniform(0.01, 0.05))  # Quick succession
            
            # User think time
            time.sleep(random.uniform(2, 10))
    
    def background_services_pattern(self):
        """Simulate background service connections"""
        service_ports = [22, 25, 110, 143, 993, 995, 53]
        
        while self.running:
            port = random.choice(service_ports)
            options = self.generate_realistic_tcp_options()
            
            pkt = IP(dst=self.target_ip)/TCP(
                dport=port,
                flags='S',
                options=options,
                sport=random.randint(32768, 65535)
            )
            send(pkt, verbose=0)
            self.packet_count += 1
            
            # Background services have longer intervals
            time.sleep(random.uniform(10, 60))
    
    def port_scan_simulation(self):
        """Occasionally simulate port scanning behavior (legitimate security tools)"""
        while self.running:
            # Wait longer between scan sessions
            time.sleep(random.uniform(300, 600))  # 5-10 minutes
            
            if not self.running:
                break
                
            # Quick port scan
            target_ports = random.sample(range(1, 1024), random.randint(5, 20))
            
            for port in target_ports:
                if not self.running:
                    break
                    
                options = self.generate_realistic_tcp_options()
                pkt = IP(dst=self.target_ip)/TCP(
                    dport=port,
                    flags='S',
                    options=options,
                    sport=random.randint(32768, 65535)
                )
                send(pkt, verbose=0)
                self.packet_count += 1
                time.sleep(random.uniform(0.001, 0.01))  # Fast scanning
    
    def start_generation(self, duration_minutes=10):
        """Start all traffic generation patterns"""
        self.running = True
        self.packet_count = 0
        
        patterns = [
            self.realistic_syn_generator,
            self.web_browsing_syn_pattern,
            self.background_services_pattern,
            self.port_scan_simulation
        ]
        
        threads = []
        for pattern in patterns:
            thread = threading.Thread(target=pattern)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        print(f"Started benign traffic generation for {duration_minutes} minutes...")
        
        # Monitor and report
        start_time = time.time()
        while time.time() - start_time < duration_minutes * 60:
            time.sleep(30)  # Report every 30 seconds
            print(f"Generated {self.packet_count} benign SYN packets so far...")
        
        self.running = False
        print(f"Benign traffic generation complete. Total packets: {self.packet_count}")
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Benign Traffic Generator")
    parser.add_argument("--target", default="10.0.0.21", help="Target IP address")
    parser.add_argument("--duration", type=int, default=10, help="Duration in minutes")
    
    args = parser.parse_args()
    
    generator = EnhancedTrafficGenerator(args.target)
    generator.start_generation(args.duration)