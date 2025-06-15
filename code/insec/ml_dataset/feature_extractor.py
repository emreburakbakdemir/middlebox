#!/usr/bin/env python3

import os
import pandas as pd
import numpy as np
from scapy.all import rdpcap, TCP, IP
import hashlib
import argparse
from collections import Counter
import warnings
warnings.filterwarnings("ignore")

class TCPSYNFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            "src_port", "dst_port", "window_size", "tcp_flags", "packet_size",
            "num_options", "has_MSS", "has_WScale", "has_NOP", "has_SAckOK",
            "has_Timestamp", "has_UTO", "has_EOL", "mss_value", "has_standard_mss",
            "wscale_value", "timestamp_val", "timestamp_echo", "has_zero_timestamp",
            "option_sequence_hash", "has_4_options", "has_5_options", "src_port_range",
            "dst_port_range", "avg_interval", "std_interval", "min_interval",
            "max_interval", "interval_regularity", "interval_coefficient_variation",
            "pattern_diversity", "total_syn_packets"
        ]
    
    def extract_packet_features(self, packet):
        """Extract features from a single TCP SYN packet"""
        features = {}
        
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None
            
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Basic packet features
        features['src_port'] = tcp.sport
        features['dst_port'] = tcp.dport
        features['window_size'] = tcp.window
        features['tcp_flags'] = tcp.flags
        features['packet_size'] = len(packet)
        
        # TCP options analysis
        options = tcp.options if tcp.options else []
        features['num_options'] = len(options)
        
        # Option presence flags
        option_types = [opt[0] if isinstance(opt, tuple) else opt for opt in options]
        features['has_MSS'] = 1 if 'MSS' in option_types else 0
        features['has_WScale'] = 1 if 'WScale' in option_types else 0
        features['has_NOP'] = 1 if 'NOP' in option_types else 0
        features['has_SAckOK'] = 1 if 'SAckOK' in option_types else 0
        features['has_Timestamp'] = 1 if 'Timestamp' in option_types else 0
        features['has_UTO'] = 1 if 'UTO' in option_types else 0
        features['has_EOL'] = 1 if 'EOL' in option_types else 0
        
        # Option values
        features['mss_value'] = 0
        features['wscale_value'] = 0
        features['timestamp_val'] = 0
        features['timestamp_echo'] = 0
        
        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                if opt[0] == 'MSS':
                    features['mss_value'] = opt[1]
                elif opt[0] == 'WScale':
                    features['wscale_value'] = opt[1]
                elif opt[0] == 'Timestamp' and isinstance(opt[1], tuple) and len(opt[1]) >= 2:
                    features['timestamp_val'] = opt[1][0]
                    features['timestamp_echo'] = opt[1][1]
        
        # Derived features
        features['has_standard_mss'] = 1 if features['mss_value'] == 1460 else 0
        features['has_zero_timestamp'] = 1 if (features['timestamp_val'] == 0 and 
                                              features['timestamp_echo'] == 0 and 
                                              features['has_Timestamp']) else 0
        
        # Option sequence hash
        option_sequence = str(sorted(option_types))
        features['option_sequence_hash'] = int(hashlib.md5(option_sequence.encode()).hexdigest()[:8], 16)
        
        # Option count patterns
        features['has_4_options'] = 1 if features['num_options'] == 4 else 0
        features['has_5_options'] = 1 if features['num_options'] == 5 else 0
        
        return features
    
    def calculate_flow_features(self, packets):
        """Calculate flow-level features from a list of packets"""
        if not packets:
            return {}
        
        # Extract timestamps and ports
        timestamps = [float(pkt.time) for pkt in packets]
        src_ports = [pkt[TCP].sport for pkt in packets if pkt.haslayer(TCP)]
        dst_ports = [pkt[TCP].dport for pkt in packets if pkt.haslayer(TCP)]
        
        # Port range features
        src_port_range = max(src_ports) - min(src_ports) if src_ports else 0
        dst_port_range = max(dst_ports) - min(dst_ports) if dst_ports else 0
        
        # Timing features
        intervals = []
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if intervals:
            avg_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            min_interval = min(intervals)
            max_interval = max(intervals)
            
            # Interval regularity (inverse of coefficient of variation)
            cv = std_interval / avg_interval if avg_interval > 0 else 0
            interval_regularity = 1 / (1 + cv) if cv > 0 else 1
            interval_coefficient_variation = cv
        else:
            avg_interval = std_interval = min_interval = max_interval = 0
            interval_regularity = interval_coefficient_variation = 0
        
        # Pattern diversity (unique option sequences)
        option_patterns = []
        for pkt in packets:
            if pkt.haslayer(TCP):
                options = pkt[TCP].options if pkt[TCP].options else []
                option_types = [opt[0] if isinstance(opt, tuple) else opt for opt in options]
                option_patterns.append(tuple(sorted(option_types)))
        
        pattern_diversity = len(set(option_patterns))
        total_syn_packets = len(packets)
        
        return {
            'src_port_range': src_port_range,
            'dst_port_range': dst_port_range,
            'avg_interval': avg_interval,
            'std_interval': std_interval,
            'min_interval': min_interval,
            'max_interval': max_interval,
            'interval_regularity': interval_regularity,
            'interval_coefficient_variation': interval_coefficient_variation,
            'pattern_diversity': pattern_diversity,
            'total_syn_packets': total_syn_packets
        }
    
    def process_pcap(self, pcap_path, label):
        """Process a single PCAP file and extract features"""
        print(f"Processing {pcap_path}...")
        
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            print(f"Error reading {pcap_path}: {e}")
            return []
        
        # Filter TCP SYN packets
        syn_packets = []
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:  # SYN flag
                syn_packets.append(pkt)
        
        print(f"Found {len(syn_packets)} SYN packets in {pcap_path}")
        
        if not syn_packets:
            return []
        
        # Extract packet-level features
        packet_features = []
        for pkt in syn_packets:
            features = self.extract_packet_features(pkt)
            if features:
                packet_features.append(features)
        
        # Calculate flow-level features
        flow_features = self.calculate_flow_features(syn_packets)
        
        # Combine features
        result_rows = []
        for pkt_features in packet_features:
            combined_features = {**pkt_features, **flow_features}
            combined_features['label'] = label
            combined_features['pcap_file'] = os.path.basename(pcap_path)
            result_rows.append(combined_features)
        
        return result_rows
    
    def extract_features_from_pcaps(self, pcap_files, output_csv):
        """Extract features from multiple PCAP files and save to CSV"""
        all_features = []
        
        for pcap_path, label in pcap_files:
            if not os.path.exists(pcap_path):
                print(f"Warning: {pcap_path} not found, skipping...")
                continue
            
            features = self.process_pcap(pcap_path, label)
            all_features.extend(features)
        
        if not all_features:
            print("No features extracted from any PCAP files!")
            return
        
        # Create DataFrame
        df = pd.DataFrame(all_features)
        
        # Ensure all feature columns exist
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        # Reorder columns
        column_order = self.feature_names + ['label', 'pcap_file']
        df = df[column_order]
        
        # Save to CSV
        df.to_csv(output_csv, index=False)
        print(f"Features extracted and saved to {output_csv}")
        print(f"Total samples: {len(df)}")
        print(f"Label distribution:")
        print(df['label'].value_counts())
        
        return df

def main():
    parser = argparse.ArgumentParser(description="Extract TCP SYN features from PCAP files")
    parser.add_argument("--pcap-dir", type=str, default="./raw_pcaps", 
                       help="Directory containing PCAP files")
    parser.add_argument("--output", type=str, default="tcp_syn_features.csv",
                       help="Output CSV file")
    
    args = parser.parse_args()
    
    # Define PCAP files and their labels
    pcap_files = [
        (os.path.join(args.pcap_dir, "benign1.pcap"), "benign"),
        (os.path.join(args.pcap_dir, "benign2.pcap"), "benign"),
        (os.path.join(args.pcap_dir, "benign3.pcap"), "benign"),
        (os.path.join(args.pcap_dir, "benign4.pcap"), "benign"),
        (os.path.join(args.pcap_dir, "covert.pcap"), "covert"),
        (os.path.join(args.pcap_dir, "mixed.pcap"), "mixed")
    ]
    
    # Create feature extractor
    extractor = TCPSYNFeatureExtractor()
    
    # Extract features
    df = extractor.extract_features_from_pcaps(pcap_files, args.output)
    
    if df is not None:
        print(f"\nFeature extraction completed successfully!")
        print(f"Output saved to: {args.output}")

if __name__ == "__main__":
    main()