import asyncio
from nats.aio.client import Client as NATS
import os, random, pickle, time
import numpy as np
from collections import defaultdict, deque
from scapy.all import Ether, IP, TCP


class Processor:
    def __init__(self):
        self.nc = NATS()
        self.nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
        
        # Configuration from environment variables
        self.mitigation_enabled = os.getenv('MITIGATION_ENABLED', 'true').lower() == 'true'
        self.mitigation_mode = os.getenv('MITIGATION_MODE', 'adaptive')
        self.models_dir = os.getenv('MODELS_DIR', '/code/new-python-processor/models')
        
        # Load ML models
        self.detector_model = None
        self.label_encoder = None
        self.scaler = None
        self.load_ml_models()
        
        # Flow tracking
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'covert_predictions': deque(maxlen=10),
            'last_seen': time.time()
        })
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'covert_detected': 0,
            'packets_normalized': 0,
            'packets_delayed': 0
        }
        
        # Normalization settings
        self.standard_option_order = ['MSS', 'SAckOK', 'WScale', 'Timestamp', 'NOP']
        self.standard_mss_values = [1460, 1440, 1380, 1360]
        
        print(f"   Processor initialized:")
        print(f"   Mitigation: {'Enabled' if self.mitigation_enabled else 'Disabled'}")
        print(f"   Mode: {self.mitigation_mode}")
        print(f"   Models dir: {self.models_dir}")
    
    def load_ml_models(self):
        """Load your three .pkl files"""
        try:
            # Model file paths
            detector_file = "covert_detector_fixed.pkl"
            encoder_file = "label_encoder_fixed.pkl"
            scaler_file = "scaler_fixed.pkl"
            
            # Load detector
            detector_path = os.path.join(self.models_dir, detector_file)
            if os.path.exists(detector_path):
                with open(detector_path, 'rb') as f:
                    self.detector_model = pickle.load(f)
                print(f"Loaded: {detector_file}")
            else:
                print(f"Not found: {detector_file}")
            
            # Load encoder
            encoder_path = os.path.join(self.models_dir, encoder_file)
            if os.path.exists(encoder_path):
                with open(encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                print(f"Loaded: {encoder_file}")
            else:
                print(f"Not found: {encoder_file}")
            
            # Load scaler
            scaler_path = os.path.join(self.models_dir, scaler_file)
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print(f"Loaded: {scaler_file}")
            else:
                print(f"Not found: {scaler_file}")
                
        except Exception as e:
            print(f"Error loading models: {e}")
    
    def extract_features(self, tcp_layer):
        """Extract features matching your Phase 3 training"""
        try:
            features = []
            options = tcp_layer.options if tcp_layer.options else []
            
            features.extend([
                len(options),
                int(tcp_layer.flags),  # Convert FlagValue to int
                tcp_layer.dport,
                tcp_layer.sport,
                tcp_layer.window
            ])
            
            # Option presence
            common_options = ['MSS', 'WScale', 'NOP', 'SAckOK', 'Timestamp', 'EOL']
            option_names = [opt[0] if len(opt) > 0 else '' for opt in options]
            
            for opt_name in common_options:
                features.append(1 if opt_name in option_names else 0)
            
            # Option values
            mss_val = wscale_val = timestamp_val = 0
            for opt in options:
                if len(opt) >= 2:
                    if opt[0] == 'MSS' and isinstance(opt[1], int):
                        mss_val = opt[1]
                    elif opt[0] == 'WScale' and isinstance(opt[1], int):
                        wscale_val = opt[1]
                    elif opt[0] == 'Timestamp' and isinstance(opt[1], tuple):
                        timestamp_val = opt[1][0] if len(opt[1]) > 0 else 0
            
            features.extend([mss_val, wscale_val, timestamp_val])
            
            # Option order (important for your covert channel)
            for i in range(3):
                if i < len(option_names):
                    features.append(hash(option_names[i]) % 1000)
                else:
                    features.append(0)
            
            # Pad to consistent length
            while len(features) < 20:
                features.append(0)
            
            return np.array(features[:20])
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return np.zeros(20)
    
    def predict_covert(self, tcp_layer):
        """Predict if packet contains covert channel"""
        if not all([self.detector_model, self.scaler]):
            return self.rule_based_detect(tcp_layer)
        
        try:
            features = self.extract_features(tcp_layer).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            
            if hasattr(self.detector_model, 'predict_proba'):
                probs = self.detector_model.predict_proba(features_scaled)[0]
                
                # Find covert class probability
                if self.label_encoder and hasattr(self.label_encoder, 'classes_'):
                    classes = list(self.label_encoder.classes_)
                    if 'covert' in classes:
                        covert_idx = classes.index('covert')
                        return float(probs[covert_idx])
                    elif 'Covert' in classes:
                        covert_idx = classes.index('Covert')
                        return float(probs[covert_idx])
                    elif len(classes) == 2:
                        # Binary classification: assume [benign, covert] or [0, 1]
                        return float(probs[1])
                
                # Fallback: assume last class is covert
                return float(probs[-1])
            else:
                # No probabilities available
                pred = self.detector_model.predict(features_scaled)[0]
                return 1.0 if str(pred).lower() in ['covert', '1'] else 0.0
                
        except Exception as e:
            print(f"ML prediction error: {e}")
            return self.rule_based_detect(tcp_layer)
    
    def rule_based_detect(self, tcp_layer):
        """Fallback detection using known patterns"""
        if not tcp_layer.options:
            return 0.0
        
        option_names = set(opt[0] for opt in tcp_layer.options if opt[0] != 'EOL')
        
        # Your covert channel signatures
        if option_names == {'MSS', 'WScale', 'NOP', 'SAckOK'}:
            return 0.9
        if option_names == {'MSS', 'WScale', 'NOP', 'SAckOK', 'Timestamp'}:
            return 0.9
        if tcp_layer.dport == 1234 and len(option_names) >= 3:
            return 0.7
        
        return 0.1
    
    def should_mitigate(self, flow_key, covert_prob):
        """Decide whether to apply mitigation based on prediction and mode"""
        flow = self.flow_stats[flow_key]
        
        # Evaluate each packet individually first
        thresholds = {
            'conservative': 0.9,
            'adaptive': 0.8,
            'aggressive': 0.6
        }
        
        current_threshold = thresholds.get(self.mitigation_mode, 0.8)
        
        # Individual packet decision
        if covert_prob > current_threshold:
            flow['covert_predictions'].append(covert_prob)
            return True
        
        # For non-covert packets, still track but don't average with covert ones
        if covert_prob < 0.3:  # Only track clearly benign packets
            flow['covert_predictions'].append(covert_prob)
        
        # Optional: Flow-based enhancement (only for borderline cases)
        if 0.3 <= covert_prob <= current_threshold and len(flow['covert_predictions']) >= 2:
            # Look at recent high-confidence predictions only
            high_conf_predictions = [p for p in list(flow['covert_predictions']) if p > 0.5]
            if len(high_conf_predictions) >= 2:
                recent_avg = np.mean(high_conf_predictions[-3:])  # Last 3 high-confidence predictions
                return recent_avg > (current_threshold - 0.1)  # Slightly lower threshold for patterns
        
        return False
    
    def normalize_tcp_options(self, tcp_layer):
        """Apply realistic TCP option normalization"""
        if not tcp_layer.options:
            return False
        
        original = tcp_layer.options[:]
        
        # Group options by type
        option_dict = {}
        for opt in tcp_layer.options:
            if opt[0] != 'EOL':
                option_dict[opt[0]] = opt
        
        # Rebuild in standard order
        normalized = []
        for opt_name in self.standard_option_order:
            if opt_name in option_dict:
                opt = option_dict[opt_name]
                
                # Normalize MSS to standard values
                if opt_name == 'MSS' and len(opt) > 1:
                    if opt[1] not in self.standard_mss_values:
                        closest = min(self.standard_mss_values, key=lambda x: abs(x - opt[1]))
                        opt = (opt[0], closest)
                
                # Clamp window scale to valid range
                elif opt_name == 'WScale' and len(opt) > 1:
                    if not (0 <= opt[1] <= 8):
                        opt = (opt[0], max(0, min(8, opt[1])))
                
                normalized.append(opt)
        
        # Add any remaining options
        for opt_name, opt in option_dict.items():
            if opt_name not in self.standard_option_order:
                normalized.append(opt)
        
        # Update if changed
        if normalized != original:
            tcp_layer.options = normalized
            return True
        
        return False
    
    def get_flow_key(self, packet):
        """Generate flow identifier for tracking"""
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return "unknown"
        
        ip = packet[IP]
        tcp = packet[TCP]
        
        # Normalize flow direction
        if ip.src < ip.dst:
            return f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
        else:
            return f"{ip.dst}:{tcp.dport}-{ip.src}:{tcp.sport}"
    
    async def message_handler(self, msg):
        """Enhanced message handler with mitigation"""
        subject = msg.subject
        data = msg.data
        packet = Ether(data)
        
        self.stats['total_packets'] += 1
        
        # Original functionality: random delay
        delay = random.expovariate(1 / 1e-4)  # 0.1ms average
        # print(f"Delaying packet for {delay:.6f} seconds")
        await asyncio.sleep(delay)
        self.stats['packets_delayed'] += 1
        
        # Mitigation logic (if enabled and TCP packet)
        if self.mitigation_enabled and packet.haslayer(TCP):
            self.stats['tcp_packets'] += 1
            tcp_layer = packet[TCP]
            flow_key = self.get_flow_key(packet)
            
            # Predict covert channel probability
            covert_prob = self.predict_covert(tcp_layer)
            
            # Update flow stats
            flow = self.flow_stats[flow_key]
            flow['packet_count'] += 1
            flow['last_seen'] = time.time()
            
            # Apply mitigation if needed
            if self.should_mitigate(flow_key, covert_prob):
                self.stats['covert_detected'] += 1
                
                print(f"COVERT DETECTED: {flow_key[:30]}... (prob: {covert_prob:.3f})")
                
                # Apply normalization
                if self.normalize_tcp_options(tcp_layer):
                    self.stats['packets_normalized'] += 1
                    print(f"   TCP options normalized")
                    
                    # Recalculate checksums after modification
                    if packet.haslayer(IP):
                        del packet[IP].chksum
                        del packet[TCP].chksum
                        # Reconstruct packet to trigger checksum calculation
                        packet = packet.__class__(bytes(packet))
                
                # Additional delay for covert packets
                delay = random.expovariate(1 / 1e-4) # 0.1ms
                # print(f"Delaying the packet for {delay:.6f} seconds")
        
        # Forward packet (original functionality)
        if subject == "inpktsec":
            await self.nc.publish("outpktinsec", bytes(packet))
        else:
            await self.nc.publish("outpktsec", bytes(packet))
        
        # Show packet details occasionally
        # if self.stats['total_packets'] % 50 == 0:
        #     print(packet.show())
    
    def cleanup_flows(self):
        """Remove old flow entries to prevent memory bloat"""
        current_time = time.time()
        timeout = 300  # 5 minutes
        
        old_flows = [k for k, v in self.flow_stats.items() 
                    if current_time - v['last_seen'] > timeout]
        
        for flow_key in old_flows:
            del self.flow_stats[flow_key]
        
        if old_flows:
            print(f"Cleaned up {len(old_flows)} old flows")
    
    def print_stats(self):
        """Print comprehensive statistics"""
        print("\n" + "="*60)
        print("ENHANCED PROCESSOR STATISTICS")
        print("="*60)
        print(f"Total packets processed: {self.stats['total_packets']}")
        print(f"TCP packets: {self.stats['tcp_packets']}")
        print(f"Packets delayed (original): {self.stats['packets_delayed']}")
        
        if self.mitigation_enabled:
            print(f"Covert packets detected: {self.stats['covert_detected']}")
            print(f"Packets normalized: {self.stats['packets_normalized']}")
            print(f"Active flows tracked: {len(self.flow_stats)}")
            
            if self.stats['tcp_packets'] > 0:
                detection_rate = self.stats['covert_detected'] / self.stats['tcp_packets']
                print(f"Detection rate: {detection_rate:.1%}")
            
            print(f"Mitigation mode: {self.mitigation_mode}")
            
            # Model status
            models_loaded = sum([
                self.detector_model is not None,
                self.label_encoder is not None, 
                self.scaler is not None
            ])
            print(f"ML models loaded: {models_loaded}/3")
        else:
            print("Mitigation: DISABLED")
        
        print("="*60)

async def run():
    # Create enhanced processor
    processor = Processor()
    
    # Connect to NATS
    await processor.nc.connect(processor.nats_url)
    print(f"Connected to NATS at {processor.nats_url}")
    
    # Subscribe to packet topics
    await processor.nc.subscribe("inpktsec", cb=processor.message_handler)
    await processor.nc.subscribe("inpktinsec", cb=processor.message_handler)
    
    print("Enhanced Processor Started!")
    print("Subscribed to inpktsec and inpktinsec topics")
    
    try:
        # Stats and cleanup loop
        last_stats_time = time.time()
        stats_interval = 30  # Print stats every 30 seconds
        
        while True:
            await asyncio.sleep(1)
            
            current_time = time.time()
            if current_time - last_stats_time >= stats_interval:
                processor.print_stats()
                processor.cleanup_flows()
                last_stats_time = current_time
                
    except KeyboardInterrupt:
        processor.print_stats()
        await processor.nc.close()
        print("Processor stopped")

if __name__ == '__main__':
    asyncio.run(run())