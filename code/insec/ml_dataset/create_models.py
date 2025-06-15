#!/usr/bin/env python3
"""
create_test_models.py - Create working models for testing mitigation
Run this on your host machine to create compatible model files
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

def create_covert_channel_models():
    """Create models that can detect your specific covert channel"""
    
    print("Creating test models for covert channel detection...")
    
    # Create synthetic training data that matches your covert channel
    np.random.seed(42)
    
    # Features: [num_options, flags, dport, sport, window, MSS_present, WScale_present, 
    #           NOP_present, SAckOK_present, Timestamp_present, EOL_present,
    #           mss_value, wscale_value, timestamp_value, opt1_hash, opt2_hash, opt3_hash]
    n_samples = 1000
    n_features = 20
    
    # Generate benign traffic features
    benign_samples = n_samples // 2
    X_benign = np.random.rand(benign_samples, n_features)
    
    # Typical benign TCP options
    X_benign[:, 0] = np.random.randint(1, 4, benign_samples)  # 1-3 options
    X_benign[:, 1] = 2  # SYN flag
    X_benign[:, 2] = np.random.choice([80, 443, 22, 25], benign_samples)  # Common ports
    X_benign[:, 3] = np.random.randint(1024, 65535, benign_samples)  # Random source ports
    X_benign[:, 4] = np.random.randint(1000, 65535, benign_samples)  # Window size
    
    # Generate covert traffic features (your specific pattern)
    covert_samples = n_samples // 2
    X_covert = np.random.rand(covert_samples, n_features)
    
    # Your covert channel characteristics
    X_covert[:, 0] = 4  # Exactly 4 options for 4-bit encoding
    X_covert[:, 1] = 2  # SYN flag
    X_covert[:, 2] = 1234  # Your covert channel port!
    X_covert[:, 3] = np.random.randint(1024, 65535, covert_samples)  # Random source
    X_covert[:, 4] = np.random.randint(1000, 65535, covert_samples)  # Window
    
    # Your specific option pattern: MSS, WScale, NOP, SAckOK
    X_covert[:, 5] = 1  # MSS present
    X_covert[:, 6] = 1  # WScale present  
    X_covert[:, 7] = 1  # NOP present
    X_covert[:, 8] = 1  # SAckOK present
    X_covert[:, 9] = 0  # Timestamp not present (for 4-bit mode)
    X_covert[:, 10] = 0  # EOL not present
    
    # Your specific values
    X_covert[:, 11] = 1460  # MSS value
    X_covert[:, 12] = 10    # WScale value
    
    # Combine data
    X = np.vstack([X_benign, X_covert])
    y = ['benign'] * benign_samples + ['covert'] * covert_samples
    
    # Create and train models
    print("Training RandomForest classifier...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    rf_model = RandomForestClassifier(
        n_estimators=100, 
        random_state=42,
        max_depth=10
    )
    rf_model.fit(X_scaled, y_encoded)
    
    # Test the model
    print("Testing model accuracy...")
    accuracy = rf_model.score(X_scaled, y_encoded)
    print(f"Training accuracy: {accuracy:.2f}")
    
    # Show feature importance
    print("Top feature importances:")
    feature_names = [
        'num_options', 'flags', 'dport', 'sport', 'window',
        'MSS_present', 'WScale_present', 'NOP_present', 'SAckOK_present', 
        'Timestamp_present', 'EOL_present', 'mss_value', 'wscale_value',
        'timestamp_value', 'opt1_hash', 'opt2_hash', 'opt3_hash',
        'extra1', 'extra2', 'extra3'
    ]
    
    importances = rf_model.feature_importances_
    for i, importance in enumerate(importances[:10]):  # Top 10
        print(f"  {feature_names[i]}: {importance:.3f}")
    
    # Save models with compatible pickle protocol
    print("Saving models...")
    
    models = {
        'covert_detector_fixed.pkl': rf_model,
        'label_encoder_fixed.pkl': label_encoder,
        'scaler_fixed.pkl': scaler
    }
    
    for filename, model in models.items():
        with open(filename, 'wb') as f:
            pickle.dump(model, f, protocol=2)  # Use protocol 2 for compatibility
        print(f"Saved: {filename}")
    
    # Test loading
    print("Testing model loading...")
    for filename in models.keys():
        try:
            with open(filename, 'rb') as f:
                loaded_model = pickle.load(f)
            print(f"Successfully loaded: {filename}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    
    print("\nDone! Copy these files to your container:")
    print("cp *_fixed.pkl /path/to/your/middlebox/models/")
    
    return rf_model, label_encoder, scaler

if __name__ == "__main__":
    create_covert_channel_models()