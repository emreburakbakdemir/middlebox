#!/usr/bin/env python3
"""
Revised Covert Channel Detection Training
========================================

Updated to work with the TCP SYN feature extractor CSV output.
Focuses on detecting covert channels using TCP option permutations.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings("ignore")

def load_and_prepare_data(file_path='/home/emreburak/ders/3/SPRING/519netwsec/middlebox/code/insec/ml_dataset/tcp_syn_features.csv'):
    """Load and prepare the dataset for training."""
    
    # Load data
    df = pd.read_csv(file_path)
    print(f"Dataset loaded: {df.shape}")
    print(f"Class distribution:\n{df['label'].value_counts()}")
    
    # Remove non-feature columns
    feature_cols = [col for col in df.columns if col not in ['label', 'pcap_file']]
    X = df[feature_cols]
    y = df['label']
    
    # Handle any missing values
    X = X.fillna(0)
    
    # Convert categorical features to numeric if needed
    for col in X.columns:
        if X[col].dtype == 'object':
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
    
    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"Final feature count: {X.shape[1]}")
    print(f"Features: {list(X.columns)}")
    
    return X, y_encoded, label_encoder

def select_covert_features(X):
    """Select the most relevant features for covert channel detection based on our feature set."""
    
    # Priority features for covert channel detection from our feature extractor
    covert_priority_features = [
        # Option-based features (key for detecting TCP option permutations)
        'num_options',                    # Number of TCP options
        'has_MSS',                       # MSS option presence
        'has_WScale',                    # Window Scale option presence  
        'has_NOP',                       # NOP option presence
        'has_SAckOK',                    # Selective ACK option presence
        'has_Timestamp',                 # Timestamp option presence
        'has_4_options',                 # Exactly 4 options (4-bit encoding)
        'has_5_options',                 # Exactly 5 options (5-bit encoding)
        'option_sequence_hash',          # Hash of option sequence (key indicator)
        
        # Value-based features (detecting specific covert values)
        'mss_value',                     # MSS value (1460 is common in covert)
        'has_standard_mss',              # Standard MSS flag
        'wscale_value',                  # Window scale value (10 is used in covert)
        'has_zero_timestamp',            # Zero timestamp values
        
        # Flow-level features (detecting covert traffic patterns)
        'pattern_diversity',             # Diversity of option patterns
        'interval_regularity',           # Timing regularity
        'interval_coefficient_variation', # Timing variation coefficient
        'avg_interval',                  # Average packet interval
        'std_interval',                  # Standard deviation of intervals
        'min_interval',                  # Minimum interval
        'max_interval',                  # Maximum interval
        'total_syn_packets',             # Total SYN packets in flow
        
        # Port and size features
        'src_port',                      # Source port
        'dst_port',                      # Destination port (1234 for covert)
        'src_port_range',                # Source port range
        'dst_port_range',                # Destination port range
        'packet_size',                   # Packet size
        'window_size',                   # TCP window size
        'tcp_flags'                      # TCP flags
    ]
    
    # Get available features from the priority list
    available_features = [f for f in covert_priority_features if f in X.columns]
    
    # Add any remaining numeric features not in priority list
    remaining_features = [f for f in X.columns if f not in available_features]
    all_features = available_features + remaining_features
    
    print(f"Selected {len(all_features)} features for training")
    print(f"Priority covert detection features available: {len(available_features)}")
    print("Key features:", available_features[:10])
    
    return X[all_features]

def create_derived_features(X):
    """Create additional derived features using only existing features."""
    
    X_derived = X.copy()
    
    # Port 1234 targeting (main covert channel indicator)
    X_derived['targets_port_1234'] = (X_derived['dst_port'] == 1234).astype(int)
    
    # Covert option pattern detection using existing features
    # 4-bit pattern: exactly 4 options with the covert combination
    covert_4bit_pattern = (
        (X_derived['has_MSS'] == 1) & 
        (X_derived['has_WScale'] == 1) & 
        (X_derived['has_NOP'] == 1) & 
        (X_derived['has_SAckOK'] == 1) &
        (X_derived['has_4_options'] == 1)
    ).astype(int)
    
    # 5-bit pattern: exactly 5 options with the covert combination
    covert_5bit_pattern = (
        (X_derived['has_MSS'] == 1) & 
        (X_derived['has_WScale'] == 1) & 
        (X_derived['has_NOP'] == 1) & 
        (X_derived['has_SAckOK'] == 1) &
        (X_derived['has_Timestamp'] == 1) &
        (X_derived['has_5_options'] == 1)
    ).astype(int)
    
    X_derived['covert_4bit_pattern'] = covert_4bit_pattern
    X_derived['covert_5bit_pattern'] = covert_5bit_pattern
    X_derived['any_covert_pattern'] = (covert_4bit_pattern | covert_5bit_pattern).astype(int)
    
    # Use existing derived features
    # has_standard_mss already indicates MSS=1460
    # Check for window scale value 10
    X_derived['has_wscale_10'] = (X_derived['wscale_value'] == 10).astype(int)
    
    # Combined covert score using available features
    X_derived['covert_score'] = (
        X_derived['targets_port_1234'] * 3 +
        X_derived['any_covert_pattern'] * 2 +
        X_derived['has_standard_mss'] * 1 +
        X_derived['has_wscale_10'] * 1
    )
    
    # Port concentration (how focused the traffic is)
    X_derived['dst_port_is_1234'] = (X_derived['dst_port'] == 1234).astype(int)
    
    # Regular timing indicator using existing features
    if 'interval_coefficient_variation' in X_derived.columns:
        X_derived['is_regular_timing'] = (
            X_derived['interval_coefficient_variation'] < 0.1
        ).astype(int)
    
    print(f"Added derived features. New feature count: {X_derived.shape[1]}")
    
    return X_derived

def train_covert_detectors(X, y, test_size=0.2):
    """Train multiple models for covert channel detection."""
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Define models optimized for covert detection
    models = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        ),
        'XGBoost': xgb.XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            random_state=42,
            eval_metric='mlogloss',
            tree_method='hist',
            device='cpu'
        ),
        'LogisticRegression': LogisticRegression(
            random_state=42,
            class_weight='balanced',
            max_iter=1000
        ),
        'SVM': SVC(
            kernel='rbf',
            random_state=42,
            class_weight='balanced',
            probability=True
        )
    }
    
    results = {}
    
    # Train and evaluate models
    for name, model in models.items():
        print(f"\nTraining {name}...")
        
        try:
            # Use scaled data for all models except RandomForest
            if name == 'RandomForest':
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='f1_macro')
            else:
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='f1_macro')
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            f1_macro = f1_score(y_test, y_pred, average='macro')
            f1_weighted = f1_score(y_test, y_pred, average='weighted')
            cv_mean = cv_scores.mean()
            cv_std = cv_scores.std()
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'f1_macro': f1_macro,
                'f1_weighted': f1_weighted,
                'cv_mean': cv_mean,
                'cv_std': cv_std,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            print(f"{name} Results:")
            print(f"  Accuracy: {accuracy:.4f}")
            print(f"  F1 (Macro): {f1_macro:.4f}")
            print(f"  F1 (Weighted): {f1_weighted:.4f}")
            print(f"  CV F1: {cv_mean:.4f} (+/- {cv_std * 2:.4f})")
            
        except Exception as e:
            print(f"Error training {name}: {e}")
            print(f"Skipping {name} model...")
            continue
    
    return results, (X_train, X_test, y_train, y_test), scaler

def evaluate_and_visualize(results, data_splits, label_encoder):
    """Evaluate models and create comprehensive visualizations."""
    
    X_train, X_test, y_train, y_test = data_splits
    
    # Find best model based on F1 macro score
    if not results:
        print("No models trained successfully!")
        return None, None
        
    best_model_name = max(results.keys(), key=lambda k: results[k]['f1_macro'])
    best_model = results[best_model_name]
    
    print(f"\n{'='*60}")
    print(f"BEST MODEL: {best_model_name}")
    print(f"Accuracy: {best_model['accuracy']:.4f}")
    print(f"F1 Macro: {best_model['f1_macro']:.4f}")
    print(f"F1 Weighted: {best_model['f1_weighted']:.4f}")
    print(f"CV F1: {best_model['cv_mean']:.4f} (+/- {best_model['cv_std'] * 2:.4f})")
    print(f"{'='*60}")
    
    # Detailed evaluation of best model
    y_pred = best_model['predictions']
    
    print("\nDetailed Classification Report:")
    print(classification_report(
        y_test, y_pred, 
        target_names=label_encoder.classes_,
        digits=4
    ))
    
    # Create comprehensive visualizations
    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    
    # 1. Model comparison
    models = list(results.keys())
    metrics = ['accuracy', 'f1_macro', 'f1_weighted']
    
    x = np.arange(len(models))
    width = 0.25
    
    for i, metric in enumerate(metrics):
        values = [results[m][metric] for m in models]
        axes[0,0].bar(x + i*width, values, width, label=metric.replace('_', ' ').title(), alpha=0.8)
    
    axes[0,0].set_xlabel('Models')
    axes[0,0].set_ylabel('Score')
    axes[0,0].set_title('Model Performance Comparison')
    axes[0,0].set_xticks(x + width)
    axes[0,0].set_xticklabels(models, rotation=45)
    axes[0,0].legend()
    axes[0,0].grid(True, alpha=0.3)
    
    # 2. Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0,1],
                xticklabels=label_encoder.classes_,
                yticklabels=label_encoder.classes_)
    axes[0,1].set_title(f'Confusion Matrix - {best_model_name}')
    axes[0,1].set_ylabel('True Label')
    axes[0,1].set_xlabel('Predicted Label')
    
    # 3. Cross-validation scores
    cv_means = [results[m]['cv_mean'] for m in models]
    cv_stds = [results[m]['cv_std'] for m in models]
    
    axes[0,2].bar(models, cv_means, yerr=cv_stds, capsize=5, alpha=0.8)
    axes[0,2].set_ylabel('F1 Score')
    axes[0,2].set_title('Cross-Validation F1 Scores')
    axes[0,2].tick_params(axis='x', rotation=45)
    axes[0,2].grid(True, alpha=0.3)
    
    # 4. Feature importance (if Random Forest is best)
    if best_model_name == 'RandomForest':
        rf_model = best_model['model']
        feature_names = X_train.columns if hasattr(X_train, 'columns') else [f'Feature_{i}' for i in range(X_train.shape[1])]
        
        # Get top 15 features
        importance = rf_model.feature_importances_
        indices = np.argsort(importance)[::-1][:15]
        
        axes[1,0].barh(range(15), importance[indices][::-1])
        axes[1,0].set_yticks(range(15))
        axes[1,0].set_yticklabels([feature_names[i] for i in indices[::-1]], fontsize=8)
        axes[1,0].set_xlabel('Feature Importance')
        axes[1,0].set_title('Top 15 Feature Importances')
    else:
        axes[1,0].text(0.5, 0.5, f'Feature importance\nnot available for\n{best_model_name}', 
                       ha='center', va='center', transform=axes[1,0].transAxes)
        axes[1,0].set_title('Feature Importance')
    
    # 5. Class distribution comparison
    y_test_labels = label_encoder.inverse_transform(y_test)
    y_pred_labels = label_encoder.inverse_transform(y_pred)
    
    true_counts = pd.Series(y_test_labels).value_counts()
    pred_counts = pd.Series(y_pred_labels).value_counts()
    
    x_pos = np.arange(len(label_encoder.classes_))
    axes[1,1].bar(x_pos - 0.2, [true_counts.get(cls, 0) for cls in label_encoder.classes_], 
                  0.4, label='True', alpha=0.8)
    axes[1,1].bar(x_pos + 0.2, [pred_counts.get(cls, 0) for cls in label_encoder.classes_], 
                  0.4, label='Predicted', alpha=0.8)
    axes[1,1].set_xlabel('Class')
    axes[1,1].set_ylabel('Count')
    axes[1,1].set_title('True vs Predicted Class Distribution')
    axes[1,1].set_xticks(x_pos)
    axes[1,1].set_xticklabels(label_encoder.classes_)
    axes[1,1].legend()
    
    # 6. Performance per class
    per_class_f1 = f1_score(y_test, y_pred, average=None)
    axes[1,2].bar(label_encoder.classes_, per_class_f1, alpha=0.8)
    axes[1,2].set_ylabel('F1 Score')
    axes[1,2].set_title('Per-Class F1 Scores')
    axes[1,2].tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig('covert_detection_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    return best_model_name, best_model

def analyze_covert_patterns(X, y, label_encoder):
    """Analyze patterns specific to covert channels using only existing features."""
    
    # Convert y back to labels for analysis
    y_labels = label_encoder.inverse_transform(y)
    df_analysis = X.copy()
    df_analysis['label'] = y_labels
    
    print(f"\n{'='*60}")
    print("COVERT CHANNEL PATTERN ANALYSIS")
    print(f"{'='*60}")
    
    # Key covert indicators that we actually created
    covert_indicators = [
        'targets_port_1234',
        'any_covert_pattern', 
        'covert_4bit_pattern',
        'covert_5bit_pattern',
        'covert_score',
        'dst_port_is_1234',
        'has_wscale_10'
    ]
    
    # Analyze each indicator by class (only if it exists)
    for indicator in covert_indicators:
        if indicator in df_analysis.columns:
            print(f"\n{indicator}:")
            summary = df_analysis.groupby('label')[indicator].agg(['mean', 'std', 'count'])
            print(summary.round(4))
    
    # Port analysis using actual features
    print(f"\nDestination port analysis:")
    if 'dst_port' in df_analysis.columns:
        port_summary = df_analysis.groupby('label')['dst_port'].agg(['min', 'max', 'mean', 'std'])
        print(port_summary.round(2))
        
        # Count of port 1234 usage
        port_1234_count = df_analysis.groupby('label')['dst_port'].apply(lambda x: (x == 1234).sum())
        total_count = df_analysis.groupby('label').size()
        port_1234_pct = (port_1234_count / total_count * 100).round(2)
        print(f"\nPort 1234 usage percentage by class:")
        print(port_1234_pct)
    
    # Option pattern analysis using existing features
    option_features = ['has_MSS', 'has_WScale', 'has_NOP', 'has_SAckOK', 'has_Timestamp', 
                      'has_4_options', 'has_5_options', 'num_options']
    
    print(f"\nTCP Option pattern analysis:")
    for feature in option_features:
        if feature in df_analysis.columns:
            print(f"\n{feature}:")
            option_stats = df_analysis.groupby('label')[feature].agg(['mean', 'std'])
            print(option_stats.round(3))
    
    # Pattern diversity analysis
    if 'pattern_diversity' in df_analysis.columns:
        print(f"\nOption pattern diversity:")
        pattern_analysis = df_analysis.groupby('label')['pattern_diversity'].describe()
        print(pattern_analysis.round(2))
    
    # Timing analysis using existing features
    timing_features = ['avg_interval', 'std_interval', 'interval_regularity', 
                      'interval_coefficient_variation', 'min_interval', 'max_interval']
    
    available_timing = [f for f in timing_features if f in df_analysis.columns]
    
    if available_timing:
        print(f"\nTiming pattern analysis:")
        for feature in available_timing:
            print(f"\n{feature}:")
            timing_stats = df_analysis.groupby('label')[feature].describe()
            print(timing_stats.round(4))
    
    # Option sequence hash analysis
    if 'option_sequence_hash' in df_analysis.columns:
        print(f"\nOption sequence hash diversity:")
        hash_diversity = df_analysis.groupby('label')['option_sequence_hash'].nunique()
        print("Unique hash values per class:")
        print(hash_diversity)

def save_model_and_results(best_model_name, best_model, scaler, label_encoder, results):
    """Save the best model and related objects."""
    
    import joblib
    import json
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save model and preprocessing objects
    joblib.dump(best_model['model'], f'covert_detector_{best_model_name}_{timestamp}.pkl')
    joblib.dump(scaler, f'scaler_{timestamp}.pkl')
    joblib.dump(label_encoder, f'label_encoder_{timestamp}.pkl')
    
    # Save results summary
    results_summary = {}
    for model_name, result in results.items():
        results_summary[model_name] = {
            'accuracy': float(result['accuracy']),
            'f1_macro': float(result['f1_macro']),
            'f1_weighted': float(result['f1_weighted']),
            'cv_mean': float(result['cv_mean']),
            'cv_std': float(result['cv_std'])
        }
    
    with open(f'results_summary_{timestamp}.json', 'w') as f:
        json.dump(results_summary, f, indent=2)
    
    print(f"\nModels and results saved with timestamp: {timestamp}")
    print(f"Best model: {best_model_name}")
    
    return timestamp

def main():
    """Main training pipeline."""
    
    print("TCP SYN Covert Channel Detection Training Pipeline")
    print("=" * 60)
    
    # Step 1: Load and prepare data
    print("\n1. Loading and preparing data...")
    X, y, label_encoder = load_and_prepare_data('tcp_syn_features.csv')
    
    # Step 2: Feature selection and engineering
    print("\n2. Selecting covert-relevant features...")
    X_selected = select_covert_features(X)
    
    print("\n3. Creating derived features...")
    X_engineered = create_derived_features(X_selected)
    
    # Step 3: Train models
    print("\n4. Training covert detection models...")
    results, data_splits, scaler = train_covert_detectors(X_engineered, y)
    
    # Step 4: Evaluate and visualize
    print("\n5. Evaluating models...")
    best_model_name, best_model = evaluate_and_visualize(results, data_splits, label_encoder)
    
    # Step 5: Analyze covert patterns
    print("\n6. Analyzing covert channel patterns...")
    analyze_covert_patterns(X_engineered, y, label_encoder)
    
    # Step 6: Save results
    print("\n7. Saving models and results...")
    timestamp = save_model_and_results(best_model_name, best_model, scaler, label_encoder, results)
    
    print(f"\n{'='*60}")
    print("TRAINING COMPLETED SUCCESSFULLY!")
    print(f"Best Model: {best_model_name}")
    print(f"Best F1-Score: {results[best_model_name]['f1_macro']:.4f}")
    print(f"Files saved with timestamp: {timestamp}")
    print(f"{'='*60}")
    
    return results, best_model, scaler, label_encoder

if __name__ == "__main__":
    results, best_model, scaler, label_encoder = main()