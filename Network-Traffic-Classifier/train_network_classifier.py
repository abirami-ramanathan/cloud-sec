"""
Network Traffic Classification Model Training
Implements Algorithm 1 from the research paper

Trains Random Forest classifier on NSL-KDD, CIC-IDS-2017, and UNSW-NB15 datasets
Generates RFCMODEL.pkl and scalerr.sc for deployment
"""

import pandas as pd
import numpy as np
import pickle
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# Algorithm 1: Network Traffic Classification Using Random Forest
# ============================================================================

def load_nsl_kdd(file_path):
    """
    Load NSL-KDD dataset
    Features: 41 features with attack type labels
    Attack categories: DoS, R2L, U2R, Probe, Normal
    """
    print("\n[1/3] Loading NSL-KDD dataset...")
    
    # NSL-KDD column names (41 features + 1 attack type + 1 difficulty)
    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 
        'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
        'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
    ]
    
    try:
        df = pd.read_csv(file_path, names=column_names, header=None)
        
        # Remove difficulty level column
        if 'difficulty' in df.columns:
            df = df.drop('difficulty', axis=1)
        
        print(f"   Loaded {len(df)} samples")
        print(f"   Attack distribution:")
        print(df['attack_type'].value_counts().head(10))
        
        return df
    except Exception as e:
        print(f"   ✗ Error loading NSL-KDD: {e}")
        return None


def load_cic_ids_2017(file_path):
    """
    Load CIC-IDS-2017 dataset
    Features: 80 flow-based and content-based characteristics
    Attack types: Brute Force, DDoS, Infiltration, etc.
    """
    print("\n[2/3] Loading CIC-IDS-2017 dataset...")
    
    try:
        df = pd.read_csv(file_path)
        
        # Rename label column to 'attack_type' for consistency
        label_columns = ['Label', 'label', ' Label', 'Attack']
        for col in label_columns:
            if col in df.columns:
                df = df.rename(columns={col: 'attack_type'})
                break
        
        print(f"   Loaded {len(df)} samples")
        if 'attack_type' in df.columns:
            print(f"   Attack distribution:")
            print(df['attack_type'].value_counts().head(10))
        
        return df
    except Exception as e:
        print(f"   ✗ Error loading CIC-IDS-2017: {e}")
        return None


def load_unsw_nb15(file_path):
    """
    Load UNSW-NB15 dataset
    Features: 49 features from hybrid testbed environment
    Attack types: Fuzzing, Backdoors, Shellcode, etc.
    """
    print("\n[3/3] Loading UNSW-NB15 dataset...")
    
    try:
        df = pd.read_csv(file_path)
        
        # Rename label column to 'attack_type' for consistency
        label_columns = ['attack_cat', 'Label', 'label', 'Attack']
        for col in label_columns:
            if col in df.columns:
                df = df.rename(columns={col: 'attack_type'})
                break
        
        print(f"   Loaded {len(df)} samples")
        if 'attack_type' in df.columns:
            print(f"   Attack distribution:")
            print(df['attack_type'].value_counts().head(10))
        
        return df
    except Exception as e:
        print(f"   Error loading UNSW-NB15: {e}")
        return None


def preprocess_data(df):
    """
    Step 2-4 of Algorithm 1: Pre-process data
    - Drop irrelevant features (flags, protocols, services - non-numeric)
    - Separate features (X) and labels (y)
    - Handle missing values and encode categorical variables
    """
    print("\n" + "="*70)
    print("PREPROCESSING DATA")
    print("="*70)
    
    # Save attack_type labels
    if 'attack_type' not in df.columns:
        print("   Error: 'attack_type' column not found!")
        return None, None
    
    y = df['attack_type'].copy()
    
    # Drop label column from features
    X = df.drop('attack_type', axis=1)
    
    print(f"\n1. Initial shape: {X.shape}")
    
    # Drop non-numeric columns (protocol_type, service, flag, etc.)
    # Keep only numeric features that match our extraction pipeline
    numeric_features = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 
        'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
        'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate'
    ]
    
    # Keep only features that exist in the dataset
    available_features = [col for col in numeric_features if col in X.columns]
    X = X[available_features]
    
    print(f"2. After selecting numeric features: {X.shape}")
    print(f"   Features: {list(X.columns)}")
    
    # Handle missing values
    X = X.fillna(0)
    
    # Handle infinite values
    X = X.replace([np.inf, -np.inf], 0)
    
    print(f"3. After handling missing/infinite values: {X.shape}")
    print(f"4. Label distribution:")
    print(y.value_counts())
    
    # Remove classes with very few samples (less than 2) to enable stratified splitting
    value_counts = y.value_counts()
    rare_classes = value_counts[value_counts < 2].index.tolist()
    
    if len(rare_classes) > 0:
        print(f"\n5. Removing {len(rare_classes)} rare classes with <2 samples: {rare_classes}")
        mask = ~y.isin(rare_classes)
        X = X[mask]
        y = y[mask]
        print(f"   After removal: {X.shape[0]} samples remaining")
    
    return X, y


def train_random_forest(X_train, y_train, X_test, y_test, feature_names):
    """
    Step 7-10 of Algorithm 1: Build Random Forest model
    - Define RandomForestClassifier with 100 estimators
    - Set random state for reproducibility (42)
    - Train model on training data
    - Evaluate on test data
    """
    print("\n" + "="*70)
    print("TRAINING RANDOM FOREST CLASSIFIER")
    print("="*70)
    
    # Step 7-8: Define Random Forest classifier
    print("\n1. Initializing Random Forest...")
    print("   - Number of estimators: 100")
    print("   - Random state: 42")
    print("   - Criterion: gini")
    print("   - Max depth: None (fully grown trees)")
    
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        criterion='gini',
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,
        verbose=0
    )
    
    # Step 9: Train model
    print("\n2. Training model...")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Features: {X_train.shape[1]}")
    
    rf_classifier.fit(X_train, y_train)
    
    print("   ✓ Training complete!")
    
    # Step 10: Evaluate model
    print("\n3. Evaluating model...")
    
    # Training accuracy
    train_predictions = rf_classifier.predict(X_train)
    train_accuracy = accuracy_score(y_train, train_predictions)
    print(f"   Training Accuracy: {train_accuracy*100:.2f}%")
    
    
    # Test accuracy
    test_predictions = rf_classifier.predict(X_test)
    test_accuracy = accuracy_score(y_test, test_predictions)
    print(f"   Test Accuracy: {test_accuracy*100:.2f}%")
    test_precision = precision_score(y_test, test_predictions, average='weighted', zero_division=0)
    test_recall = recall_score(y_test, test_predictions, average='weighted', zero_division=0)
    test_f1 = f1_score(y_test, test_predictions, average='weighted', zero_division=0)
    print(f"   Test Precision: {test_precision*100:.2f}%")  
    print(f"   Test Recall: {test_recall*100:.2f}%")
    print(f"   Test F1-Score: {test_f1*100:.2f}%")

    # Classification report
    print("\n4. Classification Report:")
    print(classification_report(y_test, test_predictions))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_classifier.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n5.Features:")
    print(feature_importance)
    
    return rf_classifier


def measure_latency(classifier, X_test, y_test):
    """
    Measure prediction latency and throughput
    """
    print("\n6. Latency Measurement:")
    
    # Batch latency
    start = time.perf_counter()
    _ = classifier.predict(X_test)
    end = time.perf_counter()
    
    total_time = end - start
    avg_latency = total_time / len(X_test)
    throughput = len(X_test) / total_time
    
    print(f"   Total Prediction Time : {total_time:.6f} sec")
    print(f"   Average Latency       : {avg_latency*1000:.6f} ms")
    print(f"   Throughput            : {throughput:.2f} samples/sec")
    
    # Per-sample latency
    latencies = []
    for i in range(min(1000, len(X_test))):  # Limit to 1000 samples for per-sample measurement
        sample = X_test[i].reshape(1, -1)
        
        s = time.perf_counter()
        _ = classifier.predict(sample)
        e = time.perf_counter()
        
        latencies.append(e - s)
    
    latencies = np.array(latencies)
    
    print(f"   95th Percentile       : {np.percentile(latencies,95)*1000:.6f} ms")
    print(f"   Max Latency           : {np.max(latencies)*1000:.6f} ms")
    
    return latencies


def calculate_severity_score(classifier, y_test, test_predictions):
    """
    Calculate data-driven severity score for multi-class classification
    """
    print("\n7. Data-Driven Severity Score:")
    
    # Get unique classes that actually appear in y_test
    unique_classes_in_test = np.unique(y_test)
    
    # Create confusion matrix only for classes in test set
    cm = confusion_matrix(y_test, test_predictions, labels=unique_classes_in_test)
    classes = unique_classes_in_test
    
    # Get class counts
    class_counts = pd.Series(y_test).value_counts()
    
    severity_score = 0
    
    for idx, cls in enumerate(classes):
        TP = cm[idx, idx]
        FN = cm[idx, :].sum() - TP
        FP = cm[:, idx].sum() - TP
        
        # Inverse frequency weight (rarer attacks = more severe)
        weight = 1 / class_counts[cls] if class_counts[cls] > 0 else 0
        
        class_severity = weight * (TP - 2*FN - FP)
        
        severity_score += class_severity
        
        # Get original class name if it was encoded
        if hasattr(classifier, 'classes_') and len(classifier.classes_) > 0:
            if isinstance(classifier.classes_[0], (int, np.integer)):
                # If classes are integers, use them directly
                class_name = f"Class_{cls}"
            else:
                # Try to get original class name
                try:
                    class_name = classifier.classes_[cls]
                except:
                    class_name = f"Class_{cls}"
        else:
            class_name = f"Class_{cls}"
        
        print(f"   {class_name}: weight={weight:.6f}, "
              f"TP={TP}, FN={FN}, FP={FP}, "
              f"class_severity={class_severity:.6f}")
    
    print(f"\n   Final Severity Score: {severity_score:.6f}")
    
    return severity_score


def main():
    """
    Main training pipeline implementing Algorithm 1
    """
    print("="*70)
    print("NETWORK TRAFFIC CLASSIFICATION MODEL TRAINING")
    print("Algorithm 1: Random Forest Classifier")
    print("="*70)
    
    # ========================================================================
    # STEP 1: Load datasets
    # ========================================================================
    print("\n" + "="*70)
    print("LOADING DATASETS")
    print("="*70)
    
    # Load all three datasets
    nsl_kdd_df = load_nsl_kdd('../data/NSL_KDD.csv')
    cic_ids_df = load_cic_ids_2017('../data/CIC_IDS_2017.csv')
    unsw_nb15_df = load_unsw_nb15('../data/UNSW_NB15.csv')
    
    # Use the dataset that loaded successfully
    # Priority: NSL-KDD (most compatible with our feature extraction)
    df = None
    dataset_name = ""
    original_labels = None  # Store original labels for reference
    
    if nsl_kdd_df is not None:
        df = nsl_kdd_df
        dataset_name = "NSL-KDD"
        print(f"\n✓ Using NSL-KDD dataset for training")
    elif cic_ids_df is not None:
        df = cic_ids_df
        dataset_name = "CIC-IDS-2017"
        print(f"\n✓ Using CIC-IDS-2017 dataset for training")
    elif unsw_nb15_df is not None:
        df = unsw_nb15_df
        dataset_name = "UNSW-NB15"
        print(f"\n✓ Using UNSW-NB15 dataset for training")
    else:
        print("\n✗ Error: No dataset could be loaded!")
        return
    
    # ========================================================================
    # STEP 2-4: Preprocess data
    # ========================================================================
    X, y = preprocess_data(df)
    
    if X is None or y is None:
        print("\n✗ Error: Preprocessing failed!")
        return
    
    # Store original labels for reference
    original_labels = y.copy()
    
    # Encode labels if they are strings
    if y.dtype == 'object':
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        print(f"\nEncoded labels: {len(label_encoder.classes_)} classes")
        print(f"Sample label mapping:")
        for i in range(min(5, len(label_encoder.classes_))):
            print(f"   {i} -> {label_encoder.classes_[i]}")
    else:
        y_encoded = y
        label_encoder = None
    
    # ========================================================================
    # STEP 5: Split data into training and testing sets
    # ========================================================================
    print("\n" + "="*70)
    print("SPLITTING DATA")
    print("="*70)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, 
        test_size=0.2, 
        random_state=42,
        stratify=y_encoded
    )
    
    # Also split original labels for reference
    _, y_test_original = train_test_split(
        original_labels, 
        test_size=0.2, 
        random_state=42,
        stratify=y_encoded
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    print(f"Features: {X_train.shape[1]}")
    print(f"Unique classes in test set: {len(np.unique(y_test))}")
    
    # ========================================================================
    # STEP 6: Standardize features using StandardScaler
    # ========================================================================
    print("\n" + "="*70)
    print("STANDARDIZING FEATURES")
    print("="*70)
    
    # Save feature names before scaling
    feature_names = X_train.columns.tolist()
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"\n✓ Features standardized (mean=0, std=1)")
    print(f"   Training data shape: {X_train_scaled.shape}")
    print(f"   Test data shape: {X_test_scaled.shape}")
    
    # ========================================================================
    # STEP 7-10: Train Random Forest model
    # ========================================================================
    rf_classifier = train_random_forest(
        X_train_scaled, y_train, 
        X_test_scaled, y_test,
        feature_names
    )
    
    # ========================================================================
    # STEP 11: Save trained model and scaler
    # ========================================================================
    print("\n" + "="*70)
    print("SAVING MODEL")
    print("="*70)
    
    # Create MLModel directory if it doesn't exist
    import os
    os.makedirs('./MLModel', exist_ok=True)
    
    # Save Random Forest model
    model_path = './MLModel/RFCMODEL.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(rf_classifier, f)
    print(f"\n✓ Model saved: {model_path}")
    
    # Save StandardScaler
    scaler_path = './MLModel/scalerr.sc'
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"✓ Scaler saved: {scaler_path}")
    
    # Save label encoder if used
    if label_encoder is not None:
        encoder_path = './MLModel/label_encoder.pkl'
        with open(encoder_path, 'wb') as f:
            pickle.dump(label_encoder, f)
        print(f"✓ Label encoder saved: {encoder_path}")
        
        # Save class mapping for reference
        class_mapping = pd.DataFrame({
            'encoded_value': range(len(label_encoder.classes_)),
            'original_label': label_encoder.classes_
        })
        mapping_path = './MLModel/class_mapping.csv'
        class_mapping.to_csv(mapping_path, index=False)
        print(f"✓ Class mapping saved: {mapping_path}")
    
    # ========================================================================
    # Additional metrics
    # ========================================================================
    # Get predictions for metrics
    test_predictions = rf_classifier.predict(X_test_scaled)
    
    # Measure latency
    measure_latency(rf_classifier, X_test_scaled, y_test)
    
    # Calculate severity score (using encoded labels)
    calculate_severity_score(rf_classifier, pd.Series(y_test), test_predictions)
    
    # Print sample predictions with original labels for verification
    print("\n8. Sample Predictions (first 10 test samples):")
    print("-" * 60)
    print(f"{'Index':<6} {'True Label':<20} {'Predicted':<20} {'Correct':<8}")
    print("-" * 60)
    
    for i in range(min(10, len(y_test))):
        true_label = y_test_original.iloc[i] if hasattr(y_test_original, 'iloc') else y_test_original[i]
        pred_label = label_encoder.inverse_transform([test_predictions[i]])[0] if label_encoder else test_predictions[i]
        correct = "✓" if (y_test[i] == test_predictions[i]) else "✗"
        
        print(f"{i:<6} {str(true_label):<20} {str(pred_label):<20} {correct:<8}")
    
    # ========================================================================
    # Summary
    # ========================================================================
    print("\n" + "="*70)
    print("TRAINING COMPLETE!")
    print("="*70)
    print(f"\nDataset: {dataset_name}")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(f"Number of features: {X_train.shape[1]}")
    print(f"Number of attack types: {len(np.unique(y_encoded))}")
    print(f"\nModel: {model_path}")
    print(f"Scaler: {scaler_path}")
    if label_encoder:
        print(f"Label encoder: {encoder_path}")
        print(f"Class mapping: {mapping_path}")
    print("\n✓ Ready for deployment in Docker containers!")
    print("="*70)


if __name__ == "__main__":
    main()