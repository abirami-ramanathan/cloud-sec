"""
Network Traffic Classification Model Training
Implements Algorithm 1 from the research paper

Trains Random Forest classifier on NSL-KDD, CIC-IDS-2017, and UNSW-NB15 datasets
Generates RFCMODEL.pkl and scalerr.sc for deployment
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
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
        
        print(f"   ✓ Loaded {len(df)} samples")
        print(f"   ✓ Attack distribution:")
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
        
        print(f"   ✓ Loaded {len(df)} samples")
        if 'attack_type' in df.columns:
            print(f"   ✓ Attack distribution:")
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
        
        print(f"   ✓ Loaded {len(df)} samples")
        if 'attack_type' in df.columns:
            print(f"   ✓ Attack distribution:")
            print(df['attack_type'].value_counts().head(10))
        
        return df
    except Exception as e:
        print(f"   ✗ Error loading UNSW-NB15: {e}")
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
        print("   ✗ Error: 'attack_type' column not found!")
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
    
    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        criterion='gini',
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        n_jobs=-1,
        verbose=1
    )
    
    # Step 9: Train model
    print("\n2. Training model...")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Features: {X_train.shape[1]}")
    
    classifier.fit(X_train, y_train)
    
    print("   ✓ Training complete!")
    
    # Step 10: Evaluate model
    print("\n3. Evaluating model...")
    
    # Training accuracy
    train_predictions = classifier.predict(X_train)
    train_accuracy = accuracy_score(y_train, train_predictions)
    print(f"   Training Accuracy: {train_accuracy*100:.2f}%")
    
    # Test accuracy
    test_predictions = classifier.predict(X_test)
    test_accuracy = accuracy_score(y_test, test_predictions)
    print(f"   Test Accuracy: {test_accuracy*100:.2f}%")
    
    # Classification report
    print("\n4. Classification Report:")
    print(classification_report(y_test, test_predictions))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': classifier.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n5. Top 10 Most Important Features:")
    print(feature_importance.head(10))
    
    return classifier


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
    
    # Optional: Combine all datasets (if you want multi-dataset training)
    # Uncomment these lines to combine all datasets
    """
    datasets = []
    if nsl_kdd_df is not None:
        datasets.append(nsl_kdd_df)
    if cic_ids_df is not None:
        datasets.append(cic_ids_df)
    if unsw_nb15_df is not None:
        datasets.append(unsw_nb15_df)
    
    if len(datasets) > 1:
        print(f"\n✓ Combining {len(datasets)} datasets for training")
        df = pd.concat(datasets, ignore_index=True)
        dataset_name = "Combined (NSL-KDD + CIC-IDS-2017 + UNSW-NB15)"
    """
    
    # ========================================================================
    # STEP 2-4: Preprocess data
    # ========================================================================
    X, y = preprocess_data(df)
    
    if X is None or y is None:
        print("\n✗ Error: Preprocessing failed!")
        return
    
    # ========================================================================
    # STEP 5: Split data into training and testing sets
    # ========================================================================
    print("\n" + "="*70)
    print("SPLITTING DATA")
    print("="*70)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=0.2, 
        random_state=42,
        stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    print(f"Features: {X_train.shape[1]}")
    
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
    classifier = train_random_forest(
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
    
    # Save Random Forest model
    model_path = './MLModel/RFCMODEL.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(classifier, f)
    print(f"\n✓ Model saved: {model_path}")
    
    # Save StandardScaler
    scaler_path = './MLModel/scalerr.sc'
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"✓ Scaler saved: {scaler_path}")
    
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
    print(f"Number of attack types: {len(y.unique())}")
    print(f"\nModel: {model_path}")
    print(f"Scaler: {scaler_path}")
    print("\n✓ Ready for deployment in Docker containers!")
    print("="*70)


if __name__ == "__main__":
    main()
