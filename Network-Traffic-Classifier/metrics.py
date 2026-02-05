"""
Network Traffic Classifier - Model Metrics Display
Run this script to view detailed metrics for the trained Random Forest model
Usage: python metrics.py
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

def load_model():
    """Load the trained Random Forest model and scaler"""
    print("="*80)
    print("LOADING MODEL")
    print("="*80)
    
    with open("./MLModel/RFCMODEL.pkl", "rb") as model_file:
        classifier = pickle.load(model_file)
    print("✓ Loaded Random Forest model")
    
    with open("./MLModel/scalerr.sc", "rb") as scaler_file:
        scaler = pickle.load(scaler_file)
    print("✓ Loaded StandardScaler")
    
    return classifier, scaler

def load_test_data():
    """Load NSL-KDD test data"""
    print("\n" + "="*80)
    print("LOADING TEST DATA")
    print("="*80)
    
    # Load NSL-KDD dataset (will use 20% as test set)
    train_file = "../data/NSL_KDD.csv"
    
    # NSL-KDD column names (41 features + attack_type + difficulty)
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
        df_full = pd.read_csv(train_file, names=column_names, header=None)
        print(f"✓ Loaded NSL-KDD dataset: {len(df_full)} samples")
        
        # Remove difficulty column
        if 'difficulty' in df_full.columns:
            df_full = df_full.drop('difficulty', axis=1)
        
        # Remove rare classes (< 2 samples) before splitting
        class_counts = df_full['attack_type'].value_counts()
        rare_classes = class_counts[class_counts < 2].index.tolist()
        
        if rare_classes:
            df_full = df_full[~df_full['attack_type'].isin(rare_classes)]
            print(f"✓ Removed {len(rare_classes)} rare classes with < 2 samples")
        
        # Create train/test split (use same split as training)
        _, df = train_test_split(df_full, test_size=0.2, random_state=42, stratify=df_full['attack_type'])
        
    except FileNotFoundError:
        print(f"⚠ Dataset file not found at {train_file}")
        print("Please ensure the NSL-KDD dataset is in the ../data/ directory")
        raise
    
    # Select ONLY numeric features (38 features) - same as training script
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
    available_features = [col for col in numeric_features if col in df.columns]
    X = df[available_features]
    y = df['attack_type']
    
    print(f"✓ Test set: {len(X)} samples")
    print(f"✓ Features: {len(available_features)}")
    print(f"✓ Unique attack types: {y.nunique()}")
    
    return X, y, available_features

def display_metrics(y_true, y_pred, feature_names, classifier):
    """Display comprehensive model metrics"""
    
    print("\n" + "="*80)
    print("MODEL PERFORMANCE METRICS")
    print("="*80)
    
    # Overall accuracy
    accuracy = accuracy_score(y_true, y_pred)
    print(f"\n✓ ACCURACY: {accuracy*100:.2f}%")
    
    # Precision, Recall, F1-Score (weighted average)
    precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    
    print("\n" + "-"*80)
    print("WEIGHTED AVERAGE METRICS:")
    print("-"*80)
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    
    # Classification Report
    print("\n" + "="*80)
    print("DETAILED CLASSIFICATION REPORT")
    print("="*80)
    print(classification_report(y_true, y_pred, zero_division=0))
    
    # Confusion Matrix
    print("\n" + "="*80)
    print("CONFUSION MATRIX")
    print("="*80)
    cm = confusion_matrix(y_true, y_pred)
    
    # Get unique classes
    classes = sorted(y_true.unique())
    
    # Display confusion matrix with class names
    print(f"\nMatrix shape: {cm.shape[0]}x{cm.shape[1]} (Top 10 classes shown)")
    print("-"*80)
    
    # Show top 10 most frequent classes
    class_counts = pd.Series(y_true).value_counts()
    top_classes = class_counts.head(10).index.tolist()
    
    # Filter confusion matrix for top classes
    class_indices = [classes.index(c) for c in top_classes if c in classes]
    cm_subset = cm[np.ix_(class_indices, class_indices)]
    
    # Print header
    print(f"{'':15s}", end="")
    for cls in top_classes[:10]:
        print(f"{cls[:10]:>10s}", end=" ")
    print()
    print("-"*80)
    
    # Print matrix
    for i, cls in enumerate(top_classes[:10]):
        print(f"{cls[:15]:15s}", end="")
        for j in range(len(top_classes[:10])):
            if i < len(cm_subset) and j < len(cm_subset[0]):
                print(f"{cm_subset[i][j]:>10d}", end=" ")
            else:
                print(f"{'0':>10s}", end=" ")
        print()
    
    # Feature Importances
    print("\n" + "="*80)
    print("FEATURE IMPORTANCES")
    print("="*80)
    
    if hasattr(classifier, 'feature_importances_'):
        importances = classifier.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\nTop 15 Most Important Features:")
        print("-"*80)
        for idx, row in feature_importance_df.head(15).iterrows():
            print(f"{row['feature']:35s}: {row['importance']:.6f}")
        
        print("\n" + "-"*80)
        print("Top 5 Features (Bar Chart):")
        print("-"*80)
        for idx, row in feature_importance_df.head(5).iterrows():
            bar_length = int(row['importance'] * 500)
            bar = "█" * bar_length
            print(f"{row['feature']:25s}: {bar} {row['importance']:.6f}")
    
    # Class distribution
    print("\n" + "="*80)
    print("PREDICTION DISTRIBUTION")
    print("="*80)
    
    pred_counts = pd.Series(y_pred).value_counts()
    print(f"\nTotal predictions: {len(y_pred)}")
    print("\nTop 15 Predicted Classes:")
    print("-"*80)
    for attack_type, count in pred_counts.head(15).items():
        percentage = (count / len(y_pred)) * 100
        print(f"{attack_type:20s}: {count:6d} ({percentage:5.2f}%)")
    
    # Model Information
    print("\n" + "="*80)
    print("MODEL CONFIGURATION")
    print("="*80)
    print(f"Model Type: Random Forest Classifier")
    print(f"Number of Estimators: {classifier.n_estimators}")
    print(f"Max Depth: {classifier.max_depth}")
    print(f"Criterion: {classifier.criterion}")
    print(f"Min Samples Split: {classifier.min_samples_split}")
    print(f"Min Samples Leaf: {classifier.min_samples_leaf}")
    print(f"Random State: {classifier.random_state}")

def main():
    """Main execution function"""
    print("\n")
    print("="*80)
    print(" "*20 + "NETWORK TRAFFIC CLASSIFIER")
    print(" "*25 + "MODEL METRICS REPORT")
    print("="*80)
    
    # Load model
    classifier, scaler = load_model()
    
    # Load test data
    X_test, y_test, feature_names = load_test_data()
    
    # Scale features
    print("\n" + "="*80)
    print("PREPROCESSING")
    print("="*80)
    X_test_scaled = scaler.transform(X_test)
    print("✓ Features scaled using StandardScaler")
    
    # Make predictions
    print("\n" + "="*80)
    print("MAKING PREDICTIONS")
    print("="*80)
    print("Predicting... please wait...")
    y_pred = classifier.predict(X_test_scaled)
    print(f"✓ Generated predictions for {len(y_pred)} samples")
    
    # Display all metrics
    display_metrics(y_test, y_pred, feature_names, classifier)
    
    print("\n" + "="*80)
    print("REPORT COMPLETE")
    print("="*80)
    print()

if __name__ == "__main__":
    main()
