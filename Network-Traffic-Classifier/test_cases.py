"""
Network Traffic Classification - Test Cases
Loads trained RFCMODEL.pkl and scalerr.sc to classify network traffic

Usage:
    python test_cases.py                          # Run all test cases
    python test_cases.py --interactive             # Interactive mode
    python test_cases.py --file input_features.csv # Batch mode from CSV
"""

import pickle
import numpy as np
import pandas as pd
import argparse
import sys
import os
from pathlib import Path

class NetworkTrafficClassifier:
    """Network Traffic Classifier using trained Random Forest model"""
    
    def __init__(self, model_dir='./MLModel'):
        """
        Initialize classifier with trained model and scaler
        
        Args:
            model_dir: Directory containing RFCMODEL.pkl, scalerr.sc, and label_encoder.pkl
        """
        self.model_dir = Path(model_dir)
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.class_mapping = None
        self.feature_names = None
        
        # Load all components
        self._load_components()
        
    def _load_components(self):
        """Load model, scaler, and label encoder"""
        try:
            # Load Random Forest model
            model_path = self.model_dir / 'RFCMODEL.pkl'
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"✓ Model loaded: {model_path}")
            
            # Load scaler
            scaler_path = self.model_dir / 'scalerr.sc'
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print(f"✓ Scaler loaded: {scaler_path}")
            
            # Load label encoder if exists
            encoder_path = self.model_dir / 'label_encoder.pkl'
            if encoder_path.exists():
                with open(encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                print(f"✓ Label encoder loaded: {encoder_path}")
            
            # Load class mapping if exists
            mapping_path = self.model_dir / 'class_mapping.csv'
            if mapping_path.exists():
                self.class_mapping = pd.read_csv(mapping_path)
                print(f"✓ Class mapping loaded: {mapping_path}")
            
            # Get feature names from model if available
            if hasattr(self.model, 'feature_names_in_'):
                self.feature_names = self.model.feature_names_in_
                print(f"✓ Using feature names from model")
            else:
                # Default feature names from NSL-KDD
                self.feature_names = [
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
                print(f"✓ Using default feature names")
            
            print(f"✓ Model ready with {len(self.feature_names)} features")
            
        except FileNotFoundError as e:
            print(f"✗ Error loading components: {e}")
            print("  Make sure you've trained the model first using training code")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            sys.exit(1)
    
    def _create_feature_dataframe(self, features_dict):
        """
        Create a DataFrame with features in the correct order
        
        Args:
            features_dict: Dictionary of feature values
            
        Returns:
            DataFrame with features in correct order
        """
        # Create a dictionary with all features (fill missing with 0)
        complete_features = {}
        
        for feature_name in self.feature_names:
            if feature_name in features_dict:
                complete_features[feature_name] = float(features_dict[feature_name])
            else:
                complete_features[feature_name] = 0.0
                print(f"  ⚠ Warning: '{feature_name}' not provided, using 0")
        
        # Create DataFrame with single row
        df = pd.DataFrame([complete_features])
        
        # Ensure columns are in the correct order
        df = df[self.feature_names]
        
        return df
    
    def predict(self, features_dict):
        """
        Predict attack type for single sample
        
        Args:
            features_dict: Dictionary with feature names and values
            
        Returns:
            dict: Prediction results
        """
        # Create DataFrame with features
        feature_df = self._create_feature_dataframe(features_dict)
        
        # Scale features (using DataFrame to preserve feature names)
        feature_scaled = self.scaler.transform(feature_df)
        
        # Get prediction and probabilities
        prediction_encoded = self.model.predict(feature_scaled)[0]
        probabilities = self.model.predict_proba(feature_scaled)[0]
        
        # Decode prediction
        if self.label_encoder:
            prediction = self.label_encoder.inverse_transform([prediction_encoded])[0]
        else:
            prediction = prediction_encoded
        
        # Get class probabilities
        class_probs = []
        for i, prob in enumerate(probabilities):
            if self.label_encoder:
                class_name = self.label_encoder.inverse_transform([i])[0]
            else:
                class_name = f"Class_{i}"
            class_probs.append({
                'class': class_name,
                'probability': prob
            })
        
        # Sort by probability
        class_probs.sort(key=lambda x: x['probability'], reverse=True)
        
        return {
            'prediction': prediction,
            'confidence': float(probabilities[prediction_encoded]),
            'top_3_predictions': class_probs[:3],
            'all_probabilities': class_probs
        }
    
    def predict_batch(self, df):
        """
        Predict attack types for multiple samples
        
        Args:
            df: DataFrame with feature columns
            
        Returns:
            DataFrame with predictions
        """
        # Ensure all required features exist
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
                print(f"  ⚠ Warning: '{feature}' not in input, filled with 0")
        
        # Select and order features
        X = df[self.feature_names]
        
        # Scale features (preserves feature names)
        X_scaled = self.scaler.transform(X)
        
        # Get predictions
        predictions_encoded = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # Decode predictions
        if self.label_encoder:
            predictions = self.label_encoder.inverse_transform(predictions_encoded)
        else:
            predictions = predictions_encoded
        
        # Add predictions to dataframe
        result_df = df.copy()
        result_df['predicted_attack'] = predictions
        result_df['confidence'] = [probabilities[i][pred] for i, pred in enumerate(predictions_encoded)]
        
        return result_df


# ============================================================================
# Test Cases (same as before)
# ============================================================================

def get_normal_traffic_samples():
    """Generate normal/benign traffic test cases"""
    return [
        {
            'name': 'Normal Web Browsing',
            'features': {
                'duration': 0,
                'src_bytes': 200,
                'dst_bytes': 1500,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 1,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        },
        {
            'name': 'Normal SSH Session',
            'features': {
                'duration': 120,
                'src_bytes': 500,
                'dst_bytes': 300,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 1,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        }
    ]


def get_dos_attack_samples():
    """Generate DoS (Denial of Service) attack test cases"""
    return [
        {
            'name': 'SYN Flood Attack',
            'features': {
                'duration': 0,
                'src_bytes': 0,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 100,
                'srv_count': 100,
                'serror_rate': 1.0,
                'srv_serror_rate': 1.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 0.5,
                'diff_srv_rate': 0.5,
                'srv_diff_host_rate': 0.5,
                'dst_host_count': 255,
                'dst_host_srv_count': 255,
                'dst_host_same_srv_rate': 0.5,
                'dst_host_diff_srv_rate': 0.5,
                'dst_host_same_src_port_rate': 0.5,
                'dst_host_srv_diff_host_rate': 0.5,
                'dst_host_serror_rate': 1.0,
                'dst_host_srv_serror_rate': 1.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        },
        {
            'name': 'Ping of Death',
            'features': {
                'duration': 0,
                'src_bytes': 65535,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 1,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        }
    ]


def get_probe_attack_samples():
    """Generate Probe/Surveillance attack test cases"""
    return [
        {
            'name': 'Port Scan',
            'features': {
                'duration': 0,
                'src_bytes': 50,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 100,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 0.01,
                'diff_srv_rate': 0.99,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 255,
                'dst_host_srv_count': 10,
                'dst_host_same_srv_rate': 0.04,
                'dst_host_diff_srv_rate': 0.96,
                'dst_host_same_src_port_rate': 0.01,
                'dst_host_srv_diff_host_rate': 0.1,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        },
        {
            'name': 'Network Sweep',
            'features': {
                'duration': 0,
                'src_bytes': 50,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 100,
                'srv_count': 100,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 255,
                'dst_host_srv_count': 255,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.5,
                'dst_host_srv_diff_host_rate': 0.5,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        }
    ]


def get_r2l_attack_samples():
    """Generate R2L (Remote to Local) attack test cases"""
    return [
        {
            'name': 'Password Guessing',
            'features': {
                'duration': 0,
                'src_bytes': 100,
                'dst_bytes': 500,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 5,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 1,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        }
    ]


def get_u2r_attack_samples():
    """Generate U2R (User to Root) attack test cases"""
    return [
        {
            'name': 'Buffer Overflow',
            'features': {
                'duration': 0,
                'src_bytes': 1000,
                'dst_bytes': 0,
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 1,
                'num_failed_logins': 0,
                'logged_in': 1,
                'num_compromised': 1,
                'root_shell': 1,
                'su_attempted': 1,
                'num_root': 1,
                'num_file_creations': 1,
                'num_shells': 1,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        }
    ]


def run_all_test_cases(classifier):
    """Run all predefined test cases"""
    print("\n" + "="*80)
    print("RUNNING ALL TEST CASES")
    print("="*80)
    
    # Collect all test cases
    all_tests = []
    all_tests.extend(get_normal_traffic_samples())
    all_tests.extend(get_dos_attack_samples())
    all_tests.extend(get_probe_attack_samples())
    all_tests.extend(get_r2l_attack_samples())
    all_tests.extend(get_u2r_attack_samples())
    
    # Run each test
    results = []
    for test_case in all_tests:
        print(f"\n▶ Test: {test_case['name']}")
        print("-" * 60)
        
        try:
            result = classifier.predict(test_case['features'])
            
            print(f"  Predicted Attack Type: {result['prediction']}")
            print(f"  Confidence: {result['confidence']:.2%}")
            print("\n  Top 3 Predictions:")
            for i, pred in enumerate(result['top_3_predictions'], 1):
                print(f"    {i}. {pred['class']}: {pred['probability']:.2%}")
            
            results.append({
                'test_name': test_case['name'],
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'top_1': result['top_3_predictions'][0]['class'],
                'top_1_prob': result['top_3_predictions'][0]['probability']
            })
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    summary_df = pd.DataFrame(results)
    print(summary_df.to_string(index=False))
    
    return results


def interactive_mode(classifier):
    """Interactive mode for custom feature input"""
    print("\n" + "="*80)
    print("INTERACTIVE MODE - Enter custom features")
    print("="*80)
    print("(Press Enter with no input to use default value 0)")
    
    while True:
        print("\n" + "-"*60)
        features = {}
        
        # Ask for each feature
        for feature in classifier.feature_names:
            user_input = input(f"{feature} [0]: ").strip()
            if user_input:
                try:
                    features[feature] = float(user_input)
                except ValueError:
                    print(f"  Invalid input, using 0")
                    features[feature] = 0
            else:
                features[feature] = 0
        
        # Make prediction
        print("\nClassifying...")
        result = classifier.predict(features)
        
        print("\n" + "="*40)
        print(f"PREDICTION: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print("="*40)
        
        print("\nTop 3 predictions:")
        for i, pred in enumerate(result['top_3_predictions'], 1):
            print(f"  {i}. {pred['class']}: {pred['probability']:.2%}")
        
        # Ask to continue
        again = input("\nTest another sample? (y/n): ").strip().lower()
        if again != 'y':
            break


def batch_mode(classifier, input_file):
    """Batch mode from CSV file"""
    print(f"\nLoading features from {input_file}...")
    
    try:
        df = pd.read_csv(input_file)
        print(f"Loaded {len(df)} samples")
        
        results = classifier.predict_batch(df)
        
        # Save results
        output_file = input_file.replace('.csv', '_predictions.csv')
        results.to_csv(output_file, index=False)
        
        print(f"\nPredictions saved to {output_file}")
        print("\npredictions:")
        print(results[['predicted_attack', 'confidence']].head().to_string())
        
    except Exception as e:
        print(f"Error processing file: {e}")


def main():
    parser = argparse.ArgumentParser(description='Network Traffic Classification Test Cases')
    parser.add_argument('--interactive', '-i', action='store_true', 
                       help='Run in interactive mode')
    parser.add_argument('--file', '-f', type=str, 
                       help='CSV file with features for batch processing')
    parser.add_argument('--model-dir', '-m', type=str, default='./MLModel',
                       help='Directory containing model files (default: ./MLModel)')
    
    args = parser.parse_args()
    
    # Initialize classifier
    print("\n" + "="*80)
    print("NETWORK TRAFFIC CLASSIFIER - TEST CASES")
    print("="*80)
    
    classifier = NetworkTrafficClassifier(model_dir=args.model_dir)
    
    # Run appropriate mode
    if args.interactive:
        interactive_mode(classifier)
    elif args.file:
        batch_mode(classifier, args.file)
    else:
        run_all_test_cases(classifier)


if __name__ == "__main__":
    main()