"""
Web Server Logs Anomaly Detection Using Isolation Forest
Algorithm 3 Implementation

This module implements real-time anomaly detection for web intrusion detection
by analyzing HTTP server access logs using the Isolation Forest algorithm.

Author: AI-Powered Cyber Incident Detection System
Date: February 2026
"""

import pandas as pd 
import re
import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from alert import mainalert

# ============================================================================
# ALGORITHM 3: Feature Extraction (Steps 4-9)
# ============================================================================

def extract_features(df):
    """
    Extract features from preprocessed log data as per Algorithm 3, Steps 4-9.
    
    Features extracted (Table 4):
    1. IP-level statistics: ip_frequency, unique_connections_count, ip_volume
    2. URL aberrations: url_aberrations
    3. Unusual referrer patterns: unusual_referrer
    4. User-Agent analysis: user_agent_analysis (categorical)
    5. Out-of-order access: out_of_order_access
    
    Args:
        df (DataFrame): Preprocessed log data with columns: ip, request, status, 
                        size, referer, user_agent
    
    Returns:
        DataFrame: Feature matrix X ready for model input
    """
    
    # Step 5: Extract IP-level statistics
    # --------------------------------------
    # ip_frequency: Number of requests from each IP
    # unique_connections_count: Number of unique connections per IP
    # ip_volume: Total data volume transferred per IP

    print("[Step 5] Extracting IP-level statistics...")
    
    # Calculate unique connections based on IP address and request
    unique_connections = df[['ip', 'request']].drop_duplicates()
    
    # ip_frequency: Count of requests per IP address
    ip_frequency = df['ip'].value_counts()
    df['ip_frequency'] = df['ip'].map(ip_frequency)
    
    # unique_connections_count: Number of unique connections for each IP
    unique_conn_count = unique_connections['ip'].value_counts()
    df['unique_connections_count'] = df['ip'].map(unique_conn_count)
    
    # ip_volume: Total bytes transferred per IP address
    ip_volume = df.groupby('ip')['size'].sum()
    df['ip_volume'] = df['ip'].map(ip_volume)
    
    print(f"   - IP-level statistics extracted for {df['ip'].nunique()} unique IPs")


    # Step 6: Extract URL aberrations
    # ---------------------------------
    # Detect path traversal attacks and directory navigation attempts
    print("[Step 6] Detecting URL aberrations (path traversal attempts)...")
    
    def detect_url_aberrations(url):
        """
        Identify URL aberrations such as path traversal attempts.
        Patterns detected: /../, /./,  /.., etc.
        Returns: 1 if aberration detected, 0 otherwise
        """
        if re.search(r'/\./|/\.\./', url):
            return 1  # Presence of URL aberrations (potential attack)
        else:
            return 0  # Normal URL pattern
    
    df['url_aberrations'] = df['request'].apply(detect_url_aberrations)
    aberrations_found = df['url_aberrations'].sum()
    print(f"   - URL aberrations detected: {aberrations_found} out of {len(df)} requests")

    # Step 7: Extract unusual referrer patterns
    # -------------------------------------------
    # Identify requests with suspicious or missing referrer information
    print("[Step 7] Analyzing referrer patterns...")
    
    # Pattern for normal/expected referrers (adjust based on your domain)
    normal_referrer_pattern = re.compile(r'^-|^(https?://[^/]+)?example\.com')
    
    def detect_unusual_referrer(referrer):
        """
        Identify unusual referrer patterns that may indicate attacks.
        Missing referrers (-) or expected domains are considered normal.
        Returns: 0 for normal referrer, 1 for unusual referrer
        """
        if normal_referrer_pattern.match(referrer):
            return 0  # Normal referrer pattern
        else:
            return 1  # Unusual referrer (potential attack source)
    
    df['unusual_referrer'] = df['referer'].fillna('').apply(detect_unusual_referrer)
    unusual_referrers = df['unusual_referrer'].sum()
    print(f"   - Unusual referrers detected: {unusual_referrers} out of {len(df)} requests")


    # Step 8: User-Agent analysis (categorical)
    # ------------------------------------------
    # Analyze User-Agent strings to detect bots, outdated clients, or unusual patterns
    print("[Step 8] Performing User-Agent analysis...")
    
    # Perform frequency analysis to identify known User-Agent strings
    known_user_agents = df['user_agent'].value_counts().index.tolist()
    
    def analyze_user_agent(user_agent):
        """
        Categorize User-Agent strings based on pattern analysis.
        Categories:
        - 'old_client': Extremely outdated browsers (e.g., Mosaic/0.9)
        - 'unusual_user_agent': Never-before-seen or rare User-Agents
        - 'normal': Common/expected User-Agents
        """
        if 'Mosaic/0.9' in user_agent:
            return 'old_client'  # Extremely old/suspicious client
        elif user_agent not in known_user_agents:
            return 'unusual_user_agent'  # Rare or unknown User-Agent
        else:
            return 'normal'  # Normal User-Agent pattern
    
    df['user_agent_analysis'] = df['user_agent'].apply(analyze_user_agent)
    ua_categories = df['user_agent_analysis'].value_counts()
    print(f"   - User-Agent categories: {ua_categories.to_dict()}")



    # Step 9: Detect out-of-order access patterns
    # ---------------------------------------------
    # Identify unusual access sequences that may indicate automated attacks
    print("[Step 9] Detecting out-of-order access patterns...")
    
    # Initialize dictionary to track expected access sequence per IP
    endpoint_sequence = {}
    
    def detect_out_of_order_access(ip_address, request):
        """
        Detect if an IP is accessing endpoints in an unusual order.
        This can indicate automated scanning or attack tools.
        Returns: 1 for out-of-order access, 0 for normal sequence
        """
        if ip_address in endpoint_sequence and request != endpoint_sequence[ip_address]:
            return 1  # Out-of-order access detected
        else:
            endpoint_sequence[ip_address] = request
            return 0  # Normal sequential access
    
    df['out_of_order_access'] = df.apply(
        lambda row: detect_out_of_order_access(row['ip'], row['request']), 
        axis=1
    )
    out_of_order_count = df['out_of_order_access'].sum()
    print(f"   - Out-of-order accesses detected: {out_of_order_count} out of {len(df)} requests")
    
    # Prepare feature matrix X by removing non-feature columns
    print("\n[Step 9 Complete] Building feature matrix X...")
    X = df.drop(columns=['ip', 'request', 'time', 'size', 'referer', 'user_agent'])
    
    # Convert categorical user_agent_analysis to numerical codes
    X['user_agent_analysis'] = df['user_agent_analysis'].astype('category').cat.codes
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"Features: {list(X.columns)}")
    
    return X


# ============================================================================
# ALGORITHM 3: Data Preprocessing (Steps 1-3)
# ============================================================================

def preprocess_log_file(log_file_path):
    """
    Preprocess web server log file as per Algorithm 3, Steps 1-3.
    
    Step 1: Require Web server log file L
    Step 2: Read log file L into a DataFrame D
    Step 3: Remove missing values from D
    
    Args:
        log_file_path (str): Path to the HTTP access log file
    
    Returns:
        DataFrame: Feature matrix X with extracted features
    """
    print("\n" + "="*70)
    print("ALGORITHM 3: Web Server Logs Anomaly Detection")
    print("="*70)
    
    # Step 2: Read log file L into a DataFrame D
    print(f"\n[Step 2] Reading log file: {log_file_path}")
    
    # Parse Apache/Nginx access log format
    # Format: IP - - [timestamp] "REQUEST" STATUS SIZE "REFERER" "USER-AGENT"
    df = pd.read_csv(
        log_file_path,
        sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
        engine='python',
        usecols=[0, 3, 4, 5, 6, 7, 8],
        names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
        na_values='-',
        header=None
    )
    
    print(f"   - Log entries read: {len(df)}")
    print(f"   - Columns: {list(df.columns)}")
    
    # Step 3: Remove missing values from D
    print("\n[Step 3] Removing missing values...")
    initial_count = len(df)
    df.dropna(inplace=True)
    final_count = len(df)
    print(f"   - Entries after cleaning: {final_count}")
    print(f"   - Removed: {initial_count - final_count} incomplete entries")
    
    # Steps 4-9: Extract features
    print("\n[Steps 4-9] Extracting features from log data...")
    X = extract_features(df)
    
    return X


# ============================================================================
# ALGORITHM 3: Real-Time Anomaly Detection Deployment (Steps 10-20)
# ============================================================================

def main():
    """
    Main deployment loop for real-time web intrusion detection.
    
    This function:
    - Monitors for new log files
    - Applies preprocessing and feature extraction (Steps 1-9)
    - Uses trained Isolation Forest model for anomaly detection (Steps 11-19)
    - Triggers alerts based on threshold (Step 19)
    - Returns detection results (Step 20)
    
    Model Hyperparameters (from paper):
    - Max samples: 10,000 (optimized from initial 1,000)
    - Contamination: 0.01 (optimal after testing 0.001, 0.01, 0.1)
    - Random state: 100 (for reproducibility)
    """
    
    # Shared volume path for log collection
    # Support both Docker (/app/data2) and local (data2) environments
    if os.path.exists('/app/data2'):
        log_folder = '/app/data2'
    else:
        # Running locally - use data2 directory in current folder
        log_folder = 'data2'
        if not os.path.exists(log_folder):
            print(f"ERROR: {log_folder} directory not found!")
            print(f"Please create the directory and place access.log file in it.")
            return
    
    print("\n" + "#"*70)
    print("# WEB INTRUSION DETECTION SYSTEM - REAL-TIME MONITORING")
    print("# Using Isolation Forest Algorithm for Anomaly Detection")
    print("#"*70)
    print(f"\nMonitoring folder: {log_folder}")
    print("Waiting for access.log files...\n")
    
    # Check for log files (single pass for demo)
    for filename in os.listdir(log_folder):
        if filename == 'access.log':
            log_file_path = os.path.join(log_folder, filename)
            
            print(f"\n{'*'*70}")
            print(f"NEW LOG FILE DETECTED: {log_file_path}")
            print(f"{'*'*70}")
            
            try:
                # ===================================================
                # STEPS 1-9: Preprocess and Extract Features
                # ===================================================
                X = preprocess_log_file(log_file_path)
                unique_connections = X['unique_connections_count'].nunique()
                
                # ===================================================
                # STEPS 11-16: Load Trained Isolation Forest Model M
                # ===================================================
                print("\n" + "="*70)
                print("[Steps 11-16] Loading trained Isolation Forest model...")
                
                # Load pre-trained Isolation Forest model
                # Model trained with:
                #   - n_estimators: 100
                #   - max_samples: 10000
                #   - contamination: 0.01
                #   - random_state: 100
                with open('isolationforest.pkl', 'rb') as model_file:
                    isolation_forest_model = pickle.load(model_file)
                print("   - Isolation Forest model loaded successfully")
                
                # ===================================================
                # STEP 10: Standardize Features Using StandardScaler
                # ===================================================
                print("\n[Step 10] Standardizing numerical features...")
                
                # Load pre-fitted StandardScaler
                with open('scaler.pkl', 'rb') as scaler_file:
                    scaler = pickle.load(scaler_file)
                
                # Transform features using pre-fitted scaler
                X_scaled = scaler.transform(X)
                print(f"   - Features standardized: shape {X_scaled.shape}")
                
                # ===================================================
                # STEPS 17-19: Detect Anomalies
                # ===================================================
                print("\n" + "="*70)
                print("[Steps 17-19] Detecting anomalies...")
                
                # Step 18: Use M to predict anomaly scores for new data points
                # Isolation Forest returns:
                #   +1 for normal instances
                #   -1 for anomalies
                anomaly_predictions = isolation_forest_model.predict(X_scaled)
                X['Anomaly'] = anomaly_predictions
                
                # Step 19: Mark data points with scores below threshold as anomalies
                # Calculate the number of detected anomalies
                num_anomalies = (X['Anomaly'] == -1).sum()
                total_requests = len(X)
                anomaly_percentage = (num_anomalies / total_requests) * 100
                
                print(f"\n   DETECTION RESULTS:")
                print(f"   {'─'*50}")
                print(f"   Total requests analyzed:     {total_requests}")
                print(f"   Anomalies detected:          {num_anomalies}")
                print(f"   Anomaly rate:                {anomaly_percentage:.2f}%")
                print(f"   Unique IP connections:       {unique_connections}")
                
                # ===================================================
                # Alert Threshold Logic (Reduce False Positives)
                # ===================================================
                # Paper: "Triggers alerts only when the number of detected 
                # anomalies exceeds a predefined threshold. This approach is 
                # based on the assumption that real-world attacks often involve 
                # rapid bursts of activity."
                
                # Threshold: 20% of unique connections (configurable)
                alert_threshold = 0.20 * unique_connections
                
                print(f"\n   ALERT THRESHOLD:")
                print(f"   {'─'*50}")
                print(f"   Threshold value:             {alert_threshold:.2f}")
                print(f"   Threshold calculation:       20% × {unique_connections} unique connections")
                
                # Trigger alert if anomalies exceed threshold
                mainalert(num_anomalies, alert_threshold, unique_connections)
                
                # ===================================================
                # STEP 20: Return Anomaly Detection Results
                # ===================================================
                results_path = '/app/data2/results.csv'
                X.to_csv(results_path, index=False)
                
                print(f"\n" + "="*70)
                print("[Step 20] PROCESSING COMPLETE")
                print(f"Results saved to: {results_path}")
                print(f"Original log preserved at: {log_file_path}")
                print("="*70)
                
                # Keep the log file for demo/review purposes
                # os.remove(log_file_path)  # Commented out for live demo
                print(f"\nLog file preserved for review: {log_file_path}")
                
            except Exception as e:
                print(f"\nERROR processing log file: {str(e)}")
                import traceback
                traceback.print_exc()

# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    main()


