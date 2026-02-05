## This is the docker deploy version

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import pandas as pd
import pickle
import os
import time
from datetime import datetime
import alert


def process_csv(file_path):
    # Load ML model
    with open("./RFCMODEL.pkl", "rb") as model_file:
        classifier = pickle.load(model_file)
        print("Successfully Loaded ML model......1")

    # Load standard scaler
    with open("./scaler.sc", "rb") as scaler_file:
        scaler = pickle.load(scaler_file)
        print("Loaded the standard scaler........2")

    # Define column names
    column_names = ["duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
                    "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
                    "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
                    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
                    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
                    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
                    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate","connection_key"]

    # Read CSV file
    df = pd.read_csv(file_path, header=None, names=column_names, skiprows=1)
    con = df.pop('connection_key')
    print(f"Loaded the CSV file: {file_path}")

    # Transform data using scaler
    transformed_data = scaler.transform(df)
    
    # Make predictions
    predictions = classifier.predict(transformed_data)
    print("Performing Predictions.......4")
    
    # Add predictions to the DataFrame
    df['predictions'] = predictions
    df = df.assign(connection_key=con)
    
    def process_dataframe(row):
        if row['predictions'] != 'normal':
            alert.main()

    # Apply the process_dataframe function to each row
    df.apply(process_dataframe, axis=1)

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    # Save the predictions to a new CSV file
    output_file = f'/app/data3/{timestamp}-results.csv'
    df.to_csv(output_file, index=False)
    print(f"Predictions saved to: {output_file}")
    

def monitor_folder(folder):
    
    while True:
        # Filter for CSV files that haven't been processed yet
        for new_file in os.listdir(folder):
            if new_file == 'features.csv':
                file_path = os.path.join(folder, new_file)
                print(f"Detected new CSV file: {file_path}")
                process_csv(file_path)
                os.remove(file_path)

        time.sleep(1) 


if __name__ == "__main__":
    folder_to_watch = '/app/data2'
    monitor_folder(folder_to_watch)