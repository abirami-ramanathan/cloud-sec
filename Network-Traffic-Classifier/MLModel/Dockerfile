# Dockerfile for the ML model
FROM python:3.9

# Install required dependencies
RUN pip install pandas cryptography scikit-learn==1.2.2

# Copy your Python script for ML inference
COPY deploydocker.py /app/deploy.py
COPY alert.py /app/alert.py
COPY RFCMODEL.pkl /app/RFCMODEL.pkl
COPY scaler.sc /app/scaler.sc

# Set the working directory
WORKDIR /app
#RUN mkdir -p /app/data
# Define the command to run your script
CMD ["python", "deploy.py"]