# Dockerfile for the ML model
FROM python:3.11

# Install required dependencies (compatible with Python 3.11)
RUN pip install numpy==1.26.4 pandas cryptography scikit-learn==1.8.0

# Copy your Python script for ML inference
COPY deploydocker.py /app/deploy.py
COPY alert.py /app/alert.py
COPY RFCMODEL.pkl /app/RFCMODEL.pkl
COPY scalerr.sc /app/scalerr.sc

# Set the working directory
WORKDIR /app
#RUN mkdir -p /app/data
# Define the command to run your script
CMD ["python", "deploy.py"]