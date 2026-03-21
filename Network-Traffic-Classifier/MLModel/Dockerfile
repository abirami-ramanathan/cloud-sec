# Dockerfile for the ML model
FROM python:3.11

# Install required dependencies (compatible with Python 3.11)
RUN pip install numpy==1.26.4 pandas cryptography scikit-learn==1.8.0

# Copy your Python script for ML inference
COPY Network-Traffic-Classifier/MLModel/deploydocker.py /app/deploy.py
COPY Network-Traffic-Classifier/MLModel/alert.py /app/alert.py
COPY Network-Traffic-Classifier/MLModel/RFCMODEL.pkl /app/RFCMODEL.pkl
COPY Network-Traffic-Classifier/MLModel/scalerr.sc /app/scalerr.sc
COPY logger.py /app/logger.py

# Set the working directory
WORKDIR /app
#RUN mkdir -p /app/data
# Define the command to run your script
CMD ["python", "deploy.py"]