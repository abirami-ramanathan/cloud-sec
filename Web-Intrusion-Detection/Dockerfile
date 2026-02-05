FROM python:3.9

# Install the requirements
RUN pip install numpy==1.24.3 pandas cryptography scikit-learn==1.2.2

# Copy the files
COPY AnomalyDetector.py /app/AnomalyDetector.py
COPY isolationforest.pkl /app/isolationforest.pkl
COPY scaler.pkl /app/scaler.pkl
COPY alert.py /app/alert.py

# Set the working directory
WORKDIR /app

RUN mkdir -p /app/data2
# Command to be run on the docker instance
CMD ["python", "AnomalyDetector.py"]

