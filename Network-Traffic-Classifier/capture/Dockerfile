# Dockerfile for packet capturing
FROM python:3.9

# Set the working directory
WORKDIR /app

# Install required dependencies
RUN pip install scapy cryptography

# Copy your Python script to the container
COPY . . 

# Define the command to run your script
CMD ["python", "capturefinal.py"]
