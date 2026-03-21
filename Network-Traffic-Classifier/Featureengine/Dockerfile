# Dockerfile for feature engineering
FROM python:3.9

# Install required dependencies
RUN pip install pandas scapy cryptography

# Copy your Python script for feature engineering
COPY extractfinal.py /app/extractfinal.py

# Set the working directory
WORKDIR /app
#RUN mkdir -p /app/data
# Define the command to run your script
CMD ["python", "extractfinal.py"]
