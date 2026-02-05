"""
Alert Module for Web Intrusion Detection System

This module handles alert generation and notification when anomalies exceed
the predefined threshold. The threshold-based approach reduces false positives
by assuming that real-world attacks involve rapid bursts of anomalous activity.

Author: AI-Powered Cyber Incident Detection System
Date: February 2026
"""

import logging
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging for alert tracking
# Support both Docker (/app/data2) and local (data2) environments
if os.path.exists('/app/data2'):
    log_path = '/app/data2/alert.log'
else:
    # Running locally - use data2 directory in current folder
    log_dir = 'data2'
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, 'alert.log')

logging.basicConfig(
    filename=log_path, 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_email_alert(subject, body):
    """
    Send email notification when critical alerts are triggered.
    
    Args:
        subject (str): Email subject line
        body (str): Email body content
    
    Note: Email credentials must be configured before enabling email alerts.
    """
    # Email configuration (TO BE CONFIGURED IN PRODUCTION)
    sender_email = ''  # TODO: Configure sender email
    receiver_email = ''  # TODO: Configure receiver email
    smtp_server = ''  # TODO: Configure SMTP server (e.g., smtp.gmail.com)
    smtp_port = 587
    smtp_username = ''  # TODO: Configure SMTP username
    smtp_password = ''  # TODO: Configure SMTP password

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Establish a connection to the SMTP server
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        logging.info(f"Email alert sent successfully: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {str(e)}")

def mainalert(num_anomalies, alert_threshold, unique_connections):
    """
    Main alert function implementing threshold-based alerting strategy.
    
    From the paper:
    "To reduce false positives, the application triggers alerts only when 
    the number of detected anomalies exceeds a predefined threshold. This 
    approach is based on the assumption that real-world attacks often involve 
    rapid bursts of activity, leading to a surge in detected anomalies."
    
    Args:
        num_anomalies (int): Number of detected anomalies
        alert_threshold (float): Threshold for triggering alert
        unique_connections (int): Number of unique connections analyzed
    """
    
    print(f"\n   ALERT EVALUATION:")
    print(f"   {'-'*50}")
    
    if num_anomalies > alert_threshold:
        # CRITICAL ALERT: Anomalies exceed threshold
        print(f"\n   CRITICAL ALERT: WEB INTRUSION DETECTED ")
        print(f"   {'='*50}")
        print(f"   Anomalies detected:      {num_anomalies}")
        print(f"   Alert threshold:         {alert_threshold:.2f}")
        print(f"   Unique connections:      {unique_connections}")
        print(f"   {'='*50}")
        print(f"   STATUS: ALERT TRIGGERED")
        print(f"   A significant surge in anomalous activity has been detected.")
        print(f"   This may indicate an ongoing web-based attack.")
        print(f"   Immediate investigation is recommended.")
        
        # Log the critical alert
        logging.error(
            f"CRITICAL ALERT - Anomalies: {num_anomalies}, "
            f"Threshold: {alert_threshold:.2f}, "
            f"Unique Connections: {unique_connections}"
        )
        
    else:
        # Normal operation: Below threshold
        print(f"   ✅ STATUS: Normal Operation")
        print(f"   Anomalies ({num_anomalies}) are within acceptable threshold ({alert_threshold:.2f})")
        print(f"   No alert triggered.")
        
        # Log normal status
        logging.info(
            f"Normal operation - Anomalies: {num_anomalies}, "
            f"Threshold: {alert_threshold:.2f}"
        )
