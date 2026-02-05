import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(filename='/app/data3/alert.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def send_email(subject, body):
    # Email configuration
    sender_email = 'konvict.serendib@gmail.com'
    receiver_email = 'w1945035@my.westminster.ac.uk'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'konvict.serendib@gmail.com'
    smtp_password = 'jtya rrox uyrs himn'

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Establish a connection to the SMTP server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

def main():

    # Log the alert
    logging.error("Alert! An Attack has been detected.")

    # Send an email
    subject = "Alert: Attack Detected"
    body = "The Network Traffic Classifier System has detected an Attack. Please check."
    #send_email(subject, body)
