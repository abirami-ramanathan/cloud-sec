import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import sniff, wrpcap

PACKETS_TO_CAPTURE = 1000
CAPTURE_FILE_PREFIX = "captured_packets"

## The capture engine will sniff a particular interface, and captures packets and saves it to a file
captured_packets = []

## Function to capture packets and append to the dictionary
def packet_callback(packet):
    global captured_packets
    captured_packets.append(packet)

    if len(captured_packets) == PACKETS_TO_CAPTURE:
        save_packets()

def save_packets():
    global captured_packets
    filename = "/app/data1/captured_traffic.pcap"
    wrpcap(filename, captured_packets)
    print(f"{len(captured_packets)} packets captured and saved to {filename}")
    captured_packets = []

def main():
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
