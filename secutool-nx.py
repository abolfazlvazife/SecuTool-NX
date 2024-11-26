import socket
import scapy.all as scapy
from threading import Thread
import requests
from bs4 import BeautifulSoup
import time
import hashlib
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')



# Menu
def display_menu():
    print(""" 
        ===========================
            SecuTool NX 1.0.0
        ===========================
          """)
    print("Choose an option:")
    print("1. Port Scanner")
    print("2. Traffic Analyzer")
    print("3. ARP Spoof Detection")
    print("4. Brute Force Tester (Beta)")
    print("5. Web Vulnerability Scanner (Beta)")
    print("6. Exit")

# 1. Port Scanner
def port_scanner():
    target = input("Enter the target IP address: ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))
    
    print(f"Scanning ports on {target} from {start_port} to {end_port}...")
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} is open.")
            else:
                print(f"Port {port} is closed.")

# 2. Traffic Analyzer
def traffic_analyzer():
    print("Starting Traffic Analyzer...")
    print("Press Ctrl+C to stop.")
    try:
        scapy.sniff(prn=lambda x: x.show(), store=False)
    except KeyboardInterrupt:
        print("\nTraffic Analyzer stopped.")

# 3. ARP Spoof Detection
def detect_arp_spoof():
    def monitor_arp():
        while True:
            packets = scapy.sniff(filter="arp", count=1)
            for packet in packets:
                if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                    print(f"Potential ARP Spoofing detected: {packet.summary()}")

    print("Detecting ARP Spoofing (Press Ctrl+C to stop)...")
    try:
        monitor_arp()
    except KeyboardInterrupt:
        print("\nARP Spoof Detection stopped.")

# 4. Brute Force Tester
def brute_force():
    target = input("Enter the target IP or URL: ")
    wordlist = input("Enter the path to the password wordlist: ")

    with open(wordlist, "r") as file:
        passwords = file.readlines()
    
    print(f"Starting Brute Force Attack on {target}...")
    for password in passwords:
        password = password.strip()
        print(f"Trying: {password}")
        time.sleep(0.5)  # Simulate the attack
        # You can add actual logic for FTP/SSH here if needed.
        if password == "test":  # Replace with real check
            print(f"Password found: {password}")
            break
    else:
        print("Password not found in the provided wordlist.")

# 5. Web Vulnerability Scanner
def web_vulnerability_scanner():
    url = input("Enter the URL of the website: ")
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    
    print("Scanning for vulnerabilities...")
    if "<script>" in str(soup):
        print("Potential XSS vulnerability detected.")
    if "SELECT" in str(soup).upper() or "DROP" in str(soup).upper():
        print("Potential SQL Injection vulnerability detected.")
    print("Scan completed.")

# Main Loop
def main():
    
    while True:
        display_menu()
        choice = input("Enter your choice: ")
        if choice == "1":
            port_scanner()
        elif choice == "2":
            traffic_analyzer()
        elif choice == "3":
            detect_arp_spoof()
        elif choice == "4":
            brute_force()
        elif choice == "5":
            web_vulnerability_scanner()
        elif choice == "6":
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
