"""
Author: Deniz Can
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Maps common port numbers to their standard network service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using properties allows us to safely control how a variable is accessed or changed. 
    # Instead of letting outside code modify the target directly and potentially break the program, we use the setter to validate the input first (like checking for an empty string).
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, meaning it automatically gets the target variable and its validation logic. 
# We don't have to rewrite the target property or setter in PortScanner; we just call super().__init__(target) to reuse the parent's code.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If we didn't use try-except, the program would completely crash and stop running if it encountered a network issue, such as a timeout or an unreachable host.
        # The try-except block allows the scanner to handle the error gracefully, print a message, and continue scanning the remaining ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                status = "Open"
            else:
                status = "Closed"
                
            if port in common_ports:
                service_name = common_ports[port]
            else:
                service_name = "Unknown"
            
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
            
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Scanning ports one by one takes a long time because the program has to wait for each port connection to timeout before moving to the next.
    # By using threading, we can scan many ports at the exact same time, which turns a process that would take minutes into just a few seconds.
    def scan_range(self, start_port, end_port):
        threads = []
        
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        
        scan_date = str(datetime.datetime.now())
        
        for result in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                           (target, result[0], result[1], result[2], scan_date))
            
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        
        if len(rows) == 0:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
                
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

if __name__ == "__main__":
    try:
        target_input = input("Target IP (default 127.0.0.1): ")
        if target_input == "":
            target_ip = "127.0.0.1"
        else:
            target_ip = target_input
            
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        
        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target_ip)
            print(f"Scanning {scanner.target} from port {start_port} to {end_port}...")
            
            scanner.scan_range(start_port, end_port)
            open_ports = scanner.get_open_ports()
            
            print(f"\n--- Scan Results for {scanner.target} ---")
            for port in open_ports:
                print(f"Port {port[0]}: {port[1]} ({port[2]})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")
            
            save_results(scanner.target, open_ports)
            
            show_history = input("Would you like to see past scan history? (yes/no): ")
            if show_history.lower() == "yes":
                load_past_scans()
                
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# I would add an "Export to CSV" feature that allows users to save the scan results into a readable text file. 
# It would use a list comprehension to format the data (e.g., combining IP, port, and status into a single string) before writing it to the file.
# Diagram: See diagram_101591488.png in the repository root