import os
import time
import socket
import struct
import subprocess
import urllib.request
from colorama import Fore, Style
from simple_term_menu import TerminalMenu

# Define color and style variables
CCYAN = Fore.LIGHTCYAN_EX
CRED = Fore.LIGHTRED_EX
CWHITE = Fore.WHITE
CRESET = Style.RESET_ALL
CGREEN = Fore.LIGHTGREEN_EX

welcome_message = f"{CCYAN}PingIt!{CWHITE} | {CRED}Conducting cross-platform ping+port testing through ping-like emulation for port verification{CRESET}\n{CRED}Version 1.0 | By {CGREEN}PoppingXanax{CRESET}"
info = f"{CWHITE}\n! Report any issues on Github !{CRESET}\n"

class PingResult:
    def __init__(self, target, protocol, port, response_time, error):
        self.target = target
        self.protocol = protocol
        self.port = port
        self.response_time = response_time
        self.error = error

class PingHistory:
    def __init__(self):
        self.results = []
        self.test_number = 1
        self.filename = "ping_history.txt"  # Specify the filename

    def add_result(self, result):
        self.results.append(result)

    def save_test(self):
        if not self.results:
            print(f"{CRED}No test results available.{CRESET}")
            return

        with open(self.filename, "a") as file:  # Open the file in append mode
            file.write(f"--- Ping Results Test #{self.test_number} ---\n\n")
            for index, result in enumerate(self.results, start=1):
                file.write(f"--- Ping Result {index} ---\n")
                file.write(f"Target: {result.target}\n")
                file.write(f"Protocol: {result.protocol}\n")
                file.write(f"Port: {result.port}\n")
                file.write(f"Response Time: {result.response_time:.0f} ms\n")
                if result.error:
                    file.write(f"Error: {result.error}\n")
                file.write("\n")
        self.test_number += 1
        self.results = []  # Clear the results after saving the test

def udp_ping(ip, port):
    # UDP ping logic
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # Set the timeout to 5 seconds

        start_time = time.time()  # Record the start time
        sock.sendto(b"", (ip, port))  # Send an empty UDP packet to the target

        # Set a timeout for receiving the response
        sock.settimeout(5)
        try:
            data, addr = sock.recvfrom(1024)  # Receive the response
            end_time = time.time()  # Record the end time
            ms_response = (end_time - start_time) * 1000  # Calculate the time difference in milliseconds
            return ms_response, None  # Return the response time and no error
        except socket.timeout:
            return None, "Connection timeout"

    except socket.timeout:
        return None, "Connection timeout"
    except ConnectionRefusedError:
        return None, "Connection refused"
    except Exception as e:
        return None, f"Error: {str(e)}"

def tcp_ping(ip, port):
    # TCP ping logic
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set the timeout to 5 seconds

        start_time = time.time()  # Record the start time
        sock.connect((ip, port))  # Connect to the target
        end_time = time.time()  # Record the end time

        sock.close()

        ms_response = (end_time - start_time) * 1000  # Calculate the time difference in milliseconds
        return ms_response, None  # Return the response time and no error

    except socket.timeout:
        return None, "Connection timeout"
    except ConnectionRefusedError:
        return None, "Connection refused"
    except Exception as e:
        return None, f"Error: {str(e)}"

def icmp_ping(ip):
    # ICMP ping logic
    try:
        # Construct the ICMP Echo Request packet
        icmp_type = 8  # ICMP Echo Request type
        icmp_code = 0  # ICMP Echo Request code
        icmp_checksum = 0  # ICMP Checksum initially set to 0
        icmp_id = os.getpid() & 0xFFFF  # Generate ICMP identifier (PID)
        icmp_seq = 1  # ICMP sequence number

        # Create the ICMP header
        icmp_header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

        # Calculate ICMP checksum
        icmp_checksum = calculate_checksum(icmp_header)

        # Pack the ICMP header with the updated checksum
        icmp_header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_seq)

        # Create the ICMP packet
        icmp_packet = icmp_header

        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(5)  # Set the timeout to 5 seconds

        start_time = time.time()  # Record the start time
        sock.sendto(icmp_packet, (ip, 0))  # Send the ICMP packet
        try:
            data, addr = sock.recvfrom(1024)  # Receive the response
            end_time = time.time()  # Record the end time
            ms_response = (end_time - start_time) * 1000  # Calculate the time difference in milliseconds
            return ms_response, None  # Return the response time and no error
        except socket.timeout:
            return None, "Connection timeout"

    except socket.timeout:
        return None, "Connection timeout"
    except ConnectionRefusedError:
        return None, "Connection refused"
    except PermissionError:
        return None, "Permission denied. Please run the script as a privileged user."
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        return None, error_message

def calculate_checksum(data):
    # Calculate the checksum for ICMP packets.
    checksum = 0

    # If the data length is odd, append a zero byte
    if len(data) % 2 != 0:
        data += b'\x00'

    # Iterate over the data in 16-bit chunks and add them to the checksum
    for i in range(0, len(data), 2):
        chunk = (data[i] << 8) + data[i + 1]
        checksum += chunk

    # Add the carry bits
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16

    # Take the one's complement of the result
    checksum = ~checksum & 0xFFFF

    return checksum


def main():
    print(welcome_message)
    print(info)

    # Create an instance of PingHistory
    ping_history = PingHistory()

    # Create a terminal menu for protocol selection
    protocol_menu_title = "Select a protocol:"
    protocol_menu_items = ["ICMP", "UDP", "TCP", "Exit"]
    protocol_menu = TerminalMenu(protocol_menu_items, protocol_menu_title)
    protocol_index = protocol_menu.show()

    # Loop until the user chooses to exit
    while protocol_index != len(protocol_menu_items) - 1:
        protocol = protocol_menu_items[protocol_index]

        # Get the target IP address or domain from the user
        target = input("\nEnter the IP address or domain to ping: ")

        # Get the port number for UDP and TCP protocols
        if protocol == "UDP" or protocol == "TCP":
            port = int(input("Enter the port number to test: "))
        else:
            port = None

        # Perform the ping test based on the selected protocol
        if protocol == "ICMP":
            response_time, error = icmp_ping(target)
        elif protocol == "UDP":
            response_time, error = udp_ping(target, port)
        elif protocol == "TCP":
            response_time, error = tcp_ping(target, port)

        # Create a PingResult object with the test results
        result = PingResult(target, protocol, port, response_time, error)

        # Add the result to PingHistory
        ping_history.add_result(result)

        print("\n--- Ping Result ---")
        print(f"Target: {result.target}")
        print(f"Protocol: {result.protocol}")
        if result.port:
            print(f"Port: {result.port}")
        print(f"Response Time: {result.response_time:.0f} ms")
        if result.error:
            print(f"Error: {result.error}")

        # Wait for user input before continuing
        input("\nPress Enter to continue...")

        # Clear the console
        subprocess.call("cls" if os.name == "nt" else "clear", shell=True)

        # Show the protocol selection menu again
        protocol_index = protocol_menu.show()

    # Save the test results to a text file
    ping_history.save_test()

    print(f"\nTest results saved to {ping_history.filename}\n")


if __name__ == "__main__":
    main()
