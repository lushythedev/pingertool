import os
import time
import socket
import struct
import subprocess
import urllib.request
import logging
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

logging.basicConfig(filename='pingit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

    def add_result(self, result):
        self.results.append(result)
        self.save_result(result)

    def save_result(self, result):
        filename = f"test_{self.test_number}.txt"
        with open(filename, "w") as file:
            file.write(f"--- Ping Result Test #{self.test_number} ---\n")
            file.write(f"Target: {result.target}\n")
            file.write(f"Protocol: {result.protocol}\n")
            file.write(f"Port: {result.port}\n")
            file.write(f"Response Time: {result.response_time:.0f} ms\n")
            if result.error:
                file.write(f"Error: {result.error}\n")
        self.test_number += 1

    def display_history(self):
        if not self.results:
            print(f"{CRED}No ping history available.{CRESET}")
        else:
            for result in self.results:
                print(f"--- Ping Result Test #{result.test_number} ---")
                print(f"Target: {CCYAN}{result.target}")
                print(f"Protocol: {CCYAN}{result.protocol}")
                print(f"Port: {CCYAN}{result.port}")
                print(f"Response Time: {CCYAN}{result.response_time:.0f} ms{CRESET}")
                if result.error:
                    print(f"Error: {CRED}{result.error}{CRESET}")
                print()

    def display_statistics(self):
        if not self.results:
            print(f"{CRED}No statistics available. Run a scan first.{CRESET}")
        else:
            total_pings = len(self.results)
            successful_pings = len([result for result in self.results if result.response_time is not None])
            success_rate = successful_pings / total_pings * 100 if total_pings > 0 else 0
            average_response_time = sum(result.response_time for result in self.results if result.response_time is not None) / successful_pings if successful_pings > 0 else 0

            print(f"{CGREEN}--- Ping Statistics ---{CRESET}")
            print(f"{CWHITE}Total Pings: {CGREEN}{total_pings}")
            print(f"{CWHITE}Successful Pings: {CGREEN}{successful_pings}")
            print(f"{CWHITE}Success Rate: {CGREEN}{success_rate:.2f}%")
            print(f"{CWHITE}Average Response Time: {CGREEN}{average_response_time:.2f} ms{CRESET}")

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

def http_ping(url):
    # HTTP ping logic
    try:
        start_time = time.time()  # Record the start time
        response = urllib.request.urlopen(url, timeout=10)  # Increase the timeout to 10 seconds
        end_time = time.time()  # Record the end time
        
        ms_response = (end_time - start_time) * 1000  # Calculate the time difference in milliseconds
        return ms_response, None  # Return the response time and no error
    
    except urllib.error.URLError as e:
        return None, str(e)  # Return the error message without the "Error: " prefix
    except socket.timeout:
        return None, "Connection timeout"
    except Exception as e:
        return None, f"Error: {str(e)}"

def main_menu():
    main_menu_title = "  Select an option.\n  Press Q or Esc to quit. \n"
    main_menu_items = ["-- METHODS --", "TCP Ping", "UDP Ping", "ICMP Ping", "HTTP Ping", "-- OTHER --", "View History", "View Statistics", "Quit"]
    main_menu_cursor = "> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_red", "fg_black")
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=False,
    )

    os.system("clear")  # Clear the screen
    print(welcome_message)
    print(info)

    history = PingHistory()  # Create a new instance of PingHistory

    while not main_menu_exit:
        main_sel = main_menu.show()

        if main_sel == 1:
            print(f"{CRED}TCP Ping selected{CRESET}")
            target = ""
            while not target:
                target = input("Enter an IP address or website: ")
            port = ""
            while not port:
                port = input("Enter a port: ")
            num_pings = ""
            while not num_pings:
                num_pings = input("Enter the number of pings: ")
            delay = ""
            while not delay:
                delay = input("Enter a delay (in seconds): ")
            if int(delay) <= 0:
                print(f"{CRED}Invalid delay value. Delay must be greater than 0.{CRESET}")
                return

            try:
                ip = target if target.isdigit() else socket.gethostbyname(target)  # Get the IP address from the hostname or use the IP directly
                print(f"Attempting to connect to {CGREEN}{target} {CWHITE}[{CGREEN}{ip}{CWHITE}] {CRESET}on {CGREEN}TCP {CWHITE}Port: {CGREEN}{port}{CRESET}\n")

                for _ in range(int(num_pings)):
                    response_time, error = tcp_ping(ip, int(port))

                    result = PingResult(target, "TCP", port, response_time, error)
                    history.add_result(result)

                    if response_time is not None:
                        response_str = f"Connected | {CGREEN}{ip}{CRESET} {CWHITE}| Time = {CGREEN}{response_time:.0f} ms{CRESET} {CWHITE}| Protocol {CGREEN}TCP{CRESET} {CWHITE}| Port {CGREEN}{port}{CRESET}"
                        print(response_str)
                    else:
                        error_str = f"Failed to reach {CRED}{ip}{CRESET} on {CRED}{port}{CRESET} | Error: {CRED}{error}{CRESET}"
                        print(error_str)

                    time.sleep(int(delay))  # Add a delay between each ping

            except (socket.gaierror, ValueError) as e:
                print(f"{CRED}Invalid IP address or website | Error: {str(e)}")
            except Exception as e:
                print(f"{CRED}An error occurred | Error: {str(e)}")

        elif main_sel == 2:
            print(f"{CRED}UDP Ping selected{CRESET}")
            target = ""
            while not target:
                target = input("Enter an IP address or website: ")
            port = ""
            while not port:
                port = input("Enter a port: ")
            num_pings = ""
            while not num_pings:
                num_pings = input("Enter the number of pings: ")
            delay = ""
            while not delay:
                delay = input("Enter a delay (in seconds): ")
            if int(delay) <= 0:
                print(f"{CRED}Invalid delay value. Delay must be greater than 0.{CRESET}")
                return

            try:
                ip = target if target.isdigit() else socket.gethostbyname(target)  # Get the IP address from the hostname or use the IP directly
                print(f"Attempting to connect to {CGREEN}{target} {CWHITE}[{CGREEN}{ip}{CWHITE}] {CRESET}on {CGREEN}UDP {CWHITE}Port: {CGREEN}{port}{CRESET}\n")

                for _ in range(int(num_pings)):
                    response_time, error = udp_ping(ip, int(port))

                    result = PingResult(target, "UDP", port, response_time, error)
                    history.add_result(result)

                    if response_time is not None:
                        response_str = f"Connected | {CGREEN}{ip}{CRESET} {CWHITE}| Time = {CGREEN}{response_time:.0f} ms{CRESET} {CWHITE}| Protocol {CGREEN}UDP{CRESET} {CWHITE}| Port {CGREEN}{port}{CRESET}"
                        print(response_str)
                    else:
                        error_str = f"Failed to reach {CRED}{ip}{CRESET} on {CRED}{port}{CRESET} | Error: {CRED}{error}{CRESET}"
                        print(error_str)

                    time.sleep(int(delay))  # Add a delay between each ping

            except (socket.gaierror, ValueError) as e:
                print(f"{CRED}Invalid IP address or website | Error: {str(e)}")
            except Exception as e:
                print(f"{CRED}An error occurred | Error: {str(e)}")

        elif main_sel == 3:
            print(f"{CRED}ICMP Ping selected{CRESET}")
            target = ""
            while not target:
                target = input("Enter an IP address or website: ")
            num_pings = ""
            while not num_pings:
                num_pings = input("Enter the number of pings: ")
            delay = ""
            while not delay:
                delay = input("Enter a delay (in seconds): ")
            if int(delay) <= 0:
                print(f"{CRED}Invalid delay value. Delay must be greater than 0.{CRESET}")
                return

            try:
                ip = target if target.isdigit() else socket.gethostbyname(target)  # Get the IP address from the hostname or use the IP directly
                print(f"Attempting to connect to {CGREEN}{target} {CWHITE}[{CGREEN}{ip}{CWHITE}] {CRESET}using {CGREEN}ICMP{CRESET}\n")

                for _ in range(int(num_pings)):
                    response_time, error = icmp_ping(ip)

                    result = PingResult(target, "ICMP", None, response_time, error)
                    history.add_result(result)

                    if response_time is not None:
                        response_str = f"Connected | {CGREEN}{ip}{CRESET} {CWHITE}| Time = {CGREEN}{response_time:.0f} ms{CRESET} {CWHITE}| Protocol {CGREEN}ICMP{CRESET}"
                        print(response_str)
                    else:
                        error_str = f"Failed to reach {CRED}{ip}{CRESET} | Error: {CRED}{error}{CRESET}"
                        print(error_str)

                    time.sleep(int(delay))  # Add a delay between each ping

            except (socket.gaierror, ValueError) as e:
                print(f"{CRED}Invalid IP address or website | Error: {str(e)}")
            except Exception as e:
                print(f"{CRED}An error occurred | Error: {str(e)}")

        elif main_sel == 4:
            print(f"{CRED}HTTP Ping selected{CRESET}")
            url = ""
            while not url:
                url = input("Enter a URL: ")
            num_pings = ""
            while not num_pings:
                num_pings = input("Enter the number of pings: ")
            delay = ""
            while not delay:
                delay = input("Enter a delay (in seconds): ")
            if int(delay) <= 0:
                print(f"{CRED}Invalid delay value. Delay must be greater than 0.{CRESET}")
                return

            try:
                print(f"Attempting to connect to {CGREEN}{url}{CRESET} using {CGREEN}HTTP{CRESET}\n")

                for _ in range(int(num_pings)):
                    response_time, error = http_ping(url)

                    result = PingResult(url, "HTTP", None, response_time, error)
                    history.add_result(result)

                    if response_time is not None:
                        response_str = f"Connected | {CGREEN}{url}{CRESET} {CWHITE}| Time = {CGREEN}{response_time:.0f} ms{CRESET} {CWHITE}| Protocol {CGREEN}HTTP{CRESET}"
                        print(response_str)
                    else:
                        error_str = f"Failed to reach {CRED}{url}{CRESET} | Error: {CRED}{error}{CRESET}"
                        print(error_str)

                    time.sleep(int(delay))  # Add a delay between each ping

            except Exception as e:
                print(f"{CRED}An error occurred | Error: {str(e)}")

        elif main_sel == 5:
            history.display_history()

        elif main_sel == 6:
            history.display_statistics()

        elif main_sel == 7:
            main_menu_exit = True
            print(f"\n{CRED}Exiting PingIt!{CRESET}")
            print(f"{CCYAN}Thank you for using PingIt!{CRESET}")

        else:
            main_menu_exit = True
            print(f"\n{CRED}Exiting PingIt!{CRESET}")
            print(f"{CCYAN}Thank you for using PingIt!{CRESET}")

if __name__ == "__main__":
    main_menu()
