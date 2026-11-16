import os
import shutil
import subprocess
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_if_addr

NAME = "NEXUS SNIFFER"
VERSION = "1.0"
INTERFACE = "eth0"
PACKET_LIMIT = 20
CAPTURE_TIMEOUT = 30

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

stats = Counter()
total_packets = 0


def clear_screen():
    os.system("clear")


def show_banner():
    clear_screen()
    print(CYAN + BOLD)
    if shutil.which("figlet"):
        subprocess.run(["figlet", "-f", "slant", NAME], check=False)
    else:
        print(NAME)
    print(RESET)
    print(GREEN + "       NETWORK SECURITY & TRAFFIC ANALYSIS" + RESET)
    print(YELLOW + "       Python | Scapy | Kali Linux" + RESET)
    print(CYAN + "=" * 65 + RESET)


def show_menu():
    print()
    print(CYAN + "  PACKET CAPTURE".ljust(33) + "ANALYSIS" + RESET)
    print(GREEN + "  01. Start capture".ljust(33) + "04. Protocol statistics" + RESET)
    print(GREEN + "  02. Interface information".ljust(33) + "05. Packet summary" + RESET)
    print(GREEN + "  03. Available interfaces".ljust(33) + "06. Capture settings" + RESET)
    print()
    print(CYAN + "  INFORMATION" + RESET)
    print(GREEN + "  07. About NEXUS SNIFFER" + RESET)
    print(GREEN + "  00. Exit" + RESET)
    print(CYAN + "=" * 65 + RESET)


def analyze_packet(packet):
    global total_packets

    if IP not in packet:
        return

    total_packets += 1
    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol, color = "TCP", GREEN
    elif UDP in packet:
        protocol, color = "UDP", YELLOW
    elif ICMP in packet:
        protocol, color = "ICMP", RED
    else:
        protocol, color = "OTHER", WHITE

    stats[protocol] += 1
    print(
        f"{color}[{total_packets:02}] {protocol:<6} "
        f"{source:<16} -> {destination}{RESET}"
    )


def start_capture():
    global total_packets
    stats.clear()
    total_packets = 0

    print(CYAN + "\nStarting packet capture..." + RESET)
    print(f"Interface: {INTERFACE}")
    print(f"Limit: {PACKET_LIMIT} packets or {CAPTURE_TIMEOUT} seconds")
    print("-" * 65)

    try:
        sniff(
            iface=INTERFACE,
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            timeout=CAPTURE_TIMEOUT,
            store=False,
        )
        print("-" * 65)
        print(GREEN + "Capture completed!" + RESET)
        print(f"Total packets: {total_packets}")
    except Exception as error:
        print(RED + f"Capture error: {error}" + RESET)

    input("\nPress ENTER to return to menu...")


def show_statistics():
    print(CYAN + "\nPROTOCOL STATISTICS" + RESET)
    print("-" * 40)
    print(f"Total packets: {total_packets}")
    if stats:
        for protocol, count in sorted(stats.items()):
            print(f"{protocol:<10}: {count}")
    else:
        print(YELLOW + "No capture data available." + RESET)
    input("\nPress ENTER to continue...")


def packet_summary():
    print(CYAN + "\nPACKET SUMMARY" + RESET)
    print("-" * 40)
    print(f"Interface: {INTERFACE}")
    print(f"Total packets: {total_packets}")
    print(f"Protocols detected: {len(stats)}")
    input("\nPress ENTER to continue...")


def interface_information():
    print(CYAN + "\nINTERFACE INFORMATION" + RESET)
    try:
        print(f"Interface: {INTERFACE}")
        print(f"IP Address: {get_if_addr(INTERFACE)}")
    except Exception as error:
        print(RED + str(error) + RESET)
    input("\nPress ENTER to continue...")


def available_interfaces():
    print(CYAN + "\nAVAILABLE INTERFACES" + RESET)
    for interface in get_if_list():
        print(GREEN + "  " + interface + RESET)
    input("\nPress ENTER to continue...")


def capture_settings():
    print(CYAN + "\nCAPTURE SETTINGS" + RESET)
    print(f"Interface: {INTERFACE}")
    print(f"Packet limit: {PACKET_LIMIT}")
    print(f"Timeout: {CAPTURE_TIMEOUT} seconds")
    print("Filter: IPv4 packets (ip)")
    input("\nPress ENTER to continue...")


def about():
    print(CYAN + "\nABOUT NEXUS SNIFFER" + RESET)
    print(f"Name: {NAME}")
    print(f"Version: {VERSION}")
    print("Language: Python")
    print("Library: Scapy")
    print("Platform: Kali Linux")
    print("Purpose: Network packet metadata analysis")
    input("\nPress ENTER to continue...")


def main():
    while True:
        show_banner()
        show_menu()
        choice = input(YELLOW + "\nEnter your choice: " + RESET).strip()

        if choice == "1":
            start_capture()
        elif choice == "2":
            interface_information()
        elif choice == "3":
            available_interfaces()
        elif choice == "4":
            show_statistics()
        elif choice == "5":
            packet_summary()
        elif choice == "6":
            capture_settings()
        elif choice == "7":
            about()
        elif choice in ("0", "00"):
            print(GREEN + "\nNEXUS SNIFFER shutting down..." + RESET)
            break
        else:
            print(RED + "\nInvalid option!" + RESET)
            input("Press ENTER to continue...")


if __name__ == "__main__":
    main()
