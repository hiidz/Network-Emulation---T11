import socket
import threading
import time
from config import *
from classes.routing import *
from classes.arp import *
from classes.dhcpClient import *
from classes.ethernet_frame import *
from classes.firewall import *
from classes.attacks import *
from classes.DNS.dns import *

from util import *
import re
import os


def print_brk():
    try:
        columns = os.get_terminal_size().columns
    except OSError:
        columns = 80  # Default width if terminal size can't be determined
    print("-" * columns)


class Node:
    node_mac = None
    node_ip = None
    router = None
    conn_list = None
    has_firewall = False
    is_malicious = False
    url = None

    # VPN related attributes
    vpn_enabled = false
    vpn_ip_address = None
    vpn_gateway = None

    # Encryption Key
    encryption_key = None
    cipher = None

    def __init__(
            self,
            node_mac,
            default_routing_table: dict = None,
            # default_routing_port=None,
            url=None,
            has_firewall: bool = False,
            is_malicious: bool = False,
            vpn_ip_address=None,
            vpn_gateway=None,
            encryption_key=None,
    ):
        self.node_mac = node_mac
        self.url = url

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}
        self.has_firewall = has_firewall
        if has_firewall:
            self.firewall = Firewall()

        self.is_malicious = is_malicious
        if is_malicious:
            self.attacks = Attacks()

        self.routing_protocol = Routing_Protocol(default_routing_table)
        self.dhcp_protocol = DHCP_Client_Protocol()
        self.arp_protocol = ARP_Protocol()
        self.dns_protocol = DNS_Protocol()
        self.dns_ip_address = None
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.router = (HOST, default_routing_table['default']['port'])

        # Initialize VPN attributes
        self.vpn_enabled = False
        self.vpn_ip_address = vpn_ip_address
        self.vpn_gateway = vpn_gateway

        # Initialize encryption
        if encryption_key:
            self.encryption_key = encryption_key
            self.cipher = AES.new(self.encryption_key, AES.MODE_ECB)

    # Connects client to router interface 1 and exchange/update arp tables from both side
    def handle_router_connection(self):
        self.client.connect(self.router)
        self.conn_list[
            self.routing_protocol.get_routing_table()["default"]["gateway"]
        ] = self.client

        hasReceivedIPAddress = False

        try:
            # Should there be a mac address broadcast at the start
            # self.arp_protocol.arp_broadcast(self.default_routing_table['default']['gateway'], self.node_mac, '0x00', self.conn_list)
            self.dhcp_protocol.discover(self.conn_list, self.node_mac, self.url)

            while True:
                data = self.client.recv(1024)
                data = data.decode("utf-8")

                if re.match(pattern["arp_response"], data):
                    self.handle_arp_response(data)
                    self.dhcp_protocol.discover(self.conn_list, self.node_mac)

                elif re.match(pattern["dhcp_offer"], data):
                    hasReceivedIPAddress = self.handle_dhcp_offer(data, self.client)
                    if not hasReceivedIPAddress:
                        break

                elif re.match(pattern["dhcp_acknowledgement"], data):
                    hasReceivedIPAddress = self.handle_dhcp_acknowledgement(data)
                    break

                else:
                    print(f"NONE, {data}")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router_interface} aborted.")
            # Need to clear assigned IP address value and send dhcp release to server

        except Exception as e:
            print(f"Unexpected error 2: {e}")

        # Connection is established and now ready to indefinitely listen for incoming packets from connection
        if hasReceivedIPAddress:
            threading.Thread(target=self.listen).start()

    def handle_arp_response(self, arp_response):
        # Handle adding to the ARP table
        match = re.match(pattern["arp_response"], arp_response)

        if match:
            arp_ip_address = match.group("ip_address")
            arp_mac_address = match.group("mac_address")

            print(
                f"Received ARP Response: {arp_ip_address}, {arp_mac_address}. Will update ARP table..."
            )
            self.arp_protocol.add_record(arp_ip_address, arp_mac_address)
            print(self.arp_protocol.get_arp_table())

    def handle_dhcp_offer(self, dhcp_offer, conn):
        print("Received DHCP Offer...")
        match = re.match(pattern["dhcp_offer"], dhcp_offer)

        if match:
            ip_address_offered = match.group(1)
            if ip_address_offered != "null":
                print(f"Offered IP Address: {ip_address_offered}. Sending DHCP Request")
                self.dhcp_protocol.request(conn, ip_address_offered)
                return True
            else:
                print("No IP address available... Connection failed.")
                return False

    def handle_dhcp_acknowledgement(self, dhcp_acknowledgement):
        print("Received DHCP Acknowledgement...")
        match = re.match(pattern["dhcp_acknowledgement"], dhcp_acknowledgement)

        if match:
            ip_address_assigned = match.group(1)
            dns_ip_address = match.group(3)
            if ip_address_assigned != "null" and dns_ip_address != "null":
                print(
                    f"Assigning IP address: {ip_address_assigned}, DNS IP address: {dns_ip_address}"
                )
                self.node_ip = ip_address_assigned
                self.dns_ip_address = dns_ip_address
                return True
            else:
                print(
                    "IP address no longer available or DNS Server IP not received... Connection failed."
                )
                return False

    def handle_arp_request(self, arp_request, conn):
        print("Received a broadcast IP Address")
        # Figure out if the IP address that is being looked for is ours

        is_intended_receiver, ip_looked_for, sender_mac, sender_ip = (
            self.arp_protocol.verfiy_arp_request_destination(arp_request, self.node_ip)
        )
        if is_intended_receiver:
            print("ARP Request is meant for me")
            # Reply the client who sent the ARP Request
            arp_response = f"ARP Response|{ip_looked_for} is at {self.node_mac}"
            conn.send(bytes(arp_response, "utf-8"))
            print("Sent out ARP Response")

            # Update ARP table to store ARP Request
            print("Updating ARP Table")
            self.arp_protocol.add_record(sender_ip, sender_mac)

            print("\nUPDATED ARP TABLE: ")
            print(self.arp_protocol.get_arp_table())
        else:
            print("Dropping ARP request")

    def handle_ip_packet(self, packet_str):
        packet = datagram_initialization(packet_str)

        src_ip = packet["src"]

        if self.has_firewall and not self.firewall.is_allowed_incoming(src_ip):
            print(f"Packet from {src_ip} filtered and dropped by firewall.")

        # If dest in packet matches router address, router is intended recipient
        if packet["dest"] == self.node_ip:
            # print(
            #     f"IP Packet received. Protocol is: {packet['protocol']}. Payload is: {packet['data']}."
            # )
            protocol = packet["protocol"]
            if protocol == "kill":
                print("Carrying out kill protocol")
            elif protocol == "ping":
                print("Carrying out ping protol")
            elif protocol == "dns_response":
                packet_data = packet["data"]
                regex = r"^DNS_Response\|url:(.*),ip:(0x[a-fA-F0-9]+)$"
                match = re.match(regex, packet_data)
                url = match.group(1)
                ip = match.group(2)

                self.dns_protocol.add_dns_record(url, ip)
            elif protocol == "dns_update_success":
                print("\nSUCCESSFUL DNS REGISTRATION. NOW YOU CAN SEND DATA")
                threading.Thread(target=self.handle_input).start()
            else:
                print("Invalid protocol received")

        else:
            print("Not intended recipient of IP Packet. Drop IP Packet....")

    def handle_ethernet_frame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, or if broadcast ethernet, else forward based on IP packet
        if frame["dest"] == self.node_mac:
            # print(f"Ethernet Frame received: {frame}")

            # Process Ethernet frame and its IP packet if required
            if re.match(pattern["packet"], frame["data"]):
                # print("Extracting IP packet in payload...")
                self.handle_ip_packet(frame["data"])

            else:
                print(f"Payload is: {frame['data']}.")
        else:
            print(f"Not intended recipient. Will drop frame...")

    # Handles incoming connection
    def listen(self):
        print(f"Connection from {self.router}) established.")
        try:
            while True:
                received_message = self.client.recv(1024)
                received_message = received_message.decode("utf-8")
                # print("\nMessage: " + received_message)

                if re.match(pattern["arp_response"], received_message):
                    self.handle_arp_response(received_message)

                # Handling a ARP broadcast message received
                elif re.match(pattern["arp_request"], received_message):
                    self.handle_arp_request(received_message, self.client)

                elif re.match(pattern["frame"], received_message):
                    self.handle_ethernet_frame(received_message)

                # else:
                #     print("Recieved invalid payload. Dropping...")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router} closed.")
            # Need to clear assigned IP address value and send dhcp release to server

        except Exception as e:
            print(f"Unexpected error 1: {e}")

    def encrypt(self, plaintext):
        # Pad plaintext to be a multiple of 16 bytes
        padded_plaintext = plaintext + ' ' * (16 - len(plaintext) % 16)
        encrypted = self.cipher.encrypt(padded_plaintext)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_text):
        decoded_encrypted_text = base64.b64decode(encrypted_text)
        decrypted = self.cipher.decrypt(decoded_encrypted_text).decode('utf-8')
        return decrypted.strip()  # Remove padding

    def toggle_vpn(self):
        self.vpn_enabled = not self.vpn_enabled

        if self.vpn_enabled:
            print("Activating VPN...")
            print(f"New IP address at: {self.vpn_ip_address}")
        else:
            print("Deactivating VPN...")
            print(f"Reverting IP address to: {self.node_ip}")

    def send_DNS_request(self, payload, dest_url):
        route_ip = self.send_ARP_request(payload)

        max_dns_request_retries = 3
        dns_request_attempt = 1
        while (
                not self.dns_protocol.lookup_dns_cache(dest_url)
                and dns_request_attempt <= max_dns_request_retries
        ):
            print(
                "DNS Attempt "
                + str(dns_request_attempt)
                + ": No DNS IP found in DNS Cache so sending out DNS Request"
            )
            dns_request_ip_datagram = datagram_initialization(payload)
            print("ARPPP")
            print(self.arp_protocol.get_arp_table())
            ethernet_frame = EthernetFrame()
            dest_mac = self.arp_protocol.lookup_arp_table(route_ip)

            ethernet_frame.create(self.node_mac, dest_mac, dns_request_ip_datagram)
            ethernet_payload = ethernet_frame.convert_to_valid_payload()
            self.client.send(bytes(ethernet_payload, "utf-8"))
            print("\nPayload has been sent")

            time.sleep(3)
            dns_request_attempt += 1

        if self.dns_protocol.lookup_dns_cache(dest_url):
            print("Found in DNS Cache")
            dest_ip = self.dns_protocol.get_dns_cache()[dest_url]

        return dest_ip

    def send_ARP_request(self, payload):
        ip_datagram = datagram_initialization(payload)
        destination_ip = ip_datagram["dest"]

        route_ip = self.routing_protocol.getNextHopIP(destination_ip)
        if route_ip == None or route_ip == "default":
            route_ip = hex(
                int(
                    self.routing_protocol.get_routing_table()["default"]["gateway"],
                    16,
                )
            )
        max_arp_retries = 3
        arp_request_attempt = 1

        while (
                not self.arp_protocol.lookup_arp_table(route_ip)
                and arp_request_attempt <= max_arp_retries
        ):
            print(
                "ARP Attempt "
                + str(arp_request_attempt)
                + ": No MAC address found in ARP Table so sending out broadcast"
            )
            # Create ARP Request Frame
            self.arp_protocol.arp_broadcast(
                route_ip, self.node_mac, self.node_ip, self.conn_list
            )

            time.sleep(2)
            arp_request_attempt += 1

        return route_ip

    # Gets ethernet data payload to be sent
    def handle_input(self):
        while True:
            command_input = input()
            payload = None
            if command_input == "firewall" and self.has_firewall:
                self.firewall.handle_firewall_input()
            elif command_input == "spoof" and self.is_malicious:
                spoof_ip = input("Enter IP address to spoof: ")
                dest_ip = input("Enter destination address: ")
                payload = f"{{src:{spoof_ip},dest:{dest_ip},protocol:kill,dataLength:5,data:thisisfromspoofedIP}}"
            elif command_input == "sniff" and self.is_malicious:
                self.attacks.handle_sniffer_input()
            elif command_input == "whoami":
                print(f"Node's IP address is {self.node_ip}")
                print(f"Node's MAC is {self.node_mac}")
            elif command_input == "show arp":
                print(self.arp_protocol.get_arp_table())
            elif command_input == 'toggle vpn':
                self.toggle_vpn()
            elif command_input == "send data":
                dest_url = input("Who do you want to send it to? (URL): ")
                protocol = input("Pick one protocol (kill/ ping): ")
                data = input("Enter the data that you want to enter: ")

                if self.dns_protocol.lookup_dns_cache(dest_url):
                    print("Found in DNS Cache")
                    dest_ip = self.dns_protocol.get_dns_cache()[dest_url]
                    payload = f"{{src:{self.node_ip},dest:{dest_ip},protocol:{protocol},dataLength:{len(data)},data:{data}}}"

                else:
                    print("Need to find DNS record")
                    dns_data = "DNS_Request|url:" + dest_url
                    payload = f"{{src:{self.node_ip},dest:{self.dns_ip_address},protocol:dns_request,dataLength:{len(dns_data)},data:{dns_data}}}"

            else:
                print("INVALID COMMAND")
                print_brk()
                print("Valid commands")
                if self.has_firewall:
                    print("- firewall \t Configure firewall")
                if self.is_malicious:
                    print("- spoof \t Send spoofed IP packet")
                    print("sniff \t Sniff IP packets within a network")
                print("- whoami \t Show own MAC and IP address")
                print("- show arp table \t Show ARP table")
                print("- send data \t Send data to another node or router")
                print_brk()

            if payload:
                # Getting Destination IP
                if payload.split("|")[0] == "requestconnection":
                    self.client.send(bytes(payload, "utf-8"))
                elif payload.split("|")[0] == "Gratuitous ARP":
                    self.arp_protocol.gratitous_arp(payload, self.conn_list)
                else:
                    ip_datagram = datagram_initialization(payload)
                    if ip_datagram["protocol"] == "dns_request":
                        dest_ip = self.send_DNS_request(payload, dest_url)
                        payload = f"{{src:{self.node_ip},dest:{dest_ip},protocol:{protocol},dataLength:{len(data)},data:{data}}}"
                        ip_datagram = datagram_initialization(payload)

                    if self.has_firewall and not self.firewall.is_allowed_outgoing(dest_ip):
                        print(f"{dest_ip} is not included in outgoing list")
                        break

                    if self.vpn_enabled:
                        json_string_ip_datagram = dict_to_json_string(ip_datagram)
                        encrypted_ip_datagram = self.encrypt(json_string_ip_datagram)
                        src_ip = self.vpn_ip_address
                        destination_ip = self.vpn_gateway
                        protocol = ip_datagram["protocol"]
                        length = len(encrypted_ip_datagram)
                        new_payload = f"{{src:{src_ip},dest:{destination_ip},protocol:{protocol},dataLength:{length},data:{encrypted_ip_datagram}}}"
                        new_ip_datagram = datagram_initialization(new_payload)

                        ip_datagram = new_ip_datagram

                    route_ip = self.send_ARP_request(payload)
                    if self.arp_protocol.lookup_arp_table(route_ip):
                        print("\nMAC Address Found and sending payload")

                        # Package into a ethernet frame
                        dest_mac = self.arp_protocol.lookup_arp_table(route_ip)
                        ethernet_frame = EthernetFrame()

                        ethernet_frame.create(self.node_mac, dest_mac, ip_datagram)
                        ethernet_payload = ethernet_frame.convert_to_valid_payload()
                        self.client.send(bytes(ethernet_payload, "utf-8"))
                        print("\nPayload has been sent")
                    else:
                        print("ARP Request failed to get a MAC address")

        # Maybe need to add the logic for other connecting with this interface?

    def start(self):
        try:
            self.handle_router_connection()
            # self.handle_input()

        except KeyboardInterrupt:
            self.client.close()
