import socket
import threading
import time
from config import *
from classes.rip import RIP_Protocol
from classes.arp import ARP_Protocol
from classes.dhcpClient import DHCP_Client_Protocol
from classes.ethernet_frame import EthernetFrame
from classes.firewall import Firewall
from classes.attacks import Attacks
from util import datagram_initialization, pattern
import re
import os

def print_brk():
    print("-" * os.get_terminal_size().columns)

class Node:
    node_mac = None
    node_ip = None
    router = None
    conn_list = None
    has_firewall = False
    is_malicious = False

    def __init__(
        self,
        node_mac,
        default_routing_table: dict = None,
        default_routing_port = None,
        has_firewall: bool = False,
        is_malicious: bool = False,
    ):
        self.node_mac = node_mac

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}
        self.has_firewall = has_firewall
        if has_firewall:
            self.firewall = Firewall()

        self.is_malicious = is_malicious
        if is_malicious:
            self.attacks = Attacks()

        self.routing_protocol = RIP_Protocol(default_routing_table)
        self.dhcp_protocol = DHCP_Client_Protocol()
        self.arp_protocol = ARP_Protocol()
        # self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.router = (HOST, default_routing_port)

    # Connects client to router interface 1 and exchange/update arp tables from both side
    def handle_router_connection(self, interfacePort, interfaceIP):
        interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        interface_socket.connect((HOST, interfacePort))
        self.conn_list[interfaceIP] = interface_socket
        conn_ip_address = False

        try:
            # Should there be a mac address broadcast at the start
            # self.arp_protocol.arp_broadcast(self.default_routing_table['default']['gateway'], self.node_mac, '0x00', self.conn_list)
            self.dhcp_protocol.discover(self.conn_list, self.node_mac)

            while True:
                data = interface_socket.recv(1024)
                data = data.decode("utf-8")

                if re.match(pattern['arp_response'], data):
                    self.handle_arp_response(data)
                    self.dhcp_protocol.discover(self.conn_list, self.node_mac)

                elif re.match(pattern['dhcp_offer'], data):
                    conn_ip_address = self.handle_dhcp_offer(data, interface_socket)
                    if not conn_ip_address:
                        break

                elif re.match(pattern['dhcp_acknowledgement'], data):
                    conn_ip_address = self.handle_dhcp_acknowledgement(data)
                    break

                else:
                    print(f"NONE, {data}")

            routing_table = self.routing_protocol.get_routing_table()
            if 'default' in routing_table and interfaceIP != routing_table['default']['gateway']:
                self.routing_protocol.addEntry(interfaceIP, interfaceIP, '0xF0', 1)

            else:
                self.routing_protocol.addEntry(interfaceIP, interfaceIP, '0xF0', 1, True)

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {interfaceIP} aborted.")
            self.node_ip = None
            self.dhcp_protocol.release(interface_socket, conn_ip_address)

        except Exception as e:
            print(f"Unexpected error 2: {e}")

        # Connection is established and now ready to indefinitely listen for incoming packets from connection
        if conn_ip_address:
            threading.Thread(target=self.listen, args=(self.conn_list[interfaceIP], interfaceIP)).start()

    def handle_arp_response(self, arp_response):
        # Handle adding to the ARP table
        match = re.match(pattern['arp_response'], arp_response)

        if match:
            arp_ip_address = match.group('ip_address')
            arp_mac_address = match.group('mac_address')

            print(f"Received ARP Response: {arp_ip_address}, {arp_mac_address}. Will update ARP table...")
            self.arp_protocol.add_record(arp_ip_address, arp_mac_address)
            print(self.arp_protocol.get_arp_table())

    def handle_dhcp_offer(self, dhcp_offer, conn):
        print("Received DHCP Offer...")
        match = re.match(pattern['dhcp_offer'], dhcp_offer)

        if match:
            ip_address_offered = match.group(1)
            if ip_address_offered != "null":
                print(f"Offered IP Address: {ip_address_offered}. Sending DHCP Request")
                self.dhcp_protocol.request(conn, ip_address_offered)
                return ip_address_offered
            else:
                print("No IP address available... Connection failed.")
                return False

    def handle_dhcp_acknowledgement(self, dhcp_acknowledgement):
        print("Received DHCP Acknowledgement...")
        match = re.match(pattern['dhcp_acknowledgement'], dhcp_acknowledgement)

        if match:
            ip_address_assigned = match.group(1)
            if ip_address_assigned != "null":
                print(f"Assigning IP address: {ip_address_assigned}")
                self.node_ip = ip_address_assigned
                return ip_address_assigned
            else:
                print("IP address no longer available... Connection failed.")
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

        # If dest in packet matches router address, router is intended recipient
        if packet["dest"] == self.node_ip:
            print(
                f"IP Packet received. Protocol is: {packet['protocol']}. Payload is: {packet['data']}."
            )
            protocol = packet['protocol']
            if protocol == 'kill':
                print("Carrying out kill protocol")
            elif protocol == 'ping':
                print("Carrying out ping protol")
            else:
                print("Invalid protocol received")

        else:
            print("Not intended recipient of IP Packet. Drop IP Packet....")
        

    def handle_ethernet_frame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, or if broadcast ethernet, else forward based on IP packet
        if frame["dest"] == self.node_mac:
            print(f"Ethernet Frame received: {frame}")

            # Process Ethernet frame and its IP packet if required
            if re.match(pattern['packet'], frame["data"]):
                print("Extracting IP packet in payload...")
                self.handle_ip_packet(frame["data"])

            else:
                print(f"Payload is: {frame['data']}.")
        else:
            print(f"Not intended recipient. Will drop frame...")

    # Handles incoming connection
    def listen(self, conn, listenedIP):
        print(f"Connection from {self.router}) established.")
        try:
            while True:
                received_message = conn.recv(1024)
                received_message = received_message.decode("utf-8")
                # print("\nMessage: " + received_message)

                if re.match(pattern['arp_response'], received_message):
                    self.handle_arp_response(received_message)

                # Handling a ARP broadcast message received
                elif re.match(pattern['arp_request'], received_message):
                    self.handle_arp_request(received_message, conn)

                elif re.match(pattern['frame'], received_message):
                    self.handle_ethernet_frame(received_message)
                # else:
                #     print("Recieved invalid payload. Dropping...")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router} closed.")
            self.node_ip = None
            self.dhcp_protocol.release(conn, listenedIP)


        except Exception as e:
            print(f"Unexpected error 1: {e}")

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
            elif command_input == 'send data':
                dest_ip = input("Who do you want to send it to? (IP address): ")
                protocol = input("Pick one protocol (kill/ ping): ")
                data = input("Enter the data that you want to enter: ")

                payload = f"{{src:{self.node_ip},dest:{dest_ip},protocol:{protocol},dataLength:{len(data)},data:{data}}}"
                # payload = command_input
            elif command_input == "routing":
                print(self.routing_protocol.get_routing_table())
            elif command_input == "connect":
                print("Enter Router Port: ")
                routerPort = input()
                print("Enter Router IP: ")
                routerIP = input()
                self.handle_router_connection(int(routerPort), routerIP)
            else:
                print('INVALID COMMAND')
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
                # if payload.split("|")[0] == "requestconnection":
                #     self.router.send(bytes(payload, "utf-8"))
                if payload.split("|")[0] == "Gratuitous ARP":
                    self.arp_protocol.gratitous_arp(payload, self.conn_list)
                else:
                    ip_datagram = datagram_initialization(payload)
                    destination_ip = ip_datagram["dest"]

                    route_ip = self.rip_protocol.getNextHopIP(destination_ip)
                    if route_ip == None:
                        if 'default' in self.rip_protocol.get_routing_table():
                            route_ip = self.rip_protocol.get_routing_table()['default']['gateway']

                        else:
                            print(f"No routing can be found for the following IP address: {destination_ip}. Packet will be dropped.")
                            return

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
                        print("ROUTE IP:", route_ip)
                        self.arp_protocol.arp_broadcast(
                            route_ip, self.node_mac, self.node_ip, self.conn_list
                        )

                        time.sleep(2)
                        arp_request_attempt += 1

                    if self.arp_protocol.lookup_arp_table(route_ip):
                        print("\nMAC Address Found and sending payload")

                        # Package into a ethernet frame
                        dest_mac = self.arp_protocol.lookup_arp_table(route_ip)
                        ethernet_frame = EthernetFrame()

                        ethernet_frame.create(self.node_mac, dest_mac, ip_datagram)
                        ethernet_payload = ethernet_frame.convert_to_valid_payload()
                        self.conn_list[route_ip].send(bytes(ethernet_payload, "utf-8"))
                        print("\nPayload has been sent")
                    else:
                        print("ARP Request failed to get a MAC address")

        # Maybe need to add the logic for other connecting with this interface?

    def start(self):
        try:
            self.handle_router_connection(self.router[1], self.routing_protocol.get_routing_table()['default']['gateway'])
            self.handle_input()

        except KeyboardInterrupt:
            for ip in list(self.conn_list.keys()):
                self.conn_list[ip].close()
                del self.conn_list[ip]
