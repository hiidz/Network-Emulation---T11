import socket
import threading
import time
from config import *
from classes.arp import ARP_Protocol
from classes.dhcpClient import DHCP_Client_Protocol
from classes.ethernet_frame import EthernetFrame
from classes.firewall import Firewall
from classes.attacks import Attacks
from util import datagram_initialization, arp_request_pattern, arp_response_pattern, dhcp_offer_pattern, dhcp_acknowledgement_pattern
import re

class Node:
    node_mac = None
    node_ip = None
    router = None
    conn_list = None
    default_routing_table = None
    router_interface_ip = None
    router_interface_port = None
    has_firewall = False
    is_malicious = False

    def __init__(
        self,
        node_mac,
        router_interface_ip,
        router_interface_port,
        default_routing_table: dict = None,
        has_firewall: bool = False,
        is_malicious: bool = False,
    ):
        self.node_mac = node_mac
        self.default_routing_table = default_routing_table
        self.router_interface_ip = router_interface_ip
        self.router_interface_port = router_interface_port

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}
        self.has_firewall = has_firewall
        if has_firewall:
            self.firewall = Firewall()

        self.is_malicious = is_malicious
        if is_malicious:
            self.attacks = Attacks()

        self.dhcp_protocol = DHCP_Client_Protocol()
        self.arp_protocol = ARP_Protocol()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.router = (HOST, router_interface_port)

        print(self.router)

    # Connects client to router interface 1 and exchange/update arp tables from both side
    def handle_router_connection(self):
        self.client.connect(self.router)
        self.conn_list[self.router_interface_ip] = self.client
        hasReceivedIPAddress = False

        try:
            self.arp_protocol.arp_broadcast(self.default_routing_table['default']['gateway'], self.node_mac, '0x00', self.conn_list)
            while True:
                data = self.client.recv(1024)
                data = data.decode("utf-8")

                if re.match(arp_response_pattern, data):
                    self.handle_arp_response(data)
                    self.dhcp_protocol.discover(self.conn_list, self.node_mac)

                elif re.match(dhcp_offer_pattern, data):
                    hasReceivedIPAddress = self.handle_dhcp_offer(data, self.client)
                    if not hasReceivedIPAddress:
                        break

                elif re.match(dhcp_acknowledgement_pattern, data):
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

        match = re.match(arp_response_pattern, arp_response)
        arp_ip_address = match.group(1)
        arp_mac_address = match.group(2)

        print("ARP IP Address:", arp_ip_address)
        print("ARP Mac Address:", arp_mac_address)
        self.arp_protocol.add_record(arp_ip_address, arp_mac_address)

        print("\nUPDATED ARP TABLE: ")
        print(self.arp_protocol.get_arp_table())

    def handle_dhcp_offer(self, dhcp_offer, conn):
        ip_address_offered = re.match(dhcp_offer_pattern, dhcp_offer).group(1)
        if ip_address_offered != "null":
            self.dhcp_protocol.request(conn, ip_address_offered)
            return True
        else:
            print("No IP address available... Connection failed.")
            return False

    def handle_dhcp_acknowledgement(self, dhcp_acknowledgement):
        ip_address_assigned = re.match(dhcp_acknowledgement_pattern, dhcp_acknowledgement).group(1)

        if ip_address_assigned != "null":
            self.node_ip = ip_address_assigned
            return True
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

    # Handles incoming connection
    def listen(self):
        print(f"Connection from {self.router}) established.")
        try:
            while True:
                received_message = self.client.recv(1024)
                received_message = received_message.decode("utf-8")
                print("\nMessage: " + received_message)

                if re.match(arp_response_pattern, received_message):
                    self.handle_arp_response(received_message)

                # Handling a ARP broadcast message received
                elif re.match(arp_request_pattern, received_message):
                    self.handle_arp_request(received_message, self.client)

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router} closed.")
            # Need to clear assigned IP address value and send dhcp release to server

        except Exception as e:
            print(f"Unexpected error 1: {e}")

    # Gets ethernet data payload to be sent
    def handle_input(self):
        while True:
            command_input = input()
            payload = None
            if command_input == "firewall":
                self.firewall.handle_firewall_input()
            elif command_input == "spoof":
                spoof_ip = input("Enter IP address to spoof: ")
                dest_ip = input("Enter destination address: ")
                payload = f"{{src:{spoof_ip},dest:{dest_ip},protocol:kill,dataLength:5,data:thisisfromspoofedIP}}"
            elif command_input == "sniff":
                self.attacks.handle_sniffer_input()
            elif command_input == "whoami":
                print(f"Node's IP address is {self.node_ip}")
                print(f"Node's MAC is {self.node_mac}")
            elif command_input == "arp":
                print(self.arp_protocol.get_arp_table())
            else:
                payload = command_input
            if payload:
                # Getting Destination IP
                if payload.split("|")[0] == "request_interface_connection":
                    self.client.send(bytes(payload, "utf-8"))
                elif payload.split("|")[0] == "Gratuitous ARP":
                    self.arp_protocol.gratitous_arp(payload, self.conn_list)
                else:
                    ip_datagram = datagram_initialization(payload)
                    destination_ip = ip_datagram["dest"]

                    # Figure out route to take in the routing table but is hardcoded such that if it is found it will take that and if not use the router
                    if destination_ip in self.default_routing_table.keys():
                        route_to_take = self.default_routing_table[destination_ip]
                    else:
                        route_to_take = self.default_routing_table["default"]

                    route_ip = route_to_take["gateway"]

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

                    if self.arp_protocol.lookup_arp_table(route_ip):
                        print("\nMAC Address Found and sending payload")

                        # Package into a ethernet frame
                        dest_mac = self.arp_protocol.lookup_arp_table(route_ip)
                        ethernet_frame = EthernetFrame()

                        ethernet_frame.create(self.node_mac, dest_mac, ip_datagram)
                        ethernet_payload = ethernet_frame.convert_to_valid_payload()
                        self.client.send(bytes(ethernet_payload, "utf-8"))
                        print(self.client)
                        print("\nPayload has been sent")
                    else:
                        print("ARP Request failed to get a MAC address")

        # Maybe need to add the logic for other connecting with this interface?

    def start(self):
        try:
            self.handle_router_connection()
            self.handle_input()

        except KeyboardInterrupt:
            self.client.close()
