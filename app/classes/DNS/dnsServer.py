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
from classes.DNS.dns import DNS_Protocol

from util import datagram_initialization, pattern
import re
import os


class DNSServer:
    dns_mac = None
    dns_ip = None
    router = None
    conn_list = None

    def __init__(
            self,
            dns_mac,
            dns_ip,
            default_routing_table: dict = None,
            default_routing_port=None,
            dns_table: dict = None,
    ):
        self.dns_mac = dns_mac
        self.dns_ip = dns_ip
        self.dns_table = dns_table
        print(default_routing_port)

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}

        self.routing_protocol = RIP_Protocol(default_routing_table)
        self.arp_protocol = ARP_Protocol()
        self.dns_protocol = DNS_Protocol()
        self.dns_ip_address = None
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.router = (HOST, default_routing_port)

    # Connects client to router interface 1 and exchange/update arp tables from both side
    def handle_router_connection(self):
        self.client.connect(self.router)
        self.client.send(bytes(f"DNS IP|{self.dns_ip}", "utf-8"))
        self.conn_list[
            self.routing_protocol.get_routing_table()["default"]["gateway"]
        ] = self.client

        try:
            threading.Thread(target=self.listen).start()

            while True:
                data = self.client.recv(1024)
                data = data.decode("utf-8")

                if re.match(pattern["arp_response"], data):
                    self.handle_arp_response(data)

                # Handling a ARP broadcast message received
                elif re.match(pattern["arp_request"], data):
                    threading.Thread(
                        target=self.handle_arp_request,
                        args=(data, self.client),
                    ).start()
                    print("I AM CONTINUING")
                    continue
                    # break

                elif re.match(pattern["frame"], data):
                    threading.Thread(
                        target=self.handle_ethernet_frame,
                        args=(data,),
                    ).start()

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router} aborted.")
            # Need to clear assigned IP address value and send dhcp release to server

        except Exception as e:
            print(f"Unexpected error 2: {e}")

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

    def handle_arp_request(self, arp_request, conn):
        print("Received a broadcast IP Address")
        # Figure out if the IP address that is being looked for is ours

        is_intended_receiver, ip_looked_for, sender_mac, sender_ip = (
            self.arp_protocol.verfiy_arp_request_destination(arp_request, self.dns_ip)
        )
        if is_intended_receiver:
            print("ARP Request is meant for me")
            # Reply the client who sent the ARP Request
            arp_response = f"ARP Response|{ip_looked_for} is at {self.dns_mac}"
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
        if packet["dest"] == self.dns_ip:
            print(
                f"IP Packet received. Protocol is: {packet['protocol']}. Payload is: {packet['data']}."
            )
            protocol = packet["protocol"]
            if protocol == "kill":
                print("Carrying out kill protocol")
            elif protocol == "ping":
                print("Carrying out ping protol")
            elif protocol == "dns_update":
                packet_data = packet["data"]
                regex = r"^DNS_UPDATE\|url:(.*),ip:(0x[a-fA-F0-9]+)$"
                match = re.match(regex, packet_data)
                url = match.group(1)
                ip = match.group(2)

                self.dns_protocol.add_dns_record(url, ip)

                print("\nUPDATED DNS CACHE: ")
                print(self.dns_protocol.get_dns_cache())

                print("Sending success response....")
                data = f"DNS Registration successful"
                payload = f"{{src:{self.dns_ip},dest:{ip},protocol:dns_update_success,dataLength:{len(data)},data:{data}}}"

                ip_datagram = datagram_initialization(payload)

                route_ip = self.routing_protocol.getNextHopIP(ip)
                if route_ip == None or route_ip == "default":
                    route_ip = hex(
                        int(
                            self.routing_protocol.get_routing_table()["default"][
                                "gateway"
                            ],
                            16,
                        )
                    )
                dest_mac = self.arp_protocol.lookup_arp_table(route_ip)
                print("\nMAC Address Found and sending payload")

                # Package into a ethernet frame
                ethernet_frame = EthernetFrame()

                ethernet_frame.create(self.dns_mac, dest_mac, ip_datagram)
                ethernet_payload = ethernet_frame.convert_to_valid_payload()
                self.client.send(bytes(ethernet_payload, "utf-8"))
                print("\nDNS Success has been sent")

            elif protocol == "dns_request":
                src_ip = packet["src"]
                packet_data = packet["data"]
                regex = r"^DNS_Request\|url:(.*)$"
                match = re.match(regex, packet_data)
                url = match.group(1)
                ip_address = self.dns_protocol.lookup_dns_cache(url)
                data = f"DNS_Response|url:{url},ip:{ip_address}"

                payload = f"{{src:{self.dns_ip},dest:{src_ip},protocol:dns_response,dataLength:{len(data)},data:{data}}}"

                ip_datagram = datagram_initialization(payload)

                route_ip = self.routing_protocol.getNextHopIP(src_ip)
                if route_ip == None or route_ip == "default":
                    route_ip = hex(
                        int(
                            self.routing_protocol.get_routing_table()["default"][
                                "gateway"
                            ],
                            16,
                        )
                    )
                dest_mac = self.arp_protocol.lookup_arp_table(route_ip)
                print("\nMAC Address Found and sending payload")

                # Package into a ethernet frame
                ethernet_frame = EthernetFrame()

                ethernet_frame.create(self.dns_mac, dest_mac, ip_datagram)
                ethernet_payload = ethernet_frame.convert_to_valid_payload()
                self.client.send(bytes(ethernet_payload, "utf-8"))
                print("\nDNS Response has been sent")

            elif protocol == "dns_response":
                packet_data = packet["data"]
                regex = r"^DNS Response\|url:(.*),ip:(0x[a-fA-F0-9]+)$"
                match = re.match(regex, packet_data)
                url = match.group(1)
                ip = match.group(2)

                self.dns_protocol.add_dns_record(url, ip)
            else:
                print("Invalid protocol received")

        else:
            print("Not intended recipient of IP Packet. Drop IP Packet....")

    def handle_ethernet_frame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, or if broadcast ethernet, else forward based on IP packet
        if frame["dest"] == self.dns_mac:
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
                    # self.handle_arp_response(received_message)
                    threading.Thread(
                        target=self.handle_arp_response, args=(received_message)
                    ).start()

                # Handling a ARP broadcast message received
                elif re.match(pattern["arp_request"], received_message):
                    # self.handle_arp_request(received_message, self.client)
                    threading.Thread(
                        target=self.handle_arp_request,
                        args=(received_message, self.client),
                    ).start()
                    print("I AM CONTINUING")
                    continue
                    # break

                elif re.match(pattern["frame"], received_message):
                    threading.Thread(
                        target=self.handle_ethernet_frame,
                        args=(received_message,),
                    ).start()
                    # self.handle_ethernet_frame(received_message)

                else:
                    print("Recieved invalid payload. Dropping...")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {self.router} closed.")
            # Need to clear assigned IP address value and send dhcp release to server

        except Exception as e:
            print(f"Unexpected error 1: {e}")

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
                route_ip, self.dns_mac, self.dns_ip, self.conn_list
            )

            time.sleep(2)
            arp_request_attempt += 1

        return route_ip

    def start(self):
        try:
            self.handle_router_connection()
            # self.handle_input()

        except KeyboardInterrupt:
            self.client.close()
