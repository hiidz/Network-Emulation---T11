import socket
import threading
from config import HOST
from classes.rip import RIP_Protocol
from classes.arp import ARP_Protocol
from classes.ethernet_frame import EthernetFrame
from classes.routing import Routing_Table
from classes.dhcpServer import DHCP_Server_Protocol
import re
# from util import datagram_initialization, frame_pattern, packet_pattern, arp_request_pattern, gratitous_arp_pattern, dhcp_discover_pattern, dhcp_request_pattern, dhcp_release_pattern, arp_response_pattern, rip_request_pattern, rip_response_pattern, rip_setup_pattern, rip_entry_pattern
from util import datagram_initialization, pattern
import time

class RouterInterface:
    interface_ip_address = None
    interface_mac = None
    interface_port = None
    interface_socket = None
    default_routing_port = None
    # connected_interface_port = None
    # connected_interface_ip = None
    subnet_mask = None
    conn_list = None
    arp_protocol = None
    dhcp_protocol = None
    threads = []

    def __init__(self, interface_ip_address, interface_mac, interface_port, subnet_mask, ip_address_available, default_routing_table: dict = {}, default_routing_port = None):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port
        self.subnet_mask = subnet_mask
        self.default_routing_port = default_routing_port

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}

        self.rip_protocol = RIP_Protocol(default_routing_table)
        self.arp_protocol = ARP_Protocol()
        self.dhcp_protocol = DHCP_Server_Protocol(ip_address_available, subnet_mask)

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))


    def isIPAddressInNetwork(self, ip):
        if int(ip, 16) & int(self.subnet_mask, 16) == int(self.interface_ip_address, 16) & int(self.subnet_mask, 16):
            return True
        else:
            return False


    def handleIPPacket(self, packet_str):
        packet = datagram_initialization(packet_str)

        # If dest in packet matches router address, router is intended recipient
        if packet['dest'] == self.interface_ip_address:
            print(f"IP Packet received. Protocol is: {packet['protocol']}. Payload is: {packet['data']}.")

            # Process IP packet if required
            # # if packet['protocol'] == 'kill/arp etc.':

        else:
            # Create EthernetFrame and route to next interface. (for future, can use BGP routing protocol to dynamically update routing table rather than static)
            destination_ip_address = packet['dest']
            print(f"Not intended recipient, will forward based on IP packet: {destination_ip_address}")

            # Check if IP address is in router network.
            if self.isIPAddressInNetwork(destination_ip_address):
                print("Destination IP address is in the network. Will transmit as per ARP table.")

                max_arp_retries = 3
                arp_request_attempt = 1

                # Send out ARP Request if MAC not found
                while not self.arp_protocol.lookup_arp_table(destination_ip_address) and arp_request_attempt <= max_arp_retries:
                    print("ARP Attempt " + str(arp_request_attempt) + ": No MAC address found in ARP Table so sending out broadcast")
                    # Create ARP Request Frame
                    self.arp_protocol.arp_broadcast(destination_ip_address, self.interface_mac, self.interface_ip_address, self.conn_list)

                    time.sleep(2)
                    arp_request_attempt += 1

                if self.arp_protocol.lookup_arp_table(destination_ip_address):
                    destination_mac = self.arp_protocol.lookup_arp_table(destination_ip_address)
                    # valid_packet = str(packet).replace("'", "").replace(" ", "")
                    ethernet_frame = EthernetFrame()

                    ethernet_frame.create(self.interface_mac, destination_mac, packet)
                    ethernet_payload = ethernet_frame.convert_to_valid_payload()
                    # frame_str = f"{{src:{self.interface_mac},dest:{destination_mac},dataLength:{len(packet['data'])},data:{valid_packet}}}"
                    print(f"New Frame to be sent: {ethernet_payload}")

                    print("Broadcasting to entire network...")
                    # Using unicast to entire network to emulate broadcast
                    for conn in self.conn_list.values():
                        conn.send(bytes(ethernet_payload, "utf-8"))

                else:
                    print("ARP Request failed to get a MAC address")

            # Use routing table to search for highest matching prefix interface
            else:
                print("Destination IP address is not in the network. Will look up routing table...")

                # Get next hop IP address
                next_hop_ip = self.rip_protocol.getNextHopIP(destination_ip_address)
                if next_hop_ip == None:
                    if 'default' in self.rip_protocol.get_routing_table():
                        next_hop_ip = self.rip_protocol.get_routing_table()['default']['gateway']

                    else:
                        print(f"No routing can be found for the following IP address: {destination_ip_address}. Packet will be dropped.")
                        return

                print(f"Routing found, transmitting to the following IP address: {next_hop_ip}")
                interface_conn_socket = self.conn_list[next_hop_ip]

                #Modify the ip packet back to a string to send out
                str_packet = str(packet)
                str_packet_valid = str_packet.replace(" ", "").replace("'", "")

                interface_conn_socket.send(bytes(str_packet_valid, "utf-8"))
                print(f"IP Packet sent to the interface at {next_hop_ip}")


    def handleEthernetFrame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, or if broadcast ethernet, else forward based on IP packet
        if frame['dest'] == self.interface_mac:
            print(f"Ethernet Frame received: {frame}")

            # Process Ethernet frame and its IP packet if required
            if re.match(pattern['packet'], frame['data']):
                print("Extracting IP packet in payload...")
                self.handleIPPacket(frame['data'])

            else:
                print(f"Payload is: {frame['data']}.")

        elif frame['dest'] == "FF":
            # Broadcast to all sockets in the network (excl. connected interfaces if any)
            print("Broadcast Frame received, will broadcast to all device in the network")
            for ip, conn in self.conn_list.items():
                if self.isIPAddressInNetwork(ip):
                    conn.send(bytes(frame_str, "utf-8"))
            self.handleIPPacket(frame['data'])

        else:
            print(f"Invalid MAC address. Not intended recipient. Will drop frame...")


    def handle_arp_request(self, arp_request, conn):
        print("Received ARP Request")

        # Figure out if the IP address that is being looked for is ours
        is_intended_receiver, ip_looked_for, sender_mac, sender_ip = self.arp_protocol.verfiy_arp_request_destination(arp_request, self.interface_ip_address)
        if is_intended_receiver:
            print("ARP Request is meant for me")
            # Reply the client who sent the ARP Request
            arp_response = f'ARP Response|{ip_looked_for} is at {self.interface_mac}'
            conn.send(bytes(arp_response, "utf-8"))
            print("Sent out ARP Response")

            # Update ARP table to store ARP Request
            # ARP Request is sent before DHCP. So some clients might sent ARP request without valid IP
            if sender_ip != '0x00':
                print("Updating ARP Table")
                self.arp_protocol.add_record(sender_ip, sender_mac)

                print('\nUPDATED ARP TABLE: ')
                print(self.arp_protocol.get_arp_table())

        else:
            print("Dropping ARP request. Not valid recipient.")
            return


    def handle_arp_response(self, arp_response):
        # Handle adding to the ARP table
        match = re.match(pattern['arp_response'], arp_response)

        if match:
            arp_ip_address = match.group('ip_address')
            arp_mac_address = match.group('mac_address')

            print(f"Received ARP Response: {arp_ip_address}, {arp_mac_address}. Will update ARP table...")
            self.arp_protocol.add_record(arp_ip_address, arp_mac_address)
            print(self.arp_protocol.get_arp_table())


    def handle_gratitous_arp(self, gratitous_arp):
        match = re.match(pattern['gratitous_arp'], gratitous_arp)

        if match:
            ip_address = match.group('ip_address')
            new_mac_address = match.group('mac_address')

            print(f"Received ARP Response: {ip_address}, {new_mac_address}. Will update ARP table...")
            self.arp_protocol.add_record(ip_address, new_mac_address)
            print(self.arp_protocol.get_arp_table())


    def handle_dhcp_discover(self, conn, dhcp_discover):
        print("Received DHCP Discover...")
        conn_ip_address = self.dhcp_protocol.offer(conn)
        return conn_ip_address


    def handle_dhcp_request(self, conn, dhcp_request):
        print("Received DHCP Request...")
        match = re.match(pattern['dhcp_request'], dhcp_request)

        if match:
            ip_address_requested = match.group(1)
            ip_address_assigned = self.dhcp_protocol.acknowledgement(conn, ip_address_requested)
            return ip_address_assigned


    def handle_dhcp_release(self, dhcp_release):
        print("Received DHCP Release...")
        match = re.match(pattern['dhcp_release'], dhcp_release)

        if match:
            ip_address = match.group(1)
            self.dhcp_protocol.release(ip_address)


    def handle_rip_request(self, conn):
        self.rip_protocol.response(conn, self.rip_protocol.get_routing_table())


    def handle_rip_response(self, rip_response, listenedIPAddress):
        routingtable_match = re.search(pattern['rip_response'], rip_response)
        routingtable_data = routingtable_match.group(1)

        matches = re.finditer(pattern['rip_entry'], routingtable_data)
        for match in matches:
            key = match.group('key')
            netmask = match.group('netmask')
            gateway = match.group('gateway')
            hop = int(match.group('hop'))

            routing_table = self.rip_protocol.get_routing_table()
            if key == 'default' and gateway != self.interface_ip_address:
                if gateway not in routing_table or (gateway in routing_table and routing_table[gateway]['hop'] > hop + 1):
                    self.rip_protocol.addEntry(gateway, listenedIPAddress, netmask, hop + 1)

            elif key != 'default' and key != self.interface_ip_address:
                if 'default' not in routing_table or routing_table['default']['gateway'] != key:
                    if key not in routing_table or (key in routing_table and routing_table[key]['hop'] > hop + 1):
                        self.rip_protocol.addEntry(key, listenedIPAddress, netmask, hop + 1)


    def handle_rip_setup(self, conn, rip_setup):
        match = re.match(pattern['rip_setup'], rip_setup)

        if match:
            subnet_mask_received = match.group(1)
            ip_address_received = match.group(2)

            self.rip_protocol.addEntry(ip_address_received, ip_address_received, subnet_mask_received, 1)
            self.rip_protocol.setup(conn, self.subnet_mask, self.interface_ip_address, False)

            return ip_address_received


    def listen(self, conn, address, listenedIPAddress, isListeningToRouter = False):
        print(f"Connection from {listenedIPAddress} ({address}) established.")
        self.conn_list[listenedIPAddress] = conn

        if isListeningToRouter:
            timer_thread = threading.Thread(target=self.handleRIPbroadcast)

            # Need to find better way to close thread upon Ctrl+C
            timer_thread.start()
            self.threads.append(timer_thread)

        try:
            while True:
                data = conn.recv(1024)
                data = data.decode()

                # Check if the datagram received matches either frame or packet regex pattern
                if re.match(pattern['frame'], data):
                    threading.Thread(target=self.handleEthernetFrame, args=(data,)).start()
                    # self.handleEthernetFrame(data)

                elif re.match(pattern['packet'], data):
                    threading.Thread(target=self.handleIPPacket, args=(data,)).start()
                    # self.handleIPPacket(data)

                elif re.match(pattern['arp_request'], data):
                    threading.Thread(target=self.handle_arp_request, args=(data, conn)).start()
                    # self.handle_arp_request(data, conn)

                elif re.match(pattern['gratitous_arp'], data):
                    threading.Thread(target=self.handle_gratitous_arp, args=(data,)).start()
                    # self.handle_gratitous_arp(data)

                elif re.match(pattern['arp_response'], data):
                    threading.Thread(target=self.handle_arp_response, args=(data,)).start()
                    # self.handle_arp_response(data)

                elif re.match(pattern['dhcp_discover'], data):
                    threading.Thread(target=self.handle_dhcp_discover, args=(conn, data)).start()
                    # self.handle_dhcp_discover(conn, data)

                elif re.match(pattern['dhcp_request'], data):
                    threading.Thread(target=self.handle_dhcp_request, args=(conn, data,)).start()
                    # self.handle_dhcp_request(conn, data)

                elif re.match(pattern['rip_request'], data):
                    threading.Thread(target=self.handle_rip_request, args=(conn)).start()

                elif re.search(pattern['rip_response'], data):
                    threading.Thread(target=self.handle_rip_response, args=(data, listenedIPAddress)).start()

                else:
                    print(f"Datagram from {listenedIPAddress}({address}) dropped, invalid format. Data received: {data}")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {listenedIPAddress}({address}) closed.")

            # Remove routing and release assigned IP assigned
            self.rip_protocol.removeEntry(listenedIPAddress)
            self.dhcp_protocol.release(listenedIPAddress)

        except Exception as e:
            print(f"Unexpected error 4: {e}")


    # Handle request for connection from other clients and/or interfaces
    def handle_connection(self, conn, address):
        conn_ip_address = False

        try:
            while True:
                data = conn.recv(1024)
                data = data.decode()

                if re.match(pattern['arp_request'], data):
                    self.handle_arp_request(data, conn)

                elif re.match(pattern['dhcp_discover'], data):
                    conn_ip_address = self.handle_dhcp_discover(conn, data)
                    if not conn_ip_address:
                        break

                elif re.match(pattern['dhcp_request'], data):
                    conn_ip_address = self.handle_dhcp_request(conn, data)
                    break

                elif re.match(pattern['rip_setup'], data):
                    conn_ip_address = self.handle_rip_setup(conn, data)
                    break

                else:
                    print(f"Datagram from {address} dropped, invalid format. Data received: {data}. ")

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            if conn_ip_address:
                self.listen(conn, address, conn_ip_address, True)

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Failure to setup connection with {address}.")

            # Undo ARP, Routing and DHCP changes
            self.arp_protocol.remove_record(conn_ip_address)
            self.rip_protocol.removeEntry(conn_ip_address)
            self.dhcp_protocol.release(conn_ip_address)

        except Exception as e:
            print(f"Unexpected error 6: {e}")


    def handleRIPbroadcast(self):
        try:
            while len(self.conn_list) != 0:
                time.sleep(5)
                for ip, sock in self.conn_list.items():
                    self.rip_protocol.response(sock, self.rip_protocol.get_routing_table())
        except:
            print("FAIL")


    # Initiate connection with another interface
    def setup_interface_connection(self, conn, address, listenedIp):
        conn_ip_address = None

        try:
            ip_address_received, subnet_mask_received = self.rip_protocol.setup(conn,self.subnet_mask, self.interface_ip_address, True)

            routing_table = self.rip_protocol.get_routing_table()
            if 'default' in routing_table and ip_address_received != routing_table['default']['gateway']:
                self.rip_protocol.addEntry(ip_address_received, ip_address_received, subnet_mask_received, 1)

            else:
                self.rip_protocol.addEntry(ip_address_received, ip_address_received, subnet_mask_received, 1, True)

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            self.listen(conn, address, listenedIp, True)

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Failure to setup interface connection with {address}.")

            # Remove routing
            self.rip_protocol.removeEntry(conn_ip_address)


    def multi_listen_handler(self):
        try:
            self.interface_socket.listen()

            while True:
                conn, address = self.interface_socket.accept()
                # self.conn_list.append(conn)

                # For each new connection, create a new thread to continue listening to that connection
                threading.Thread(target=self.handle_connection, args=(conn, address)).start()

        except OSError:
            print("Server socket has been closed...")

        except Exception as e:
            print(f"Unexpected error 3: {e}")


    def connectToInterface(self, interface_port, listenedIp):
        try:
            if listenedIp not in self.conn_list:
                connected_interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connected_interface_socket.connect((HOST, interface_port))
                self.conn_list[listenedIp] = connected_interface_socket
                threading.Thread(target=self.setup_interface_connection, args=(connected_interface_socket, (HOST, interface_port), listenedIp)).start()
            else:
                print("Connection already established...")

        except ConnectionRefusedError:
            print(f"Unable to connect to the connected interface with port: {interface_port}.")

        except Exception as e:
            print(f"Unexpected error 18 {e}")


    def handle_input(self):
        # Logic for receiving command from user input in CLI handled here
        while True:
            command_input = input()
            if command_input == "whoami":
                print(f"Routers IP address is {self.interface_ip_address}")
                print(f"Routers MAC is {self.interface_mac}")
            elif command_input == "arp":
                print(self.arp_protocol.get_arp_table())
            elif command_input == "routing":
                print(self.rip_protocol.get_routing_table())
            elif command_input == "dhcp":
                print(self.dhcp_protocol.get_dhcp_table())
            elif command_input == "man":
                print("whoami, arp, routing, dhcp, connect")
            elif command_input == "connect":
                print("Enter Router Port: ")
                routerPort = input()
                print("Enter Router IP: ")
                routerIP = input()
                self.connectToInterface(int(routerPort), routerIP)
            else:
                print("No such command. Try again")


    def start(self):
        # If interface connected to another interface, establish connection request
        print(self.rip_protocol.get_routing_table())
        if 'default' in self.rip_protocol.get_routing_table():
            self.connectToInterface(self.default_routing_port, self.rip_protocol.get_routing_table()['default']['gateway'])

        try:
            # A thread that will listen for new incoming connections
            threading.Thread(target = self.multi_listen_handler).start()
            self.handle_input()

        except KeyboardInterrupt:
            # Close any other connection, including clients and interfaces, if any
            for ip in list(self.conn_list.keys()):
                self.conn_list[ip].close()
                del self.conn_list[ip]

            # Close RIP broadcast timer thread. To be improved
            for thread in self.threads:
                thread.join()

            # Close router interface listening port
            self.interface_socket.close()

        except Exception as e:
            print(f"Unexpected error 1: {e}")
