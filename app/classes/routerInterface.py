import socket
import threading
from config import HOST
from classes.arp import ARP_Protocol
from classes.routing import Routing_Table
from classes.dhcp import DHCP_Table
import re
from util import datagram_initialization, frame_pattern, packet_pattern, arp_request_pattern, gratitous_arp_pattern
import time

class RouterInterface:
    interface_ip_address = None
    interface_mac = None
    interface_port = None
    interface_socket = None
    connected_interface_port = None
    connected_interface_ip = None
    subnet_mask = None
    conn_list = None
    arp_protocol = None
    routing_table = None
    dhcp_table = None


    def __init__(self, interface_ip_address, interface_mac, interface_port, subnet_mask, ip_address_available, connected_interface_ip: str = None, connected_interface_port: int = None):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port
        self.connected_interface_port = connected_interface_port
        self.subnet_mask = subnet_mask
        self.connected_interface_ip = connected_interface_ip

        # List of all socket connections. Will be used to close all active connections upon exit
        self.conn_list = {}

        self.arp_protocol = ARP_Protocol()
        self.routing_table =Routing_Table()
        self.dhcp_table = DHCP_Table(ip_address_available)

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))


    def isIPAddressInNetwork(self, ip):
        # offset by 2 because IP address stirng starts with '0x'
        if ip[:2+self.subnet_mask] == self.interface_ip_address[:2+self.subnet_mask]:
            return True
        else:
            return False


    #Request connections
    #request_interface_connection|0x1A|1|client
    #request_interface_connection|0x2A|1|client
        

    # Test cases that we can use via client side:
    #       valid Gratuitous ARP
    #       Gratuitous ARP|0x11 is now at 3B

    #     valid IP packet
    #     - {src:0x1A,dest:0x11,protocol:kill,dataLength:5,data:iwanttokillyou!}
    #      - {src:0x1A,dest:0x2A,protocol:kill,dataLength:5,data:iwanttokillyou!}

    #     IP packet with invalid destination
    #     - {src:0x55,dest:0x66,protocol:kill,dataLength:5,data:iwanttokillyou!}

    #     valid ETH frame without IP packet
    #     - {src:n1,dest:R1,dataLength:5,data:thisIsNotAnIPPacket}

    #     valid ETH frame with valid IP packet (dest: router IP)
    #     - {src:n1,dest:R1,dataLength:5,data:{src:0x55,dest:0x11,protocol:kill,dataLength:5,data:iwanttokillyou!}}
        
    #     valid ETH frame with valid IP packet (dest: client IP)
    #     - {src:n1,dest:R1,dataLength:5,data:{src:0x55,dest:0x1A,protocol:kill,dataLength:5,data:iwanttokillyou!}}

    #     valid ETH frame with invalid IP packet destination
    #     - {src:n1,dest:R1,dataLength:5,data:{src:0x55,dest:0x66,protocol:kill,dataLength:5,data:iwanttokillyou!}}

    #     ETH frame with invalid destination
    #     - {src:n1,dest:R2,dataLength:5,data:ThisCanBeAnything}

    #     ETH broadcast with dest 'FF'
    #     - {src:n1,dest:FF,dataLength:5,data:{src:0x55,dest:0x11,protocol:arp,dataLength:5,data:ThisIsARPBroadcast!}}

    def configure_default_routing_table(self, ip_prefix, ip_address):
        self.routing_table.add_entry(ip_prefix, ip_address)


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

            max_arp_retries = 3
            arp_request_attempt = 1

            #Check if IP address is in router network.
            if self.isIPAddressInNetwork(destination_ip_address):
                print("Destination IP address is in the network. Will transmit as per ARP table.")

                #Send out ARP Request if MAC not found
                while not self.arp_protocol.lookup_arp_table(destination_ip_address) and arp_request_attempt <= max_arp_retries:
                    print("ARP Attempt " + str(arp_request_attempt) + ": No MAC address found in ARP Table so sending out broadcast")
                    #Create ARP Request Frame
                    self.arp_protocol.arp_broadcast(destination_ip_address, self.interface_mac, self.interface_ip_address, self.conn_list)

                    time.sleep(2)
                    arp_request_attempt += 1
                
                if self.arp_protocol.lookup_arp_table(destination_ip_address):
                    destination_mac = self.arp_protocol.lookup_arp_table(destination_ip_address)
                    valid_packet = str(packet).replace("'", "").replace(" ", "")
                    frame_str = f"{{src:{self.interface_mac},dest:{destination_mac},dataLength:{len(packet['data'])},data:{valid_packet}}}"
                    print(f"New Frame to be sent: {frame_str}")

                    #Find the socket connected to this IP and send
                    self.conn_list[destination_ip_address].send(bytes(frame_str, "utf-8"))
                    print(f'Frame sent to: {destination_ip_address}')
                else:
                    print("ARP Request failed to get a MAC address")

            # Use routing table to search for highest matching prefix interface
            else:
                print("Destination IP address is not in the network. Will look up routing table...")

                # Get next hop IP address
                next_hop_ip = self.routing_table.getNextHopIP(destination_ip_address)

                #Modify the ip packet back to a string to send out
                if next_hop_ip:
                    print(f"Routing found, transmitting to the following IP address: {next_hop_ip}")

                    while not self.arp_protocol.lookup_arp_table(next_hop_ip) and arp_request_attempt <= max_arp_retries:
                        print("ARP Attempt " + str(arp_request_attempt) + ": No MAC address found in ARP Table so sending out broadcast")
                        #Create ARP Request Frame
                        self.arp_protocol.arp_broadcast(next_hop_ip, self.interface_mac, self.interface_ip_address, self.conn_list)

                        time.sleep(2)
                        arp_request_attempt += 1
                    
                    if self.arp_protocol.lookup_arp_table(next_hop_ip):
                        destination_mac = self.arp_protocol.lookup_arp_table(destination_ip_address)
                        valid_packet = str(packet).replace("'", "").replace(" ", "")
                        frame_str = f"{{src:{self.interface_mac},dest:{destination_mac},dataLength:{len(packet['data'])},data:{valid_packet}}}"
                        print(f"New Frame to be sent: {frame_str}")

                        #Find the socket connected to this IP and send
                        self.conn_list[destination_ip_address].send(bytes(frame_str, "utf-8"))
                        print(f'Frame sent to: {destination_ip_address}')

                    else:
                        print("ARP Request failed to get a MAC address")

                else:
                    # Maybe send msg back to client that no routing is found
                    print(f"No routing can be found for the following IP address: {destination_ip_address}. Packet will be dropped.")
                    return

            # # Broadcast to all sockets (incl. connected interfaces if any)
            # for arp_value in self.arp_protocol.get_arp_table().values():
            #     print(f"Broadcasting to: {arp_value['mac']}")
            #     arp_value['socket'].send(bytes(frame_str, "utf-8"))


    def handleEthernetFrame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, or if broadcast ethernet, else forward based on IP packet
        if frame['dest'] == self.interface_mac:
            print(f"Ethernet Frame received: {frame}")

            # Process Ethernet frame and its IP packet if required
            if re.match(packet_pattern, frame['data']):
                print("Extracting IP packet in payload...")
                self.handleIPPacket(frame['data'])

            else:
                print(f"Payload is: {frame['data']}.")

        elif frame['dest'] == "FF":
            # Broadcast to all sockets in the network (excl. connected interfaces if any)
            print("Broadcast Frame received, will broadcast to all device in the network")
            for arp_key, arp_value in self.arp_protocol.get_arp_table().items():
                if self.isIPAddressInNetwork(arp_key):
                    arp_value['socket'].send(bytes(frame_str, "utf-8"))

        else:
            print(f"Invalid MAC address. Not intended recipient. Will drop frame...")


    def handle_arp_request(self, arp_request, conn):
        print("Received a broadcast IP Address")
        #Figure out if the IP address that is being looked for is ours

        is_intended_receiver, ip_looked_for, sender_ip, sender_mac = self.arp_protocol.verfiy_arp_request_destination(arp_request, self.interface_ip_address)
        if is_intended_receiver:
            print("ARP Request is meant for me")
            #Reply the client who sent the ARP Request
            arp_response = f'ARP Response|{ip_looked_for} is at {self.interface_mac}'
            conn.send(bytes(arp_response, "utf-8"))
            print("Sent out ARP Response")

            #Update ARP table to store ARP Request
            print("Updating ARP Table")
            self.arp_protocol.add_record(sender_ip, sender_mac)

            print('\nUPDATED ARP TABLE: ')
            print(self.arp_protocol.get_arp_table())
        else:
            print("Dropping ARP request")
            return


    def handle_arp_response(self, arp_response):
        #Handle adding to the ARP table
        payload = arp_response.split('|')[1]
        pattern = r"(0x\w{2}) is at (\w{2})"
        match = re.match(pattern, payload)

        if match:
            arp_ip_address = match.group(1)
            arp_mac_address = match.group(2)

            print("ARP IP Address:", arp_ip_address)
            print("ARP Mac Address:", arp_mac_address)
            self.arp_protocol.add_record(arp_ip_address, arp_mac_address)

            print('\nUPDATED ARP TABLE: ')
            print(self.arp_protocol.get_arp_table())

        else:
            print("No match found.")
            return False


    def handle_gratitous_arp(self, gratitous_arp):
        payload = gratitous_arp.split('|')[1]
        pattern = r"(0x\w{2}) is now at (\w{2})"
        match = re.match(pattern, payload)

        if match:
            ip_address = match.group(1)
            new_mac_address = match.group(2)

            print("IP Address:", ip_address)
            print("New Mac Address:", new_mac_address)
            self.arp_protocol.add_record(ip_address, new_mac_address)

            print('\nUPDATED ARP TABLE: ')
            print(self.arp_protocol.get_arp_table())

        else:
            print("No match found.")
            return False


    def listen(self, conn, address, listenedIPAddress):
        print(f"Connection from {listenedIPAddress} ({address}) established.")
        self.conn_list[listenedIPAddress] = conn

        try:
            while True:
                data = conn.recv(1024)
                data = data.decode()

                # Check if the datagram received matches either frame or packet regex pattern
                if re.match(frame_pattern, data):
                    self.handleEthernetFrame(data)

                elif re.match(packet_pattern, data):
                    self.handleIPPacket(data)
                
                elif re.match(arp_request_pattern, data):
                    self.handle_arp_request(data, conn)

                elif re.match(gratitous_arp_pattern, data):
                    self.handle_gratitous_arp(data)
                
                elif data.split('|')[0] =='ARP Response':
                    self.handle_arp_response(data)

                else:
                    print(f"Datagram from {listenedIPAddress}({address}) dropped, invalid format. Data received: {data}")

        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Connection with {listenedIPAddress}({address}) closed.")

            # Remove routing and reallocate IP assigned via DHCP
            self.routing_table.remove_entry(listenedIPAddress)
            self.dhcp_table.reallocateIP(listenedIPAddress)
            # # Remove ARP ??? probably should cache
            # self.arp_protocol.remove_record(listenedIPAddress)

        except Exception as e:
            print(f"Unexpected error 4: {e}")


    # Handle request for connection from other clients and/or interfaces
    def handle_connection(self, conn, address):
        conn_ip_address = None

        try:
            hasReceivedConnectionRequest = False
            while True:
                data = conn.recv(1024)
                data = data.decode()

                message = data.split('|')[0]
                # Connection is from another interface
                if message == "request_interface_connection":
                    split_data = data.split('|')
                    ip_address_received = conn_ip_address = split_data[1]
                    # mac_address_received = data.split('|')[2]
                    subnet_mask_received = split_data[2]
                    is_from_router_or_client = split_data[3]


                    print(f"Request for interface connection received by {address}... Updating Routing Table.")

                    # self.arp_protocol.add_record(ip_address_received, mac_address_received, conn)

                    #Should differentiate router to router interface connection from client to router connection

                    if is_from_router_or_client == 'router':
                        ipPrefix = ip_address_received[:2+int(subnet_mask_received)]
                        self.routing_table.add_entry(ipPrefix, ip_address_received)
                        print(self.routing_table.get_routing_table())

                    interface_connection_response = f"interface_connection_response|{self.interface_ip_address}|{self.subnet_mask}"
                    print(f"Sending response payload: {interface_connection_response}")
                    conn.send(bytes(interface_connection_response, "utf-8"))

                    break

                # Client send request to establish connection
                elif message == "request_connection":
                    print(f"Request for connection received by {address}.") 

                    # Interface send request to client's for their MAC address
                    requestMACAddress = "request_mac_address|null"
                    print(f"Requesting for client's MAC address. Data sending: {requestMACAddress}")
                    conn.send(bytes(requestMACAddress, "utf-8"))

                    hasReceivedConnectionRequest = True

                # Client replies request for MAC address
                elif message == "mac_address_response":
                    if hasReceivedConnectionRequest == True:
                        mac_address = data.split('|')[1]
                        print(f"Client's MAC address received: {mac_address}")

                        # Obtain available IP address and send it to client
                        ip_address = conn_ip_address = self.dhcp_table.get_available_ip_address()

                        if ip_address:
                            responseIPSuccsss = f"assigned_ip_address|{ip_address}"
                            print(f"Assigning and sending client's IP address. Data sending: {responseIPSuccsss}")
                            conn.send(bytes(responseIPSuccsss, "utf-8"))

                            # # With client's IP and MAC address available, update ARP table
                            # print("Updating ARP table and deallocating DHCP IP address")
                            # self.arp_protocol.add_record(ip_address, mac_address)
                            break

                        else:
                            responseIPFail = f"assigned_ip_address|null"
                            print(f"No IP address available. Data sending: {responseIPFail}")
                            conn.send(bytes(responseIPFail, "utf-8"))
                            return

                else:
                    print(f"Invalid connection request/response received... Data received: {data}")

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            self.listen(conn, address, conn_ip_address)
    
        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Failure to setup connection with {address}.")

            # Undo ARP, Routing and DHCP changes
            self.arp_protocol.remove_record(conn_ip_address)
            self.routing_table.remove_entry(conn_ip_address)
            self.dhcp_table.deallocateIP(conn_ip_address)

        except Exception as e:
            print(f"Unexpected error 6: {e}")


    # Initiate connection with another interface
    def setup_interface_connection(self, conn, address):
        conn_ip_address = None

        try:
            #request_interface_connection | 0x11 | R1
            # Send connection request to corresponding interface: payload = "request_interface_connection | {ip_address} | {from_client_or_router}" 
            requestInterfaceConnection = f"request_interface_connection|{self.interface_ip_address}|{self.subnet_mask}|router"
            conn.send(bytes(requestInterfaceConnection, "utf-8"))
            print(f"Establishing interface connection. Data sending: {requestInterfaceConnection}")

            while True:
                data = conn.recv(1024)
                data = data.decode()

                message = data.split('|')[0]

                # Receive response from corresponding interface
                if message == "interface_connection_response":
                    print(f"Received interface connection response. Payload: {data}")
                    ip_address_received = conn_ip_address = data.split('|')[1]
                    subnet_mask_received = data.split('|')[2]

                    print("Updating Routing Table.")
                    ipPrefix = ip_address_received[:2+int(subnet_mask_received)]
                    self.routing_table.add_entry(ipPrefix, ip_address_received)

                    break

                else:
                    print(f"Invalid connection response received... Data received: {data}")

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            self.listen(conn, address, conn_ip_address)
    
        except (ConnectionResetError, ConnectionAbortedError):
            print(f"Failure to setup interface connection with {address}.")

            # Remove ARP and routing if needed
            self.arp_protocol.remove_record(conn_ip_address)
            self.routing_table.remove_entry(conn_ip_address)

        except Exception as e:
            print(f"Unexpected error 5: {e}")


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
            connected_interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connected_interface_socket.connect((HOST, interface_port))
            self.conn_list[listenedIp] = connected_interface_socket
            threading.Thread(target=self.setup_interface_connection, args=(connected_interface_socket, (HOST, self.connected_interface_port))).start()

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
                print(self.routing_table.get_routing_table())
            elif command_input == "dhcp":
                print(self.dhcp_table.get_dhcp_table())
            elif command_input == "reconnect":
                if(self.connected_interface_port):
                    print("Attempting to reconnect to connected interface...")
                    self.connectToInterface(self.connected_interface_port, self.connected_interface_ip)
                else:
                    print("This router is not configured to connect to other interfaces...")
            elif command_input == "man":
                print("whoami, arp, routing, dhcp, reconnect")
            else:
                print("No such command. Try again")


    def start(self):
        # If interface connected to another interface, establish connection request
        if(self.connected_interface_port):
            self.connectToInterface(self.connected_interface_port, self.connected_interface_ip)

        try:
            # A thread that will listen for new incoming connections
            threading.Thread(target = self.multi_listen_handler).start()
            self.handle_input()

        except KeyboardInterrupt:
            # Close any other connection, including clients and interfaces, if any
            for ip in self.conn_list.keys():
                self.conn_list[ip].close()

            # Close router interface listening port
            self.interface_socket.close()

        except Exception as e:
            print(f"Unexpected error 1: {e}")
