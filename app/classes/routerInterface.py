import socket
import threading
from config import HOST
from classes.arp import ARP_Table
from classes.routing import Routing_Table
import re
from util import datagram_initialization, frame_pattern, packet_pattern


class RouterInterface:
    interface_ip_address = None
    interface_mac = None
    interface_port = None
    interface_socket = None
    connected_interface_port = None
    connected_socket = None
    subnet_mask = None
    conn_list = None
    arp_table = None
    routing_table = None
    dhcp_table = None


    def __init__(self, interface_ip_address, interface_mac, interface_port, subnet_mask, ip_address_available, connected_interface_port: int = None):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port
        self.connected_interface_port = connected_interface_port
        self.subnet_mask = subnet_mask

        self.conn_list = []

        self.arp_table = ARP_Table()
        self.routing_table =Routing_Table()
        self.dhcp_table = {}

        for ip in ip_address_available:
            # 1 = IP address available
            self.dhcp_table[ip] = 1

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))


    def get_available_ip_address(self):
        for ip, availability in self.dhcp_table.items():
            if availability == 1:
                # 0 = IP address no longer available
                self.dhcp_table[ip] = 0
                return ip

        return None


    def isIPAddressInNetwork(self, ip):
        # offset by 2 because IP address stirng starts with '0x'
        if ip[:2+self.subnet_mask] == self.interface_ip_address[:2+self.subnet_mask]:
            return True
        else:
            return False


    # Handle request for connection from other clients and/or interfaces
    def handle_connection(self, conn, address):
        hasReceivedMACAddressResponse = False
        hasReceivedConnectionRequest = False
        hasAssignedIPAddress = False

        hasUpdatedARP = False
        hasUpdatedRouting = False

        try:
            while True:
                data = conn.recv(1024)
                data = data.decode()

                message = data.split('|')[0]

                # Connection is from another interface
                if message == "request_interface_connection":
                    ip_address_received = data.split('|')[1]
                    mac_address_received = data.split('|')[2]
                    subnet_mask_received = data.split('|')[3]

                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    hasUpdatedARP = ip_address_received

                    ipPrefix = ip_address_received[:2+int(subnet_mask_received)]
                    self.routing_table.add_entry(ipPrefix, ip_address_received)
                    hasUpdatedRouting = ipPrefix

                    conn.send(bytes(f"interface_connection_response|{self.interface_ip_address}|{self.interface_mac}|{self.subnet_mask}", "utf-8"))
                    self.connected_socket = conn
                    break

                # Client send request to establish connection
                elif message == "request_connection":
                    if hasReceivedConnectionRequest == False:
                        print(f"Request for connection received...")
                        hasReceivedConnectionRequest = True

                        # Interface send request to client's for their MAC address
                        requestMACAddress = "request_mac_address|null"
                        print(f"Requesting for client's MAC address. Data sending: {requestMACAddress}")
                        conn.send(bytes(requestMACAddress, "utf-8"))

                # Client replies request for MAC address
                elif message == "mac_address_response":
                    if hasReceivedMACAddressResponse == False and hasReceivedConnectionRequest == True:
                        mac_address = data.split('|')[1]
                        print(f"Client's MAC address received: {mac_address}")

                        # Obtain available IP address and send it to client
                        ip_address = self.get_available_ip_address()
                        hasAssignedIPAddress = True

                        if ip_address:
                            responseIPSuccsss = f"assigned_ip_address|{ip_address}"
                            print(f"Assigning and sending client's IP address. Data sending: {responseIPSuccsss}")
                            conn.send(bytes(responseIPSuccsss, "utf-8"))

                            # With client's IP and MAC address available, update ARP table
                            print("Updating ARP table")
                            self.arp_table.add_record(ip_address, mac_address, conn)
                            hasUpdatedARP = ip_address
                            break

                        else:
                            responseIPFail = f"assigned_ip_address|null"
                            print(f"No IP address available. Data sending: {responseIPFail}")
                            conn.send(bytes(responseIPFail, "utf-8"))

                        hasReceivedMACAddressResponse = True

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            # hasUpdatedARP = IP address of connection
            self.listen(conn, address, hasUpdatedARP)
    
        except ConnectionResetError:
            print(f"Failure to setup connection with {address}.")

            # Remove ARP and DHCP if needed
            if hasUpdatedARP:
                self.arp_table.remove_record(hasUpdatedARP)
            if hasUpdatedRouting:
                self.routing_table.remove_entry(hasUpdatedARP)
            if hasAssignedIPAddress:
                self.dhcp_table[hasUpdatedARP] = 1

        except ConnectionAbortedError:
            print(f"Failure to setup connection with {address}.")
            
            # Remove ARP and DHCP if needed
            if hasUpdatedARP:
                self.arp_table.remove_record(hasUpdatedARP)
            if hasUpdatedRouting:
                self.routing_table.remove_entry(hasUpdatedARP)
            if hasAssignedIPAddress:
                self.dhcp_table[hasUpdatedARP] = 1

        except Exception as e:
            print(f"Unexpected error 6: {e}")


    # Initiate connection with another interface
    def setup_interface_connection(self, conn, address):
        hasUpdatedARP = False
        hasUpdatedRouting = False

        try:
            requestInterfaceConnection = f"request_interface_connection|{self.interface_ip_address}|{self.interface_mac}|{self.subnet_mask}"
            # Send connection request to corresponding interface: payload = "request_interface_connection | {ip_address} | {mac}" 
            conn.send(bytes(requestInterfaceConnection, "utf-8"))
            print(f"Establishing interface connection. Data sending: {requestInterfaceConnection}")

            while True:
                data = conn.recv(1024)
                data = data.decode()

                message = data.split('|')[0]

                # Receive response from corresponding interface
                if message == "interface_connection_response":
                    print(f"Received interface connection response from {address}. Payload: {data}")
                    ip_address_received = data.split('|')[1]
                    mac_address_received = data.split('|')[2]
                    subnet_mask_received = data.split('|')[3]

                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    hasUpdatedARP = ip_address_received

                    ipPrefix = ip_address_received[:2+int(subnet_mask_received)]
                    self.routing_table.add_entry(ipPrefix, ip_address_received)
                    hasUpdatedRouting = ipPrefix

                    break

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            # hasUpdatedARP = IP address of connection
            threading.Thread(target = self.listen, args=(conn, address, hasUpdatedARP)).start()
    
        except ConnectionResetError:
            print(f"Failure to setup interface connection with {address}.")

            # Remove ARP and DHCP if needed
            if hasUpdatedARP:
                self.arp_table.remove_record(hasUpdatedARP)
            if hasUpdatedRouting:
                self.routing_table.remove_entry(hasUpdatedARP)

        except Exception as e:
            print(f"Unexpected error 5: {e}")


    # Test cases that we can use via client side:

    #     valid IP packet
    #     - {src:0x55,dest:0x11,protocol:kill,dataLength:5,data:iwanttokillyou!}

    #     IP packet with invalid destination
    #     - {   

    #     valid ETH frame without IP packet
    #     - {src:n1,dest:R1,dataLength:5,data:thisIsNotAnIPPacket}

    #     valid ETH frame with valid IP packet
    #     - {src:n1,dest:R1,dataLength:5,data:{src:0x55,dest:0x11,protocol:kill,dataLength:5,data:iwanttokillyou!}}

    #     valid ETH frame with invalid IP packet destination
    #     - {src:n1,dest:R1,dataLength:5,data:{src:0x55,dest:0x66,protocol:kill,dataLength:5,data:iwanttokillyou!}}

    #     ETH frame with invalid destination
    #     - {src:n1,dest:R2,dataLength:5,data:ThisCanBeAnything}

    #     ETH broadcast with dest 'FF'
    #     - {src:n1,dest:FF,dataLength:5,data:{src:0x55,dest:0x11,protocol:arp,dataLength:5,data:ThisIsARPBroadcast!}}


    def handleIPPacket(self, packet_str):
        packet = datagram_initialization(packet_str)

        # If dest in packet matches router address, router is intended recipient
        if packet['dest'] == self.interface_ip_address:
            print(f"IP Packet received. Protocol is: {packet['protocol']}. Payload is: {packet['data']}.")

            # Process IP packet if required
            # # if packet['protocol'] == 'kill/arp etc.':

        else:
            destination_ip_address = packet['dest']
            print(f"Not intended recipient, will forward based on IP packet: {destination_ip_address}")
            # Create EthernetFrame and route to next interface. (for future, can use BGP routing protocol to dynamically update routing table rather than static)

            #Check if IP address is in router network
            if self.isIPAddressInNetwork(destination_ip_address):
                print("Destination IP address is in the network. Will transmit as per ARP table.")

                # Catch error if no mac address.  Maybe ARP broadcast. to be done
                next_hop_mac = self.arp_table.get_arp_table()[destination_ip_address]['mac']

            else:
                print("Destination IP address is not in the network. Will look up routing table...")

                # Get next hop IP address
                next_hop_ip = self.routing_table.getNextHopIP(destination_ip_address)

                if next_hop_ip:
                    print(f"Routing found, transmitting to the following IP address: {next_hop_ip}")

                    # Catch error if no mac address. Maybe ARP broadcast. to be done
                    next_hop_mac = self.arp_table.get_arp_table()[next_hop_ip]['mac']

                else:
                    print(f"No routing can be found for the following IP address: {destination_ip_address}")
                    return

            frame_str = f"{{src:{self.interface_mac},dest:{next_hop_mac},dataLength:{len(packet['data'])},data:{packet['data']}}}"
            print(f"New Frame to be broadcasted: {frame_str}")

            # Broadcast to all sockets
            for arp_value in self.arp_table.get_arp_table().values():
                print(f"Broadcasting to: {arp_value['mac']}")
                arp_value['socket'].send(bytes(frame_str, "utf-8"))


    def handleEthernetFrame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, else forward based on IP packet
        if frame['dest'] == self.interface_mac:
            print(f"Ethernet Frame received: {frame}")

            # Process Ethernet frame and its IP packet if required
            if re.match(packet_pattern, frame['data']):
                print("Extracting IP packet in payload...")
                self.handleIPPacket(frame['data'])

            else:
                print(f"Payload is: {frame['data']}.")

        elif frame['dest'] == "FF":
            # Broadcast to all sockets
            print("Broadcast Frame received, will broadcast to all device in the network")
            for arp_key, arp_value in self.arp_table.get_arp_table().items():
                if self.isIPAddressInNetwork(arp_key):
                    arp_value['socket'].send(bytes(frame_str, "utf-8"))

        else:
            print(f"Invalid MAC address. Not intended recipient. Will drop frame...")


    def listen(self, conn, address, listenedIPAddress):
        print(f"Connection from {address} established.")

        # Logic for handling/forwarding packets/frames
        try:
            while True:
                data = conn.recv(1024)
                data = data.decode()

                # Check if the datagram received matches either frame or packet regex pattern
                if re.match(frame_pattern, data):
                    self.handleEthernetFrame(data)
                elif re.match(packet_pattern, data):
                    self.handleIPPacket(data)
                else:
                    print(f"Datagram dropped, invalid format. Data received: {data}")

        except ConnectionResetError:
            print(f"Connection with client:{address} closed.")
            # Remove routing
            self.routing_table.remove_entry(listenedIPAddress)
            if listenedIPAddress in self.dhcp_table:
                self.dhcp_table[listenedIPAddress] = 1

            # Remove ARP ??? probably should cache
            # self.arp_table.remove_record(listenedIPAddress)

        except ConnectionAbortedError:
            print(f"Connection with client:{address} closed.")
            # Remove routing
            self.routing_table.remove_entry(listenedIPAddress)
            if listenedIPAddress in self.dhcp_table:
                self.dhcp_table[listenedIPAddress] = 1

            # Remove ARP ??? probably should cache
            # self.arp_table.remove_record(listenedIPAddress)

        except Exception as e:
            print(f"Unexpected error 4: {e}")
            # Remove routing
            self.routing_table.remove_entry(listenedIPAddress)
            if listenedIPAddress in self.dhcp_table:
                self.dhcp_table[listenedIPAddress] = 1

            # Remove ARP ??? probably should cache
            # self.arp_table.remove_record(listenedIPAddress)


    def handle_input(self):
        # Logic for receiving command from user input in CLI handled here
        while True:
            command_input = input()
            if command_input == "whoami":
                print(f"Routers IP address is {self.interface_ip_address}")
                print(f"Routers MAC is {self.interface_mac}")
            elif command_input == "arp":
                print(self.arp_table.get_arp_table())
            elif command_input == "routing":
                print(self.routing_table.get_routing_table())
            elif command_input == "dhcp":
                print(self.dhcp_table)
            else:
                print("No such command. Try again")


    def multi_listen_handler(self):
        try:
            self.interface_socket.listen()

            while True:
                conn, address = self.interface_socket.accept()
                self.conn_list.append(conn)

                # For each new connection, create a new thread to continue listening
                # Will exchange clients MAC address for a free IP address to assign to client
                threading.Thread(target=self.handle_connection, args=(conn, address)).start()

        except OSError:
            print("Server socket has been closed...")

        except Exception as e:
            print(f"Unexpected error 3: {e}")


    def start(self):
        # If interface connected to another interface, establish connection request
        if(self.connected_interface_port):
            self.connected_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                self.connected_socket.connect((HOST, self.connected_interface_port))
                self.setup_interface_connection(self.connected_socket, (HOST, self.connected_interface_port))

            except ConnectionRefusedError:
                print(f"Unable to connect to the connected interface.")

            except Exception as e:
                print(f"Unexpected error 2: {e}")

        try:
            # A thread that will listen for new incoming connections
            threading.Thread(target = self.multi_listen_handler).start()
            self.handle_input()

        except KeyboardInterrupt:
            self.interface_socket.close()

            if self.connected_socket != None:
                self.connected_socket.close()

            for conn in self.conn_list:
                conn.close()

        except Exception as e:
            print(f"Unexpected error 1: {e}")
