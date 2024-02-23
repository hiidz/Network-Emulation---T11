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
    arp_table = ARP_Table()
    routing_table =Routing_Table()
    dhcp_table = {}


    def __init__(self, interface_ip_address, interface_mac, interface_port, subnet_mask, ip_address_available, connected_interface_port: int = None):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port
        self.connected_interface_port = connected_interface_port
        self.subnet_mask = subnet_mask

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))

        for ip in ip_address_available:
            self.dhcp_table[ip] = 1


    def get_available_ip_address(self):
        for ip, availability in self.dhcp_table.items():
            if availability == 1:
                self.dhcp_table[ip] = 0
                return ip
        return None


    def isIPAddressInNetwork(self, ip):
        if ip[:2+self.subnet_mask] == self.interface_ip_address[:2+self.subnet_mask]:
            return True
        else:
            return False


    # Handle request for connection from other clients and/or interfaces
    def handle_connection(self, conn, address):
        try:
            mac_address_received = False
            request_connection_received = False
            while True:
                data = conn.recv(1024)

                message = data.decode("utf-8").split('|')[0]

                # Connection is from another interface
                if message == "request_interface_connection":
                    print(data.decode("utf-8"))
                    ip_address_received = data.decode("utf-8").split('|')[1]
                    mac_address_received = data.decode("utf-8").split('|')[2]
                    subnet_mask_received = data.decode("utf-8").split('|')[3]
                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    self.routing_table.add_entry(ip_address_received[:2+int(subnet_mask_received)], ip_address_received)
                    print(self.arp_table.get_arp_table())
                    conn.send(bytes(f"interface_connection_response|{self.interface_ip_address}|{self.interface_mac}|{self.subnet_mask}", "utf-8"))
                    self.connected_socket = conn
                    break

                # Client send request to establish connection
                elif message == "request_connection":
                    if request_connection_received == False:
                        print("Request for connection received")
                        request_connection_received = True
                        print("Requesting for client's MAC address")

                        # Interface send request to client's for their MAC address
                        conn.send(bytes("request_mac_address|null", "utf-8"))

                # Client replies request for MAC address
                elif message == "mac_address_response":
                    if mac_address_received == False and request_connection_received == True:
                        mac_address = data.decode("utf-8").split('|')[1]
                        print("Client's MAC address received.")
                        print("Assigning and sending client's IP address")

                        # Obtain available IP address and send it to client
                        ip_address = self.get_available_ip_address()

                        if ip_address:
                            # ip_address_assigned = True
                            conn.send(bytes(f"assigned_ip_address|{ip_address}", "utf-8"))

                            # With client's IP and MAC address available, update ARP table
                            print("Updating ARP table")
                            self.arp_table.add_record(ip_address, mac_address, conn)
                            print(self.arp_table.get_arp_table())
                            break
                        else:
                            conn.send(bytes(f"assigned_ip_address|null", "utf-8"))


            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            self.listen(conn, address)
    
        except ConnectionResetError:
            print(f"Failure to setup connection with {address}.")

        except Exception as e:
            print(f"Unexpected error 6: {e}")


    # Initiate connection with another interface
    def setup_interface_connection(self, conn, address):
        print("Establishing interface connection")

        try:
            # Send connection request to corresponding interface: payload = "request_interface_connection | {ip_address} | {mac}" 
            conn.send(bytes(f"request_interface_connection|{self.interface_ip_address}|{self.interface_mac}|{self.subnet_mask}", "utf-8"))

            while True:
                data = conn.recv(1024)

                message = data.decode("utf-8").split('|')[0]

                # Receive response from corresponding interface
                if message == "interface_connection_response":
                    ip_address_received = data.decode("utf-8").split('|')[1]
                    mac_address_received = data.decode("utf-8").split('|')[2]
                    subnet_mask_received = data.decode("utf-8").split('|')[3]
                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    self.routing_table.add_entry(ip_address_received[:2+int(subnet_mask_received)], ip_address_received)
                    print(self.arp_table.get_arp_table())
                    break

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            threading.Thread(target = self.listen, args=(conn, address)).start()
    
        except ConnectionResetError:
            print(f"Failure to setup interface connection with {address}.")

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
                print("Destination IP address is in the network. Will transmit as per ARP table")

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
                arp_value['socket'].send(bytes(frame_str, "utf-8"))


    def handleEthernetFrame(self, frame_str):
        frame = datagram_initialization(frame_str)

        # Check if intended recipient, else forward based on IP packet
        if frame['dest'] == self.interface_mac:
            print(f"Ethernet Frame received.")
            # Process Ethernet frame and its IP packet if required
            if re.match(packet_pattern, frame['data']):
                print("Extracting IP packet in payload...")
                self.handleIPPacket(frame['data'])
            else:
                print(f"Payload is: {frame['data']}.")

        elif frame['dest'] == "FF":
            print("Broadcast Frame received, will broadcast to all device in the network")
            # Broadcast to all sockets
            for arp_key, arp_value in self.arp_table.get_arp_table().items():
                if self.isIPAddressInNetwork(arp_key):
                    arp_value['socket'].send(bytes(frame_str, "utf-8"))

        else:
            print(f"Invalid MAC address. Not intended recipient. Will drop frame...")


    def listen(self, conn, address):
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

        except ConnectionAbortedError:
            print(f"Connection with client:{address} closed.")

        except Exception as e:
            print(f"Unexpected error 4: {e}")


    def handle_input(self):
        # Logic for receiving command from user input in CLI handled here
        while True:
            command_input = input()


    def multi_listen_handler(self):
        try:
            self.interface_socket.listen()

            while True:
                conn, address = self.interface_socket.accept()

                # For each new connection, create a new thread to continue listening
                # Will exchange clients MAC address for a free IP address to assign to client
                threading.Thread(target=self.handle_connection, args=(conn, address)).start()

        except OSError:
            print("Server socket has been closed...")
            return

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

        except Exception as e:
            print(f"Unexpected error 1: {e}")
