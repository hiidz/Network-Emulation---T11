import socket
import threading
from config import HOST
from classes.arp import ARP_Table

class RouterInterface:
    interface_ip_address = None
    interface_mac = None
    interface_port = None
    interface_socket = None
    connected_interface_port = None
    connected_socket = None
    arp_table = ARP_Table()


    def __init__(self, interface_ip_address, interface_mac, interface_port, connected_interface_port: int = None):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port
        self.connected_interface_port = connected_interface_port

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))


    def get_available_ip_address(self):
        # To be obtained by ARP Table
        return "0x3f"


    def setup_connection(self, conn, address):
        try:
            # ip_address_assigned = False
            mac_address_received = False
            request_connection_received = False
            while True:
                data = conn.recv(1024)

                # message = data.decode("utf-8").split('|')[0]
                message = data.decode("utf-8").split('|')[-2]
                # temporary fix until client follow sequence standard (refer to telegram picture/msg)
                if(message == "0x21"):
                    message = "request_interface_connection"

                # Connection is from another interface
                if message == "request_interface_connection":
                    print(data.decode("utf-8"))
                    ip_address_received = data.decode("utf-8").split('|')[1]
                    mac_address_received = data.decode("utf-8").split('|')[2]
                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    print(self.arp_table.get_arp_table())
                    conn.send(bytes(f"interface_connection_response|{self.interface_ip_address}|{self.interface_mac}", "utf-8"))
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
                        # mac_address = data.decode("utf-8").split('|')[1]
                        mac_address = data.decode("utf-8").split('|')[-1]
                        print("Client's MAC address received.")
                        print("Assigning and sending client's IP address")

                        # Obtain available IP address and send it to client
                        ip_address = self.get_available_ip_address()
                        # ip_address_assigned = True
                        conn.send(bytes(f"assigned_ip_address|{ip_address}", "utf-8"))

                        # With client's IP and MAC address available, update ARP table
                        print("Updating ARP table")
                        self.arp_table.add_record(ip_address, mac_address, conn)
                        print(self.arp_table.get_arp_table())
                        break

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            self.listen(conn, address)
    
        except ConnectionResetError:
            print(f"Failure to setup connection with {address}.")

        except Exception as e:
            print(f"Unexpected error 6: {e}")


    def setup_interface_connection(self, conn, address):
        print("Establishing interface connection")

        try:
            # Send connection request to corresponding interface: payload = "request_interface_connection | {ip_address} | {mac}" 
            conn.send(bytes(f"request_interface_connection|{self.interface_ip_address}|{self.interface_mac}", "utf-8"))

            while True:
                data = conn.recv(1024)

                message = data.decode("utf-8").split('|')[0]

                # Receive response from corresponding interface
                if message == "interface_connection_response":
                    ip_address_received = data.decode("utf-8").split('|')[1]
                    mac_address_received = data.decode("utf-8").split('|')[2]
                    self.arp_table.add_record(ip_address_received, mac_address_received, conn)
                    print(self.arp_table.get_arp_table())
                    break

            # Connection is established and now ready to indefinitely listen for incoming packets from connection
            # self.listen(conn, address)
            threading.Thread(target = self.listen, args=(conn, address)).start()
    
        except ConnectionResetError:
            print(f"Failure to setup interface connection with {address}.")

        except Exception as e:
            print(f"Unexpected error 5: {e}")


    def listen(self, conn, address):
        print(f"Connection from {address} established.")

        # Logic for handling/forwarding packets/frames to be implemented here.
        try:
            while True:
                data = conn.recv(1024)
                decoded_data = data.decode()
                # if not data:
                #     print(f"Connection from {address} closed.")
                #     break
                print(f"Received data from {address}: {decoded_data}")
                # conn.send(bytes("data received: " + decoded_data, "utf-8"))

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
                threading.Thread(target=self.setup_connection, args=(conn, address)).start()

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
