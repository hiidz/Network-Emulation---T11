import socket
import threading
from config import HOST
from classes.arp import ARP_Table

class RouterInterface:
    interface_ip_address = None
    interface_mac = None
    interface_port = None
    interface_socket = None
    arp_table = ARP_Table()

    def __init__(self, interface_ip_address, interface_mac, interface_port):
        self.interface_ip_address = interface_ip_address
        self.interface_mac = interface_mac
        self.interface_port = interface_port

        self.interface_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.interface_socket.bind((HOST, interface_port))


    def listen(self, conn, address):
        print(f"Connection from {address} established.")

        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    print(f"Connection from {address} closed.")
                    break
                print(f"Received data from {address}: {data.decode()}")
                conn.send(bytes("hello", "utf-8"))
                self.arp_table.add_record("ip-sample-2", "mac-sample-2")
                print(self.arp_table.get_arp_table())
        except ConnectionResetError:
            print(f"Connection with {address} closed.")
            return


    def handle_input(self):
        while True:
            command_input = input()


    def multi_listen_handler(self):
        self.interface_socket.listen()

        while True:
            conn, address = self.interface_socket.accept()

            # For each new connection, create a new thread to continue listening
            threading.Thread(target=self.listen, args=(conn, address)).start()


    def start(self):
        try:
            # A thread that will listen for new incoming connections
            threading.Thread(target = self.multi_listen_handler).start()
            self.handle_input()

        except KeyboardInterrupt:
            self.interface_socket.close()
