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

    def handle_connection(self, conn, address, arp_table):
        print(f"Connection from {address} established.")

        while True:
            data = conn.recv(1024)
            if not data:
                print(f"Connection from {address} closed.")
                break
            print(f"Received data from {address}: {data.decode()}")
            conn.send(bytes("hello", "utf-8"))
            arp_table.add_record("ip-sample-2", "mac-sample-2")
            print(arp_table.get_arp_table())

        print(f"Connection with {address} closed.")
        conn.close()

    def listen(self):
        self.interface_socket.listen(5)

        print(f"Interface on {HOST}:{self.interface_port} waiting for connections...")

        while True:
            conn, address = self.interface_socket.accept()
            self.handle_connection(conn, address, self.arp_table)

    def handle_input(self):
        while True:
            command_input = input()

    def start(self):
        try:
            threading.Thread(target = self.listen).start()
            self.handle_input()

        except KeyboardInterrupt:
            self.interface_socket.close()
