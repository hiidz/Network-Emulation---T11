import socket
import threading
from config import *
from classes.arp import ARP_Table

router_interface_1_ip = R1_1_CONFIG["network_int_ip_address"]
router_interface_1_mac = R1_1_CONFIG["network_int_mac"]

def handle_connection(conn, address, arp_table):
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

def listen(arp_table):
    interface.listen(5)

    print(f"Interface on {HOST}:{R1_1_PORT} waiting for connections...")

    while True:
        conn, address = interface.accept()
        handle_connection(conn, address, arp_table)

def handle_input():
    while True:
        command_input = input()


try:
    interface = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    interface.bind((HOST, R1_1_PORT))
    arp_table = ARP_Table()
    threading.Thread(target = listen(arp_table)).start()
    handle_input()
        
except KeyboardInterrupt:
    interface.close()