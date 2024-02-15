import socket
import threading
import time
from config import *
from classes.arp import ARP_Table

client1_ip = N1_CONFIG["node_ip_address"]
client1_mac = N1_CONFIG["node_mac"]
router = (HOST, N1_CONFIG["interface_port"])

# Connects client to router interface 1 and exchange/update arp tables from both side
def handle_router_connection(arp_table):
    client.connect(router)
    arp_table.add_record("ip-sample", "mac-sample")
    # Need to exchange router and client mac and ip and update/sync ARP tables

# Handles incoming connection
def listen():
    while True:
        received_message = client.recv(1024)
        received_message = received_message.decode("utf-8")
        print("\nMessage: " + received_message)
        print(arp_table.get_arp_table())

# Gets ethernet data payload to be sent
def handle_input():
    while True:
        command_input = input()

        # hardcoded router mac. need to get from ARP
        router_mac = "R1"

        # Format: { node-mac | router-mac | data length | data }
        payload = f"{client1_mac}|{router_mac}|{len(command_input)}|{command_input}"
        client.send(bytes(payload, "utf-8"))


# create socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
arp_table = ARP_Table()
handle_router_connection(arp_table)

try:
    threading.Thread(target = listen).start()
    handle_input()

except KeyboardInterrupt:
    client.close()
