import socket
import threading
import time
from config import *

client1_ip = N1_CONFIG["node_ip_address"]
client1_mac = N1_CONFIG["node_mac"]

router_mac = R1_1_CONFIG["network_int_mac"]
router_port = N1_CONFIG["network_int_port"]
router = (HOST, router_port)

# Connects client to router interface 1
# # Might need to add reconnect functionality or loop until connection established
client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
client1.connect(router)

def listen():
    while True:
        received_message = client1.recv(1024)
        received_message = received_message.decode("utf-8")
        source_mac = received_message[0:17]
        destination_mac = received_message[17:34]
        source_ip = received_message[34:45]
        destination_ip =  received_message[45:56]
        message = received_message[56:]
        print("\nPacket integrity:\ndestination MAC address matches client 1 MAC address: {mac}".format(mac=(client1_mac == destination_mac)))
        print("\ndestination IP address matches client 1 IP address: {mac}".format(mac=(client1_ip == destination_ip)))
        print("\nThe packed received:\n Source MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(source_mac=source_mac, destination_mac=destination_mac))
    
        print("\nSource IP address: {source_ip}, Destination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    
        print("\nMessage: " + message)

def handle_input():
    while True:
        command_input = input()
        payload = f"{client1_mac}|{router_mac}|{len(command_input)}|{command_input}"
        client1.send(bytes(payload, "utf-8"))

try:
    threading.Thread(target = listen).start()
    handle_input()

except KeyboardInterrupt:
    client1.close()