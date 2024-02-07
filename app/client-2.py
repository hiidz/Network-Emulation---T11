import socket
import time
import threading
from config import *

client2_ip = N2_CONFIG["node_ip_address"]
client2_mac = N2_CONFIG["node_mac"]

router = (HOST, N2_CONFIG["network_int_port"])
client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
client2.connect(router)

def listen():
    while True:
        received_message = client2.recv(1024)
        received_message = received_message.decode("utf-8")
        source_mac = received_message[0:17]
        destination_mac = received_message[17:34]
        source_ip = received_message[34:45]
        destination_ip =  received_message[45:56]
        message = received_message[56:]
        print("\nPacket integrity:\ndestination MAC address matches client 2 MAC address: {mac}".format(mac=(client2_mac == destination_mac)))
        print("\ndestination IP address matches client 2 IP address: {mac}".format(mac=(client2_ip == destination_ip)))
        print("\nThe packed received:\n Source MAC address: {source_mac}, Destination MAC address: {destination_mac}".format(source_mac=source_mac, destination_mac=destination_mac))
    
        print("\nSource IP address: {source_ip}, Destination IP address: {destination_ip}".format(source_ip=source_ip, destination_ip=destination_ip))
    
        print("\nMessage: " + message)

def handle_input():
    while True:
        command_input = input()
        print(command_input)

try:
    threading.Thread(target = listen).start()
    handle_input()

except KeyboardInterrupt:
    client2.close()

