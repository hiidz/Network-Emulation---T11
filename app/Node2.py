import socket
import threading
import time
import json
import os
from config import *
from classes.ethernet_frame import EthernetFrame
from classes.ip_packet import IPPacket
from classes.arp import ARP_Protocol
from app.classes.attacks import Attacks



node2_ip = N2_CONFIG["node_ip_address"]
node2_mac = N2_CONFIG["node_mac"]
router = (HOST, N3_CONFIG["interface_port"])
attacks = Attacks()
network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def print_brk():
    print('-' * os.get_terminal_size().columns)


# Connects client to router interface 1 and exchange/update arp tables from both side
def handle_router_connection(arp_table):
    client.connect(router)
    arp_table.add_record("ip-sample", "mac-sample", "socket")
    # Need to exchange router and client mac and ip and update/sync ARP tables


def send_ip_packet(ip_packet: IPPacket, corresponding_socket: socket.socket, has_top_break: bool = True, has_bottom_break: bool = True) -> None:
    if has_top_break:print_brk()

    network_socket.send(bytes(ip_packet.dumps(), "utf-8")) 
    print("IP packet has been sent")
    if has_bottom_break: print_brk()


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
        payload = command_input
        client.send(bytes(payload, "utf-8"))

        if command_input == "sniff":
            attacks.handle_sniffer_input()

        elif command_input == "spoof":
            spoof_ip = input("Enter IP address to spoof: ")
            print_brk()

            dest_ip = input("Enter destination address: ")


            ip_packet = IPPacket.input_sequence(spoof_ip, dest_ip)
            if ip_packet:
                send_ip_packet(ip_packet, network_socket)
            else:
                print_brk()
                print("Packet invalid. Please try again...")




# create socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(1)
arp_table = ARP_Protocol.arp_table()
handle_router_connection(arp_table)

try:
    threading.Thread(target = listen).start()
    handle_input()

except KeyboardInterrupt:
    client.close()