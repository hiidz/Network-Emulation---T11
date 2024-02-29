import socket
import threading
import time
from config import *
from classes.arp import ARP_Protocol
from classes.ethernet_frame import EthernetFrame
from util import datagram_initialization, arp_request_pattern
import re
from classes.firewall import Firewall

node3_mac = N3_CONFIG["node_mac"]
router = (HOST, N3_CONFIG["interface_port"])
firewall = Firewall()

conn_list = {}

default_routing_table = {
    'default': {
        'netmask': "0x00",
        'gateway': "0x21",
        'port': 8102
    }
}


# Connects client to router interface 2 and exchange/update arp tables from both side
def handle_router_connection():
    client.connect(router)
    conn_list[R1_2_CONFIG["interface_ip_address"]] = client
    # Maybe add to the routing table instead of having this from the start
    # Need to exchange router and client mac and ip and update/sync ARP tables

    request_connection = f"request_connection|null"
    print(f"Request connection from interface... Payload: {request_connection}")
    client.send(bytes(request_connection, "utf-8"))
    assigned_ip_address = None

    try:
        while True:
            data = client.recv(1024)
            data = data.decode()

            message = data.split('|')[0]

            # Receive response from corresponding interface
            if message == "request_mac_address":
                print(f"Received connection response. Payload: {data}")
                mac_address_response = f"mac_address_response|{node3_mac}"
                print(f"Sending mac address response. Payload: {mac_address_response}")

                client.send(bytes(mac_address_response, "utf-8"))

            elif message == "assigned_ip_address":
                assigned_ip_address = data.split('|')[1]

                if assigned_ip_address == 'null':
                    print("No available IP address received from Router Interface. Connection aborted...")
                    return

                else:
                    print(f"Connection success. Assigned the following IP address: {assigned_ip_address}")
                    assigned_ip_address = assigned_ip_address
                    break

            else:
                print(f"Invalid connection response received... Data received: {data}")

    except (ConnectionResetError, ConnectionAbortedError):
        print(f"Connection with {router} closed.")

    # Connection is established and now ready to indefinitely listen for incoming packets from connection
    threading.Thread(target=listen).start()
    return assigned_ip_address


def handle_arp_request(arp_request, conn):
    print("Received a broadcast IP Address")
    # Figure out if the IP address that is being looked for is ours

    is_intended_receiver, ip_looked_for, sender_ip, sender_mac = arp_protocol.verfiy_arp_request_destination(
        arp_request, client1_ip)
    if is_intended_receiver:
        print("ARP Request is meant for me")
        # Reply the client who sent the ARP Request
        arp_response = f'ARP Response|{ip_looked_for} is at {node3_mac}'
        conn.send(bytes(arp_response, "utf-8"))
        print("Sent out ARP Response")

        # Update ARP table to store ARP Request
        print("Updating ARP Table")
        arp_protocol.add_record(sender_ip, sender_mac)

        print('\nUPDATED ARP TABLE: ')
        print(arp_protocol.get_arp_table())
    else:
        print("Dropping ARP request")
        return


# Handles incoming connection
def listen():
    while True:
        received_message = client.recv(1024)
        received_message = received_message.decode("utf-8")
        print("\nMessage: " + received_message)

        if received_message.split('|')[0] == 'ARP Response':
            # Handle adding to the ARP table
            payload = received_message.split('|')[1]
            pattern = r"(0x\w{2}) is at (\w{2})"
            match = re.match(pattern, payload)

            if match:
                arp_ip_address = match.group(1)
                arp_mac_address = match.group(2)

                print("ARP IP Address:", arp_ip_address)
                print("ARP Mac Address:", arp_mac_address)
                arp_protocol.add_record(arp_ip_address, arp_mac_address)

                print('\nUPDATED ARP TABLE: ')
                print(arp_protocol.get_arp_table())

            else:
                print("No match found.")
                return False

        # Handling a ARP broadcast message received
        elif re.match(arp_request_pattern, received_message):
            handle_arp_request(received_message, client)


# Gets ethernet data payload to be sent
def handle_input(arp_protocol, firewall):
    while True:
        command_input = input()
        if command_input == "firewall":
            firewall.handle_firewall_input()

        else:
            payload = command_input

        # Getting Destination IP
            if payload.split('|')[0] == 'request_interface_connection':
                client.send(bytes(payload, "utf-8"))
            elif payload.split('|')[0] == 'Gratuitous ARP':
                arp_protocol.gratitous_arp(payload, conn_list)
            else:
                ip_datagram = datagram_initialization(payload)
                destination_ip = ip_datagram['dest']

                # Figure out route to take in the routing table but is hardcoded such that if it is found it will take that and if not use the router
                if destination_ip in default_routing_table.keys():
                    route_to_take = default_routing_table[destination_ip]
                else:
                    route_to_take = default_routing_table['default']

                route_ip = route_to_take['gateway']

                max_arp_retries = 3
                arp_request_attempt = 1

                while not arp_protocol.lookup_arp_table(route_ip) and arp_request_attempt <= max_arp_retries:
                    print("ARP Attempt " + str(
                        arp_request_attempt) + ": No MAC address found in ARP Table so sending out broadcast")
                    # Create ARP Request Frame
                    arp_protocol.arp_broadcast(route_ip, node3_mac, client1_ip, conn_list)

                    time.sleep(2)
                    arp_request_attempt += 1

                if arp_protocol.lookup_arp_table(route_ip):
                    print("\nMAC Address Found and sending payload")

                    # Package into a ethernet frame
                    dest_mac = arp_protocol.lookup_arp_table(route_ip)
                    ethernet_frame = EthernetFrame()

                    ethernet_frame.create(node3_mac, dest_mac, ip_datagram)
                    ethernet_payload = ethernet_frame.convert_to_valid_payload()
                    client.send(bytes(ethernet_payload, "utf-8"))
                    print('\nPayload has been sent')
                else:
                    print("ARP Request failed to get a MAC address")

    # Maybe need to add the logic for other connecting with this interface?


# create socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

time.sleep(1)
arp_protocol = ARP_Protocol()

try:
    client1_ip = handle_router_connection()
    handle_input(arp_protocol, firewall)

except KeyboardInterrupt:
    client.close()