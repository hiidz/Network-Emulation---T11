import re

class ARP_Protocol:
    # IP address : mac address
    arp_table = {}

    def __init__(self):
        self.arp_table = {}

    def lookup_arp_table(self, ip_address):
        available_ip_addresses = self.arp_table.keys()
        if ip_address in available_ip_addresses:
            return self.arp_table[ip_address]['mac']
        else:
            return None

    def arp_broadcast(self, ip_to_find, sender_mac, sender_ip, connected_sockets):
        arp_request = f"Who has IP: {ip_to_find}, I am {sender_mac} and my IP is {sender_ip} "
        for key in connected_sockets.keys():
            #Only send to nodes in the correct subnet
            if key[:3] == ip_to_find[:3]:
                connected_sockets[key].send(bytes(arp_request, "utf-8"))
    
    def gratitous_arp(self, gratitous_arp, connected_sockets):
        payload = gratitous_arp.split('|')[1]
        pattern = r"(0x\w{2}) is now at (\w{2})"
        match = re.match(pattern, payload)

        if match:
            ip_address = match.group(1)
            new_mac_address = match.group(2)

            print("IP Address:", ip_address)
            print("New Mac Address:", new_mac_address)

        else:
            print("No match found.")
            return False

        for key in connected_sockets.keys():
            #Only send to nodes in the correct subnet
            if key[:3] == ip_address[:3]:
                connected_sockets[key].send(bytes(gratitous_arp, "utf-8"))

    
    def verfiy_arp_request_destination(self, arp_request, receiver_ip):
        pattern = r"Who has IP: (0x\w{2}), I am (\w{2}) and my IP is (0x\w{2})"
        match = re.match(pattern, arp_request)

        if match:
            ip_looked_for = match.group(1)
            sender_mac = match.group(2)
            sender_ip = match.group(3)

            print("IP Looked for:", ip_looked_for)
            print("Sender MAC & IP:", (sender_mac, sender_ip))
        else:
            print("Not a valid ARP Request.")
            return False, None, None, None
        
        if ip_looked_for == receiver_ip:
            return True, ip_looked_for, sender_mac, sender_ip
        else:
            return False, None, None, None

        
            

    def add_record(self, ip_address: str, mac_address: str):
        self.arp_table[ip_address] = {"mac": mac_address}


    def remove_record(self, ip_address):    
        if self.arp_table.get(ip_address) is not None:
            del self.arp_table[ip_address]


    def get_arp_table(self):
        return self.arp_table
    


    