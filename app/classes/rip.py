import time
import re
from util import rip_setup_pattern

class RIP_Protocol:
    routing_table = {}


    def __init__(self, routingTable = {}):
        self.routing_table = routingTable


    def get_routing_table(self):
        return self.routing_table
    
    def setup(self, conn, netmask, ip, isFirstToInitiate):
        setup_payload =  f"RIP Setup|{netmask}|{ip}"
        conn.send(bytes(setup_payload, "utf-8"))
        while isFirstToInitiate:
            data = conn.recv(1024)
            data = data.decode()
            if re.match(rip_setup_pattern, data):
                subnet_mask_received = re.match(rip_setup_pattern, data).group(1)
                ip_address_received = re.match(rip_setup_pattern, data).group(2)
                return ip_address_received, subnet_mask_received


    def request(self, conn):
        request_payload = "RIP Request"
        conn.send(bytes(request_payload, "utf-8"))


    def response(self, conn, routing_table):
        formatted_routing_table = str(routing_table).replace(" ", "").replace("'", "")
        response_payload = f"RIP Response|{formatted_routing_table}"
        conn.send(bytes(response_payload, "utf-8"))


    def addEntry(self, ip_address, gateway, subnet_mask, hop, toModifyDefault = False):
        entry = {
            "netmask": subnet_mask,
            "gateway": gateway,
            "hop": hop
        }
        if toModifyDefault:
            self.routing_table['default'] = entry
        else:
            self.routing_table[ip_address] = entry

    
    def removeEntry(self, ip_address):
        self.routing_table = {route: data for route, data in self.routing_table.items() if data['gateway'] != ip_address}


    def getNextHopIP(self, ip):
        max_length = 0
        best_match = None
        best_hop = float('inf')

        for gateway, info in self.routing_table.items():
            prefix = hex(int(info["gateway"], 16) & int(info["netmask"], 16)).rstrip('0')
            if ip.startswith(prefix):
                if len(prefix) > max_length and info["hop"] < best_hop:
                    max_length = len(prefix)
                    best_match = gateway
                    best_hop = info["hop"]
        
        return best_match
