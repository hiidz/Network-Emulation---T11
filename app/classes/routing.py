import re
from util import pattern


class Routing_Protocol:
    routing_table = {}

    def __init__(self, routingTable={}):
        self.routing_table = routingTable

    def get_routing_table(self):
        return self.routing_table

    def setup(self, conn, netmask, ip):
        setup_payload = f"Routing Setup|{netmask}|{ip}"
        conn.send(bytes(setup_payload, "utf-8"))

        while True:
            data = conn.recv(1024)
            data = data.decode()

            match = re.match(pattern["routing_acknowledgement"], data)
            if match:
                isSuccess = match.group(1)
                return isSuccess
            else:
                return False

    def addEntry(self, ip_address, gateway, subnet_mask, port):
        entry = {"netmask": subnet_mask, "gateway": gateway, "port": port}

        self.routing_table[ip_address] = entry

    def removeEntry(self, ip_address):
        self.routing_table = {
            route: data
            for route, data in self.routing_table.items()
            if data["gateway"] != ip_address
        }

    def getNextHopIP(self, ip):
        max_length = 0
        best_match = None

        for key, route in self.routing_table.items():
            prefix = None
            if key == "default":
                prefix = hex(
                    int(route["gateway"], 16) & int(route["netmask"], 16)
                ).rstrip("0")
            else:
                prefix = hex(int(key, 16) & int(route["netmask"], 16)).rstrip("0")

            if ip.startswith(prefix):
                if len(prefix) > max_length:
                    max_length = len(prefix)
                    best_match = route["gateway"]

        return best_match

    def acknowledgement(self, conn, isSuccess):
        acknowledgement_payload = ""
        if isSuccess:
            acknowledgement_payload = f"Routing Acknowledgement|True"
        else:
            acknowledgement_payload = f"Routing Acknowledgement|False"
        conn.send(bytes(acknowledgement_payload, "utf-8"))
