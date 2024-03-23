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
            
    def setupRouter(self, conn, netmask, ip, port):
        setup_router_payload = f"Routing Setup Router|{ip}|{netmask}|{port}|{self.routing_table}"
        conn.send(bytes(setup_router_payload, "utf-8"))

        while True:
            data = conn.recv(1024)
            data = data.decode()

            match = re.match(pattern["routing_router_acknowledgement"], data)
            if match:
                receivedIP = match.group(1)
                receivedNetmask = match.group(2)
                receivedPort = match.group(3)
                receivedRoutingTable = match.group(4)

                prefix = hex(int(receivedIP, 16) & int(receivedNetmask, 16)).rstrip("0")
                self.addEntry(prefix, receivedIP, receivedNetmask, receivedPort)

                print("process connected router routing table with hops here")

                return True
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
            if key == "default":
                key = hex(
                    int(route["gateway"], 16) & int(route["netmask"], 16)
                ).rstrip("0")

            print(ip, key, "h")
            if ip.startswith(key):
                if len(key) > max_length:
                    max_length = len(key)
                    best_match = route["gateway"]

        return best_match

    def acknowledgement(self, conn, isSuccess):
        acknowledgement_payload = ""
        if isSuccess:
            acknowledgement_payload = f"Routing Acknowledgement|True"
        else:
            acknowledgement_payload = f"Routing Acknowledgement|False"
        conn.send(bytes(acknowledgement_payload, "utf-8"))

    def routingAcknowledgement(self, conn, ipAddress, netmask, port, routingTable):
        routing_router_acknowledgement = f"Routing Router Acknowledgement|{ipAddress}|{netmask}|{port}|{routingTable}"
        conn.send(bytes(routing_router_acknowledgement, "utf-8"))