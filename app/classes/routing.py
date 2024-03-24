import re
from util import pattern


class Routing_Protocol:
    routing_table = {}
    interface_ip_address = None

    def __init__(self, routingTable={}, interface_ip_address=None, netmask = None):
        self.routing_table = routingTable
        self.interface_ip_address = interface_ip_address
        self.netmask = netmask

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
            
    def setupRouter(self, conn, netmask, ip, port, interfaceList):
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
                self.addEntry(prefix, receivedIP, receivedNetmask, receivedPort, 1)
                self.mergeTable(receivedRoutingTable, receivedIP, interfaceList)
                return True
            else:
                return False

    def addEntry(self, ip_address, gateway, subnet_mask, port, hop):
        entry = {"netmask": subnet_mask, "gateway": gateway, "port": port, "hop": hop}

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
        best_hop = float('inf')

        # for key, route in self.routing_table.items():
        #     if key == "default":
        #         key = hex(
        #             int(route["gateway"], 16) & int(route["netmask"], 16)
        #         ).rstrip("0")

        #     if ip.startswith(key):
        #         if len(key) > max_length:
        #             max_length = len(key)
        #             best_match = route["gateway"]

        for key, route in self.routing_table.items():
            if key == "default":
                key = hex(
                    int(route["gateway"], 16) & int(route["netmask"], 16)
                ).rstrip("0")

            if ip.startswith(key):
                if len(key) > max_length and route["hop"] < best_hop:
                    max_length = len(key)
                    best_match = route["gateway"]
                    best_hop = route["hop"]

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

    def mergeTable(self, receivedRoutingTable, listenedIPAddress, interfaceList):
        for key, gateway in eval(receivedRoutingTable).items():
            receivedPrefix = hex(int(gateway['gateway'], 16) & int(gateway['netmask'], 16)).rstrip("0")
            interfacePrefix = hex(int(self.interface_ip_address, 16) & int(self.netmask, 16)).rstrip("0")
            defaultPrefix = None
            if 'default' in self.routing_table:
                defaultPrefix = hex(int(self.routing_table['default']['gateway'], 16) & int(self.routing_table['default']['netmask'], 16)).rstrip("0")

            if listenedIPAddress in interfaceList:
                if key == 'default':
                    if receivedPrefix != interfacePrefix:
                        if defaultPrefix !=  None:
                            if receivedPrefix == defaultPrefix:
                                if self.routing_table['default']['hop'] > gateway['hop']:
                                    self.addEntry('default', listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])
                            else:
                                if self.routing_table['default']['hop'] > gateway['hop']:
                                    self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])
                        else:
                            if receivedPrefix in self.routing_table:
                                if self.routing_table[receivedPrefix]['hop'] > gateway['hop']:
                                    self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])
                            else:
                                self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])

                else:
                    if receivedPrefix != interfacePrefix:
                        if key in self.routing_table:
                            if self.routing_table[key]['hop'] > gateway['hop']:
                                self.addEntry(key, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])
                        else:
                            self.addEntry(key, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'])
            else:
                if key == 'default':
                    if receivedPrefix != interfacePrefix:
                        if defaultPrefix !=  None:
                            if receivedPrefix == defaultPrefix:
                                if self.routing_table['default']['hop'] > gateway['hop'] + 1:
                                    self.addEntry('default', listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)
                            else:
                                if self.routing_table['default']['hop'] > gateway['hop'] + 1:
                                    self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)
                        else:
                            if receivedPrefix in self.routing_table:
                                if self.routing_table[receivedPrefix]['hop'] > gateway['hop'] + 1:
                                    self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)
                            else:
                                self.addEntry(receivedPrefix, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)

                else:
                    if receivedPrefix != interfacePrefix:
                        if key in self.routing_table:
                            if self.routing_table[key]['hop'] > gateway['hop'] + 1:
                                self.addEntry(key, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)
                        else:
                            self.addEntry(key, listenedIPAddress, gateway['netmask'], gateway['port'], gateway['hop'] + 1)
