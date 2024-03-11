class RIP_Protocol:
    routing_table = {}

    # routing_table = {
    #     "default": {"netmask": "0x10", "gateway": "0x11", "port": 8100, "hop": 1},
    #     "R2": {"netmask": "0x10", "gateway": "0x21", "port": 8200, "hop": 2}
    # }

    def __init__(self, routingTable = {}):
        self.routing_table = routingTable


    def get_routing_table(self):
        return self.routing_table


    def request(self):
        print("routing request")


    def response(self):
        print("routing response")


    def addEntry(self, ip_address, subnet_mask, hop):
        entry = {
            "netmask": subnet_mask,
            "gateway": ip_address,
            "hop": hop
        }
        self.routing_table[ip_address] = entry

    
    def removeEntry(self, ip_address):
        self.routing_table.pop(ip_address)


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
