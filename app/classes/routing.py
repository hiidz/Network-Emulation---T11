class Routing_Table:
    # IP address prefix: router interface ip address
    routing_table = {}

    def __init__(self):
        # Static routing table
        self.routing_table = {}


    def add_entry(self, prefix: str, destination: str):
        self.routing_table[prefix] = destination


    def getNextHopIP(self, ip):
        max_length = 0
        best_match = None

        for prefix, destination in self.routing_table.items():
            if ip.startswith(prefix):
                if len(prefix) > max_length:
                    max_length = len(prefix)
                    best_match = destination
        
        return best_match
