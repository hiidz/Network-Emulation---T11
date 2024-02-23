class ARP_Table:
    # IP address : mac address
    arp_table = {}

    def __init__(self):
        self.arp_table = {}


    def add_record(self, ip_address: str, mac_address: str, connSocket):
        self.arp_table[ip_address] = {"mac": mac_address, "socket": connSocket}


    def remove_record(self, ip_address):
        del self.arp_table[ip_address]


    def get_arp_table(self):
        return self.arp_table
    