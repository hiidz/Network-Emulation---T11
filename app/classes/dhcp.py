class DHCP_Table:
    # IP address : mac address
    dhcp_table = {}

    def __init__(self, IPaddressList):
        for addr in IPaddressList:
            # 1 = IP address available
            self.dhcp_table[addr] = 1


    def get_available_ip_address(self):
        for addr, availability in self.dhcp_table.items():
            if availability == 1:
                # 0 = IP address no longer available
                self.dhcp_table[addr] = 0
                return addr

        return None


    def deallocateIP(self, ip_address: str):
        if self.dhcp_table.get(ip_address) is not None:
            self.dhcp_table[ip_address] = 0


    def reallocateIP(self, ip_address):
        if self.dhcp_table.get(ip_address) is not None:
            self.dhcp_table[ip_address] = 1


    def get_dhcp_table(self):
        return self.dhcp_table
