class DHCP_Server_Protocol:
    dhcp_table = {}
    subnet_mask = None

    def __init__(self, IPaddressList, subnet_mask):
        for addr in IPaddressList:
            # 1 = IP address available, 0 = ip address unavailale
            self.dhcp_table[addr] = 1
        self.subnet_mask = subnet_mask

    def get_dhcp_table(self):
        return self.dhcp_table


    def get_available_ip_address(self):
        for addr, availability in self.dhcp_table.items():
            if availability == 1:
                return addr

        return None


    def offer(self, conn):
        ip_address_assigned = self.get_available_ip_address()
        if ip_address_assigned != None:
            print(f"Sending DHCP Offer. IP address: {ip_address_assigned}")
            offer_payload = f"DHCP Server Offer|{ip_address_assigned}|{self.subnet_mask}"
            conn.send(bytes(offer_payload, "utf-8"))
            return ip_address_assigned
        else:
            print(f"Sending DHCP Offer. No IP Address available. IP address: {ip_address_assigned}")
            offer_payload = f"DHCP Server Offer|null|null"
            conn.send(bytes(offer_payload, "utf-8"))
            return False


    def acknowledgement(self, conn, ip_address):
        if self.dhcp_table[ip_address] == 1:
            print(f"Sending DHCP Acknowledgement and updating DHCP table. IP address: {ip_address}")
            acknowledgement_payload = f"DHCP Server Acknowledgement|{ip_address}|{self.subnet_mask}"
            self.dhcp_table[ip_address] = 0
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return ip_address

        else:
            print(f"Sending DHCP Acknowledgement. IP address no longer available. IP address: {ip_address}")
            acknowledgement_payload = f"DHCP Server Acknowledgement|null|null"
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return False


    def release(self, ip_address):
        print(f"Releasing IP address and updating DHCP table. IP address: {ip_address}")
        if ip_address in self.dhcp_table:
            self.dhcp_table[ip_address] = 1
