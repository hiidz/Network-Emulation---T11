class DHCP_Server_Protocol:
    dhcp_table = {}

    def __init__(self, IPaddressList):
        for addr in IPaddressList:
            # 1 = IP address available, 0 = ip address unavailale
            self.dhcp_table[addr] = 1

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
            offer_payload = f"DHCP Server Offer|{ip_address_assigned}"
            conn.send(bytes(offer_payload, "utf-8"))
            return ip_address_assigned
        else:
            offer_payload = f"DHCP Server Offer|null"
            conn.send(bytes(offer_payload, "utf-8"))
            return False
        # server_mac|client_mac|datalength|DHCP Server Offer


    def acknowledgement(self, conn, ip_address):
        if self.dhcp_table[ip_address] == 1:
            acknowledgement_payload = f"DHCP Server Acknowledgement|{ip_address}"
            self.dhcp_table[ip_address] = 0
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return ip_address
        else:
            acknowledgement_payload = f"DHCP Server Acknowledgement|null"
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return False
        # server_mac|client_mac|datalength|DHCP Server Acknowledgement

    def release(self, ip_address):
        self.dhcp_table[ip_address] = 1
