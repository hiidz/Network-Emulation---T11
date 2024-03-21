class DHCP_Server_Protocol:
    dhcp_table = {}

    def __init__(self, IPaddressList):
        for addr in IPaddressList:
            # 1 = IP address available, 0 = ip address unavailale
            self.dhcp_table[addr] = 1
        self.conn_url = None

    def get_dhcp_table(self):
        return self.dhcp_table

    def get_available_ip_address(self):
        for addr, availability in self.dhcp_table.items():
            if availability == 1:
                return addr

        return None

    def offer(self, conn, conn_url):
        self.conn_url = conn_url
        ip_address_assigned = self.get_available_ip_address()
        if ip_address_assigned != None:
            print(f"Sending DHCP Offer. IP address: {ip_address_assigned}")
            offer_payload = f"DHCP Server Offer|{ip_address_assigned}"
            conn.send(bytes(offer_payload, "utf-8"))
            return ip_address_assigned
        else:
            print(
                f"Sending DHCP Offer. No IP Address available. IP address: {ip_address_assigned}"
            )
            offer_payload = f"DHCP Server Offer|null"
            conn.send(bytes(offer_payload, "utf-8"))
            return False

    def acknowledgement(self, conn, dhcp_ip, ip_address, dns_server_ip, dns_conn):
        # Need to send the IP address to the DNS server as well
        if self.dhcp_table[ip_address] == 1:
            print(
                f"Sending DHCP Acknowledgement and updating DHCP table. IP address: {ip_address}"
            )
            data = f"DNS_UPDATE|url:{self.conn_url},ip:{ip_address}"
            payload = f"{{src:{dhcp_ip},dest:{dns_server_ip},protocol:dns_update,dataLength:5,data:{data}}}"
            dns_conn.send(bytes(payload, "utf-8"))

            # dns_conn.send(bytes(f"DNS UPDATE|url:{self.conn_url},new_ip:{ip_address}", "utf-8"))
            acknowledgement_payload = (
                f"DHCP Server Acknowledgement|ip:{ip_address},dns_ip:{dns_server_ip}"
            )
            self.dhcp_table[ip_address] = 0
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return ip_address

        else:
            print(
                f"Sending DHCP Acknowledgement. IP address no longer available. IP address: {ip_address}"
            )
            acknowledgement_payload = f"DHCP Server Acknowledgement|null"
            conn.send(bytes(acknowledgement_payload, "utf-8"))
            return False

    def release(self, ip_address):
        print(f"Releasing IP address and updating DHCP table. IP address: {ip_address}")
        if ip_address in self.dhcp_table:
            self.dhcp_table[ip_address] = 1
