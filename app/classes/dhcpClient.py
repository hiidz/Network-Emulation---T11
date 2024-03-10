class DHCP_Client_Protocol:

    # def __init__(self, IPaddressList):
    #     for addr in IPaddressList:
    #         # 1 = IP address available
    #         self.dhcp_table[addr] = 1


    def discover(self, connected_sockets, client_mac):
        discover_payload = "DHCP Client Discover"
        # {client_mac}|FF|datalength|DHCP Client Discover
        # discover_frame = f"{client_mac}|FF|{len(discover_payload)}|{discover_payload}"
        for conn in connected_sockets.values():
            # conn.send(bytes(discover_frame, "utf-8"))
            conn.send(bytes(discover_payload, "utf-8"))


    def request(self, conn, ip_address):
        request_payload = f"DHCP Client Request|{ip_address}"
        # client_mac|dhcp_mac|datalength|DHCP Client Request
        conn.send(bytes(request_payload, "utf-8"))


    def release(self, conn, client_mac, dhcp_mac):
        release_payload = ""
        # client_mac|dhcp_mac|datalength|DHCP Client Release
        conn.send(bytes(release_payload, "utf-8"))
