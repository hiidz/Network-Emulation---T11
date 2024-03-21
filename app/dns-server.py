from classes.DNS.dnsServer import DNSServer
from config import DNS_SERVER_CONFIG

dns_server = DNSServer(
    DNS_SERVER_CONFIG["dns_mac"],
    DNS_SERVER_CONFIG["dns_ip"],
    DNS_SERVER_CONFIG["default_routing_table"],
    DNS_SERVER_CONFIG["default_routing_port"],
    DNS_SERVER_CONFIG["dns_table"],
)

dns_server.start()
