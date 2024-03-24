from classes.node import Node
from config import N4_CONFIG

node_4 = Node(
    N4_CONFIG["node_mac"],
    N4_CONFIG["default_routing_table"],
    N4_CONFIG["url"],
    has_firewall=True,
    vpn_ip_address=N4_CONFIG["vpn_interface"],
    vpn_gateway=N4_CONFIG["vpn_gateway"],
    encryption_key=N4_CONFIG["encryption_key"]
)

node_4.start()
