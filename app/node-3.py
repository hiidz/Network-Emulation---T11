from classes.node import Node
from config import N3_CONFIG

node_3 = Node(
    N3_CONFIG["node_mac"],
    N3_CONFIG["default_routing_table"],
    N3_CONFIG["url"],
    has_firewall=True,
    vpn_ip_address=N3_CONFIG["vpn_interface"],
    vpn_gateway=N3_CONFIG["vpn_gateway"],
    encryption_key=N3_CONFIG["encryption_key"]
)

node_3.start()
