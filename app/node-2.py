from classes.node import Node
from config import N2_CONFIG

node_2 = Node(
    N2_CONFIG["node_mac"],
    N2_CONFIG["default_routing_table"],
    N2_CONFIG["url"],
    is_malicious=True,
    vpn_ip_address=N2_CONFIG["vpn_interface"],
    vpn_gateway=N2_CONFIG["vpn_gateway"],
    encryption_key=N2_CONFIG["encryption_key"]
)
node_2.start()
