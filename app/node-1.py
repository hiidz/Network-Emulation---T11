from classes.node import Node
from config import N1_CONFIG

node_1 = Node(
    N1_CONFIG["node_mac"],
    N1_CONFIG["default_routing_table"],
    N1_CONFIG["url"],
    vpn_ip_address=N1_CONFIG["vpn_interface"],
    vpn_gateway=N1_CONFIG["vpn_gateway"],
    encryption_key=N1_CONFIG["encryption_key"]
)
node_1.start()
