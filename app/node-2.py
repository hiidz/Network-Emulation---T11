from classes.node import Node
from config import N2_CONFIG

node_2 = Node(
    N2_CONFIG["node_mac"],
    N2_CONFIG["default_routing_table"],
    N2_CONFIG["default_routing_port"],
    is_malicious=True,
)
node_2.start()
