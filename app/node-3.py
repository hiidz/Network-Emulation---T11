from classes.node import Node
from config import N3_CONFIG

node_3 = Node(
    N3_CONFIG["node_mac"],
    N3_CONFIG["default_routing_table"],
    has_firewall=True
)

node_3.start()
