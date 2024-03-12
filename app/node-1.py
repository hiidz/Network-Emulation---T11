from classes.node import Node
from config import N1_CONFIG

node_1 = Node(
    N1_CONFIG["node_mac"],
    N1_CONFIG["default_routing_table"],
    N1_CONFIG["default_routing_port"]
)
node_1.start()
