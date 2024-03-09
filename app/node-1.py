from classes.node import Node
from config import N1_CONFIG

default_routing_table = {
    "default": {"netmask": "0x00", "gateway": "0x11", "port": 8100}
}
node_1 = Node(
    N1_CONFIG["node_mac"],
    N1_CONFIG["interface_ip"],
    N1_CONFIG["interface_port"],
    default_routing_table,
)
node_1.start()
