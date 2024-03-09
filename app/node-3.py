from classes.node import Node
from config import N3_CONFIG

default_routing_table = {
    "default": {"netmask": "0x00", "gateway": "0x21", "port": 8200}
}

node_3 = Node(
    N3_CONFIG["node_mac"],
    N3_CONFIG["interface_ip"],
    N3_CONFIG["interface_port"],
    default_routing_table,
    has_firewall=True
)

node_3.start()
