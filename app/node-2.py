from classes.node import Node
from config import N2_CONFIG

default_routing_table = {
    "default": {"netmask": "0x00", "gateway": "0x21", "port": 8200}
}

node_2 = Node(
    N2_CONFIG["node_mac"],
    N2_CONFIG["interface_ip"],
    N2_CONFIG["interface_port"],
    default_routing_table,
    is_malicious=True,
)
node_2.start()
