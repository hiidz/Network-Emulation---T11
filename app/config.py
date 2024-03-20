HOST = "localhost"
R1_1_PORT = 8100
R1_2_PORT = 8200
R1_3_PORT = 8300


R1_1_CONFIG = {
  "interface_ip_address": "0x11",
  "interface_mac": "R1",
  "interface_port": R1_1_PORT,
  "subnet_mask": "0xF0",
  "ip_address_available": ['0x1A'],
}

R1_2_CONFIG = {
  "interface_ip_address": "0x21",
  "interface_mac": "R2",
  "interface_port": R1_2_PORT,
  "subnet_mask": "0xF0",
  "ip_address_available": ['0x2A', '0x2B'],
  "default_routing_table": {"default": {"netmask": "0xF0", "gateway": R1_1_CONFIG["interface_ip_address"],  "port": R1_1_CONFIG["interface_port"]}},
}

R1_3_CONFIG = {
  "interface_ip_address": "0x31",
  "interface_mac": "R3",
  "interface_port": R1_3_PORT,
  "subnet_mask": "0xF0",
  "ip_address_available": ['0x3A', '0x3B'],
  "default_routing_table": {"default": {"netmask": "0xF0", "gateway": R1_1_CONFIG["interface_ip_address"], "port": R1_1_CONFIG["interface_port"]}, "0x21":{"netmask":"0xF0", "gateway": R1_2_CONFIG["interface_ip_address"], "port": R1_2_CONFIG["interface_port"]}},
}

N1_CONFIG = {
    "node_mac": "N1",
    "interface_mac": R1_1_CONFIG["interface_mac"],
    "default_routing_table": {"default": {"netmask": "0xF0", "gateway": R1_1_CONFIG["interface_ip_address"], "port": R1_1_CONFIG["interface_port"]}},
    "default_routing_port": R1_1_CONFIG["interface_port"]
}

N2_CONFIG = {
    "node_mac": "N2",
    "interface_mac": R1_2_CONFIG["interface_mac"],
    "default_routing_table": {"default": {"netmask": "0xF0", "gateway": R1_2_CONFIG["interface_ip_address"], "port": R1_2_CONFIG["interface_port"]}},
    "default_routing_port": R1_2_CONFIG["interface_port"]
}

N3_CONFIG = {
    "node_mac": "N3",
    "interface_mac": R1_2_CONFIG["interface_mac"],
    "default_routing_table": {"default": {"netmask": "0xF0", "gateway": R1_2_CONFIG["interface_ip_address"], "port": R1_2_CONFIG["interface_port"]}},
}
