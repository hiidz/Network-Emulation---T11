HOST = "localhost"
R1_1_PORT = 8100
R1_2_PORT = 8200

R1_1_CONFIG = {
  "interface_ip_address": "0x11",
  "interface_mac": "R1",
  "interface_port": R1_1_PORT,
  "subnet_mask": 1,
  "ip_address_available": ['0x1A']
}

R1_2_CONFIG = {
  "interface_ip_address": "0x21",
  "interface_mac": "R2",
  "interface_port": R1_2_PORT,
  "subnet_mask": 1,
  "ip_address_available": ['0x2A', '0x2B'],
  "connected_interface_port": R1_1_PORT
}

N1_CONFIG = {
  "node_ip_address": "0x1A",
  "node_mac": "N1",
  "interface_mac": R1_1_CONFIG["interface_mac"], 
  "interface_port": R1_1_PORT
}

N2_CONFIG = {
  "node_ip_address": "0x2A",
  "node_mac": "N2",
  "interface_mac": R1_2_CONFIG["interface_mac"],  
  "interface_port": R1_2_PORT
}

N3_CONFIG = {
  "node_ip_address": "0x2B",
  "node_mac": "N3",
  "interface_mac": R1_2_CONFIG["interface_mac"], 
  "interface_port": R1_2_PORT
}