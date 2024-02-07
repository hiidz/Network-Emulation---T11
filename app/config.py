HOST = "localhost"
R1_1_PORT = 8100
R1_2_PORT = 8200

R1_1_CONFIG = {
  "network_int_ip_address": "0x11",
  "network_int_mac": "R1",
  "network_int_port": R1_1_PORT,
}

R1_2_CONFIG = {
  "network_int_ip_address": "0x21",
  "network_int_mac": "R2",
  "network_int_port": R1_2_PORT,
}

N1_CONFIG = {
  "node_ip_address": "0x1A",
  "node_mac": "N1",
  "network_int_mac": R1_1_CONFIG["network_int_mac"], 
  "network_int_port": R1_1_PORT,
}

N2_CONFIG = {
  "node_ip_address": "0x2A",
  "node_mac": "N2",
  "network_int_mac": R1_2_CONFIG["network_int_mac"],  
  "network_int_port": R1_2_PORT,
}

N3_CONFIG = {
  "node_ip_address": "0x2B",
  "node_mac": "N3",
  "network_int_mac": R1_2_CONFIG["network_int_mac"], 
  "network_int_port": R1_2_PORT,
}