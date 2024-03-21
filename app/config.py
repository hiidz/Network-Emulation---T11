HOST = "localhost"
R1_1_PORT = 8100
R1_2_PORT = 8200
R1_3_PORT = 8300


R1_1_CONFIG = {
    "interface_ip_address": "0x11",
    "interface_mac": "R1",
    "interface_port": R1_1_PORT,
    "subnet_mask": "0xF0",
    "ip_address_available": ["0x1A"],
}

R1_2_CONFIG = {
    "interface_ip_address": "0x21",
    "interface_mac": "R2",
    "interface_port": R1_2_PORT,
    "subnet_mask": "0xF0",
    "ip_address_available": ["0x2A", "0x2B"],
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_1_CONFIG["interface_ip_address"],
            "port": R1_1_CONFIG["interface_port"],
        }
    },
}

R1_3_CONFIG = {
    "interface_ip_address": "0x31",
    "interface_mac": "R3",
    "interface_port": R1_3_PORT,
    "subnet_mask": "0xF0",
    "ip_address_available": ["0x3A", "0x3B"],
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_1_CONFIG["interface_ip_address"],
            "port": R1_1_CONFIG["interface_port"],
        },
        "0x21": {
            "netmask": "0xF0",
            "gateway": R1_2_CONFIG["interface_ip_address"],
            "port": R1_2_CONFIG["interface_port"],
        },
    },
}

N1_CONFIG = {
    "node_mac": "N1",
    "url": "www.node1.com",
    "interface_mac": R1_1_CONFIG["interface_mac"],
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_1_CONFIG["interface_ip_address"],
            "port": R1_1_CONFIG["interface_port"],
        }
    },
    "default_routing_port": R1_1_CONFIG["interface_port"],
    "vpn_interface": "0xA1",
    "vpn_gateway": "0x11",
    "encryption_key": "encryption_key_1"
}

N2_CONFIG = {
    "node_mac": "N2",
    "url": "www.node2.com",
    "interface_mac": R1_2_CONFIG["interface_mac"],
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_2_CONFIG["interface_ip_address"],
            "port": R1_2_CONFIG["interface_port"],
        }
    },
    "default_routing_port": R1_2_CONFIG["interface_port"],
    "vpn_interface": "0xA2",
    "vpn_gateway": "0x21",
    "encryption_key": "encryption_key_2"
}

N3_CONFIG = {
    "node_mac": "N3",
    "url": "www.node3.com",
    "interface_mac": R1_2_CONFIG["interface_mac"],
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_2_CONFIG["interface_ip_address"],
            "port": R1_2_CONFIG["interface_port"],
        }
    },
    "default_routing_port": R1_2_CONFIG["interface_port"],
    "vpn_interface": "0xA3",
    "vpn_gateway": "0x21",
    "encryption_key": "encryption_key_3"
}

DNS_SERVER_CONFIG = {
    "dns_mac": "D1",
    "dns_ip": "0x3A",
    "interface_mac": R1_3_CONFIG["interface_mac"],
    "default_routing_port": R1_3_CONFIG["interface_port"],
    "dns_table": {"www.node1.com": "", "www.node2.com": "", "www.node3.com": ""},
    "default_routing_table": {
        "default": {
            "netmask": "0xF0",
            "gateway": R1_3_CONFIG["interface_ip_address"],
            "hop": 1,
        }
    },
}

VPN_GATEWAY_CONFIG = {
    "vpn_table_for_router": {"0x1A": "0xA1", "0x2A": "0xA2", "0x2B": "0xA3"},
    "vpn_table_for_node": {"R1": "0x11", "R2": "0x21"},
    "encryption_key_table": {"0xA1": "encryption_key_1", "0xA2": "encryption_key_2", "0xA3": "encryption_key_3"}
}
