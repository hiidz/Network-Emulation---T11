from classes.routerInterface import RouterInterface
from config import R3_2_CONFIG, VPN_GATEWAY_CONFIG

router_interface = RouterInterface(**R3_2_CONFIG, vpn_table=VPN_GATEWAY_CONFIG["vpn_table_for_router"], encryption_key_table=VPN_GATEWAY_CONFIG["encryption_key_table"])
router_interface.start()