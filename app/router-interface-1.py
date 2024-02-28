from classes.routerInterface import RouterInterface
from config import R1_1_CONFIG

router_interface = RouterInterface(**R1_1_CONFIG)
router_interface.configure_default_routing_table('0x2', 'Ox21')
router_interface.start()