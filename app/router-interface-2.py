from classes.routerInterface import RouterInterface
from config import R1_2_CONFIG

router_interface = RouterInterface(**R1_2_CONFIG)
router_interface.start()