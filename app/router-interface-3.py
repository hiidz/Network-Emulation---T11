from classes.routerInterface import RouterInterface
from config import R1_3_CONFIG

router_interface = RouterInterface(**R1_3_CONFIG)
router_interface.start()