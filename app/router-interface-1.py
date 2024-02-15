from classes.routerInterface import RouterInterface
from config import R1_1_CONFIG

router_interface = RouterInterface(**R1_1_CONFIG)
router_interface.start()