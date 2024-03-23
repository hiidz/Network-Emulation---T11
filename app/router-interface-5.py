from classes.routerInterface import RouterInterface
from config import R2_2_CONFIG

router_interface = RouterInterface(**R2_2_CONFIG)
router_interface.start()