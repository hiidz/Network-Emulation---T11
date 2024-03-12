from typing import Dict, List
import os


def print_brk():
    try:
        columns = os.get_terminal_size().columns
    except OSError:
        columns = 80  # Default width if terminal size can't be determined
    print('-' * columns)


def input_ip_sequence(prompt: str) -> str:
    ip_to_add = input(prompt)
    valid_input = True if ip_to_add[:2] == "0x" else False
    while not valid_input:
        ip_to_add = input("Invalid input, please enter a valid IP (e.g., 0x1A).\n> ")
        valid_input = True if ip_to_add[:2] == "0x" else False

    return ip_to_add


class Firewall:
    incoming_blacklist: List[str]
    incoming_whitelist: List[str]
    outgoing_blacklist: List[str]
    outgoing_whitelist: List[str]
    blacklist_disabled: bool
    whitelist_disabled: bool

    def __init__(
            self,
            incoming_blacklist: List[str] = [],
            incoming_whitelist: List[str] = [],
            outgoing_blacklist: List[str] = [],
            outgoing_whitelist: List[str] = [],
            blacklist_disabled: bool = False,
            whitelist_disabled: bool = True,
    ):
        self.incoming_blacklist = incoming_blacklist
        self.incoming_whitelist = incoming_whitelist
        self.outgoing_blacklist = outgoing_blacklist
        self.outgoing_whitelist = outgoing_whitelist
        self.blacklist_disabled = blacklist_disabled
        self.whitelist_disabled = whitelist_disabled

    def __str__(self) -> str:
        return

    def add_to_incoming_blacklist(self, ip_add: str):
        if ip_add not in self.incoming_blacklist:
            self.incoming_blacklist.append(ip_add)
            print(f"IP {ip_add} successfully added to incoming blacklist.")
        else:
            print("IP already in incoming blacklist.")
        print_brk()

    def remove_from_incoming_blacklist(self, ip_add: str):
        if ip_add in self.incoming_blacklist:
            self.incoming_blacklist.remove(ip_add)
            print(f"IP {ip_add} removed from incoming blacklist.")
        else:
            print("IP is currently not in incoming blacklist.")
        print_brk()

    def add_to_outgoing_blacklist(self, ip_add: str):
        if ip_add not in self.outgoing_blacklist:
            self.outgoing_blacklist.append(ip_add)
            print(f"IP {ip_add} successfully added to outgoing blacklist.")
        else:
            print("IP already in outgoing blacklist.")
        print_brk()

    def remove_from_outgoing_blacklist(self, ip_add: str):
        if ip_add in self.outgoing_blacklist:
            self.outgoing_blacklist.remove(ip_add)
            print(f"IP {ip_add} removed from outgoing blacklist.")
        else:
            print("IP is currently not in outgoing blacklist.")
        print_brk()

    def add_to_incoming_whitelist(self, ip_add: str):
        if ip_add not in self.incoming_whitelist:
            self.incoming_whitelist.append(ip_add)
            print(f"IP {ip_add} successfully added to incoming whitelist.")
        else:
            print("IP already in incoming whitelist.")
        print_brk()

    def remove_from_incoming_whitelist(self, ip_add: str):
        if ip_add in self.incoming_whitelist:
            self.incoming_whitelist.remove(ip_add)
            print(f"IP {ip_add} removed from incoming whitelist.")
        else:
            print("IP is currently not in incoming whitelist.")
        print_brk()

    def add_to_outgoing_whitelist(self, ip_add: str):
        if ip_add not in self.outgoing_whitelist:
            self.outgoing_whitelist.append(ip_add)
            print(f"IP {ip_add} successfully added to outgoing whitelist.")
        else:
            print("IP already in outgoing whitelist.")
        print_brk()

    def remove_from_outgoing_whitelist(self, ip_add: str):
        if ip_add in self.outgoing_whitelist:
            self.outgoing_whitelist.remove(ip_add)
            print(f"IP {ip_add} removed from outgoing whitelist.")
        else:
            print("IP is currently not in outgoing whitelist.")
        print_brk()

    def is_disabled(self):
        '''
          Returns True if both whitelisting and blacklisting disabled.
          Otherwise, return False.
        '''
        return not (self.blacklist_disabled or self.whitelist_disabled)

    def enable_whitelist(self):
        self.whitelist_disabled = False
        print("Whitelisting firewall successfully enabled.")
        print_brk()

    def disable_whitelist(self):
        self.whitelist_disabled = True
        print("Whitelisting firewall successfully disabled.")
        print_brk()

    def enable_blacklist(self):
        self.blacklist_disabled = False
        print("Blacklisting firewall successfully enabled.")
        print_brk()

    def disable_blacklist(self):
        self.blacklist_disabled = True
        print("Blacklisting firewall successfully disabled.")
        print_brk()

    def get_incoming_blacklist(self) -> List:
        return self.incoming_blacklist

    def get_outgoing_blacklist(self) -> List:
        return self.outgoing_blacklist

    def get_incoming_whitelist(self) -> List:
        return self.incoming_whitelist

    def get_outgoing_whitelist(self) -> List:
        return self.outgoing_whitelist

    def is_allowed_incoming(self, ip_address: str) -> bool:
        if not self.blacklist_disabled and ip_address in self.incoming_blacklist:
            return False
        if not self.whitelist_disabled and ip_address not in self.incoming_whitelist:
            return False
        return True

    def is_allowed_outgoing(self, ip_address: str) -> bool:
        if not self.blacklist_disabled and ip_address in self.outgoing_blacklist:
            return False
        if not self.whitelist_disabled and ip_address not in self.outgoing_whitelist:
            return False
        return True

    def handle_firewall_input(self, has_top_break: bool = True):
        if has_top_break:
            print_brk()

        print("Command list for firewall")
        print("- s \t\t\t Display current status of firewall.")
        print("- b -list \t\t View the current incoming/outgoing blacklist for this node.")
        print("- b -add \t\t Add a node to the incoming/outgoing blacklist.")
        print("- b -remove \t Remove a node from the incoming/outgoing blacklist.")
        print("- b -on \t\t Enable blacklist firewall.")
        print("- b -off \t\t Disable blacklist firewall.")
        print("- w -list \t\t View the current incoming/outgoing whitelist for this node.")
        print("- w -add \t\t Add a node to the incoming/outgoing whitelist.")
        print("- w -remove \t Remove a node from the incoming/outgoing whitelist.")
        print("- w -on \t\t Enable whitelist firewall.")
        print("- w -off \t\t Disable whitelist firewall.")
        print_brk()

        user_input = input("> ")

        if user_input == "s":
            print(f"Blacklisting currently enabled: {not self.blacklist_disabled}")
            print(f"Whitelisting currently enabled: {not self.whitelist_disabled}")
            print_brk()

        elif user_input == "b -list":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                print(f"Current incoming blacklisted IPs are: {self.get_incoming_blacklist()}.")
            elif network_direction == "outgoing":
                print(f"Current outgoing blacklisted IPs are: {self.get_outgoing_blacklist()}.")
            else:
                print("Invalid Command.")
            print_brk()

        elif user_input == "b -add":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to incoming blacklist?\n> ")
                self.add_to_incoming_blacklist(ip_to_add)
            elif network_direction == "outgoing":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to outgoing blacklist?\n> ")
                self.add_to_outgoing_blacklist(ip_to_add)
            else:
                print("Invalid Command.")

        elif user_input == "b -remove":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to remove from incoming "
                                              "blacklist?\n> ")
                self.remove_from_incoming_blacklist(ip_to_add)
            elif network_direction == "outgoing":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to remove from outgoing "
                                              "blacklist?\n> ")
                self.remove_from_outgoing_blacklist(ip_to_add)
            else:
                print("Invalid Command.")

        elif user_input == "b -on":
            self.enable_blacklist()

        elif user_input == "b -off":
            self.disable_blacklist()

        elif user_input == "w -list":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                print(f"Current whitelisted IPs: {self.get_incoming_whitelist()}.")
            elif network_direction == "outgoing":
                print(f"Current whitelisted IPs: {self.get_outgoing_whitelist()}.")
            else:
                print("Invalid Command.")
            print_brk()

        elif user_input == "w -add":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to incoming whitelist?\n> ")
                self.add_to_incoming_whitelist(ip_to_add)
            elif network_direction == "outgoing":
                ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to outgoing whitelist?\n> ")
                self.add_to_outgoing_whitelist(ip_to_add)
            else:
                print("Invalid Command.")

        elif user_input == "w -remove":
            network_direction = input("Please enter incoming/outgoing: ")
            if network_direction == "incoming":
                ip_to_add = input_ip_sequence(
                    "What is the value of the IP you wish to remove from incoming whitelist?\n> ")
                self.remove_from_incoming_whitelist(ip_to_add)
            elif network_direction == "outgoing":
                ip_to_add = input_ip_sequence(
                    "What is the value of the IP you wish to remove from outgoing whitelist?\n> ")
                self.remove_from_outgoing_whitelist(ip_to_add)
            else:
                print("Invalid Command.")

        elif user_input == "w -on":
            self.enable_whitelist()

        elif user_input == "w -off":
            self.disable_whitelist()

        else:
            print_brk()
            print("Invalid Command.")
            print("Command list for firewall")
            print("- s \t\t\t Display current status of firewall.")
            print("- b -list \t\t View the current incoming/outgoing blacklist for this node.")
            print("- b -add \t\t Add a node to the incoming/outgoing blacklist.")
            print("- b -remove \t Remove a node from the incoming/outgoing blacklist.")
            print("- b -on \t\t Enable blacklist firewall.")
            print("- b -off \t\t Disable blacklist firewall.")
            print("- w -list \t\t View the current incoming/outgoing whitelist for this node.")
            print("- w -add \t\t Add a node to the incoming/outgoing whitelist.")
            print("- w -remove \t Remove a node from the incoming/outgoing whitelist.")
            print("- w -on \t\t Enable whitelist firewall.")
            print("- w -off \t\t Disable whitelist firewall.")
            print_brk()
