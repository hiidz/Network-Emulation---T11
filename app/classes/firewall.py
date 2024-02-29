from typing import Dict, List
import os


def print_brk():
    print('-' * os.get_terminal_size().columns)


def input_ip_sequence(prompt: str) -> str:
    ip_to_add = input(prompt)
    valid_input = True if ip_to_add[:2] == "0x" else False
    while not valid_input:
        ip_to_add = input("Invalid input, please enter a valid IP (e.g., 0x1A).\n> ")
        valid_input = True if ip_to_add[:2] == "0x" else False

    return ip_to_add


class Firewall:
    blacklist: List[str]
    whitelist: List[str]
    blacklist_disabled: bool
    whitelist_disabled: bool

    def __init__(
            self,
            blacklist: List[str] = [],
            whitelist: List[str] = [],
            blacklist_disabled: bool = False,
            whitelist_disabled: bool = True,
    ):
        self.blacklist = blacklist
        self.whitelist = whitelist
        self.blacklist_disabled = blacklist_disabled
        self.whitelist_disabled = whitelist_disabled

    def __str__(self) -> str:
        return

    def add_to_blacklist(self, ip_add: str):
        if ip_add not in self.blacklist:
            self.blacklist.append(ip_add)
            print(f"IP {ip_add} successfully added to blacklist.")
        else:
            print("IP already in blacklist.")
        print_brk()

    def remove_from_blacklist(self, ip_add: str):
        if ip_add in self.blacklist:
            self.blacklist.remove(ip_add)
            print(f"IP {ip_add} removed from blacklist.")
        else:
            print("IP is currently not in blacklist.")
        print_brk()

    def add_to_whitelist(self, ip_add: str):
        if ip_add not in self.whitelist:
            self.whitelist.append(ip_add)
            print(f"IP {ip_add} successfully added to whitelist.")
        else:
            print("IP already in whitelist.")
        print_brk()

    def remove_from_whitelist(self, ip_add: str):
        if ip_add in self.whitelist:
            self.whitelist.remove(ip_add)
            print(f"IP {ip_add} removed from whitelist.")
        else:
            print("IP is currently not in whitelist.")
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

    def get_blacklist(self) -> List:
        return self.blacklist

    def get_whitelist(self) -> List:
        return self.whitelist

    def is_allowed(self, ip_address: str) -> bool:
        if not self.blacklist_disabled and ip_address in self.blacklist:
            return False
        if not self.whitelist_disabled and ip_address not in self.whitelist:
            return False
        return True

    def handle_whitelist_firewall_input(self, device: str, has_top_break: bool = True):
        if has_top_break:
            print_brk()

        print("Commands to configure firewall:")
        print("- w -list \t\t View the current whitelist for this node.")
        print("- w -add \t\t Add a node to the whitelist.")
        print("- w -remove \t\t Remove a node from the whitelist.")
        print("- w -off \t Disable firewall.")
        print("- w -on \t Enable firewall.")
        print_brk()

        user_input = input("> ")
        if user_input == "w -list":
            print(f"Current whitelisted IPs: {self.get_whitelist()}.")
            print_brk()

        elif user_input == "w -add":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to whitelist?\n> ")
            self.add_to_whitelist(ip_to_add)

        elif user_input == "w -remove":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to remove from whitelist?\n> ")
            self.remove_from_whitelist(ip_to_add)

        elif user_input == "w -off":
            self.disable_whitelist()

        elif user_input == "w -on":
            self.enable_whitelist()

        else:
            print_brk()
            print("Unidentified command. Please use a registered command...")
            print("Commands to configure firewall:")
            print("- w -list \t\t View the current whitelist for this node.")
            print("- w -add \t\t Add a node to the whitelist.")
            print("- w -remove \t\t Remove a node from the whitelist.")
            print("- w -off \t Disable firewall.")
            print("- w -on \t Enable firewall.")
            print_brk()

    def handle_firewall_input(self, has_top_break: bool = True):
        if has_top_break:
            print_brk()

        print("Commands to configure firewall:")
        print("- s \t\t Display current status of firewall.")
        print("- b -list \t\t View the current blacklist for this node.")
        print("- b -add \t\t Add a node to the blacklist.")
        print("- b -remove \t\t Remove a node from the blacklist.")
        print("- b -on \t\t Enable blacklist firewall.")
        print("- b -off \t\t Disable blacklist firewall.")
        print("- w -list \t\t View the current whitelist for this node.")
        print("- w -add \t\t Add a node to the whitelist.")
        print("- w -remove \t\t Remove a node from the whitelist.")
        print("- w -on \t\t Enable whitelist firewall.")
        print("- w -off \t\t Disable whitelist firewall.")
        print_brk()

        user_input = input("> ")

        if user_input == "s":
            print(f"Blacklisting currently enabled: {not self.blacklist_disabled}")
            print(f"Whitelisting currently enabled: {not self.whitelist_disabled}")
            print_brk()

        elif user_input == "b -list":
            print(f"Current blacklisted IPs are: {self.get_blacklist()}.")
            print_brk()

        elif user_input == "b -add":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to blacklist?\n> ")
            self.add_to_blacklist(ip_to_add)

        elif user_input == "b -remove":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to remove from blacklist?\n> ")
            self.remove_from_blacklist(ip_to_add)

        elif user_input == "b -on":
            self.enable_blacklist()

        elif user_input == "b -off":
            self.disable_blacklist()

        elif user_input == "w -list":
            print(f"Current whitelisted IPs: {self.get_whitelist()}.")
            print_brk()

        elif user_input == "w -add":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to add to whitelist?\n> ")
            self.add_to_whitelist(ip_to_add)

        elif user_input == "w -remove":
            ip_to_add = input_ip_sequence("What is the value of the IP you wish to remove from whitelist?\n> ")
            self.remove_from_whitelist(ip_to_add)

        elif user_input == "w -on":
            self.enable_whitelist()

        elif user_input == "w -off":
            self.disable_whitelist()

        else:
            print_brk()
            print("Unidentified command. Please use a registered command...")
            print("Commands to configure firewall:")
            print("- w -list \t\t View the current whitelist for this node.")
            print("- w -add \t\t Add a node to the whitelist.")
            print("- w -remove \t\t Remove a node from the whitelist.")
            print("- w -off \t Disable firewall.")
            print("- w -on \t Enable firewall.")
            print_brk()
