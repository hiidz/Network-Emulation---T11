import os

def print_brk():
    print('-' * os.get_terminal_size().columns)

class Attacks:
  is_sniffing = False
  is_ip_spoofing = False

  def show_status(self) -> None:
    if self.is_sniffing:
      print("Node sniffing enabled.")
    else:
      print("Node sniffing disabled.")
    if self.is_ip_spoofing:
      print("Node is spoofing IP.")
    else:
      print("Node is not spoofing IP.")
    print_brk()
      

  def enable_sniffing(self) -> None:
    self.is_sniffing = True
    print("Sniffing has been enabled.")
    print_brk()

  def disable_sniffing(self) -> None:
    self.is_sniffing = False
    print("Sniffing has been disabled.")
    print_brk()
  
  def enable_ip_spoofing(self) -> None:
    self.is_ip_spoofing = True
    print("IP spoofing has been enabled.")
    print_brk()

  def disable_ip_spoofing(self) -> None:
    self.is_ip_spoofing = False
    print("IP spoofing has been disabled.")
    print_brk()

  def handle_sniffer_input(self, has_top_break: bool = True):
    if has_top_break:
      print_brk()

    print("Commands to configure sniffer:")
    print("- (s)tatus \t\t Shows if sniffing has been activated.")
    print("- (d)isable \t\t Disable sniffing.")
    print("- (e)nable \t\t Enable sniffing.")
    print("- (es) \t Enable IP spoofing.")
    print("- (ds) \t Disable IP spoofing.")
    print_brk()

    user_input = input("> ")

    if user_input == "status" or user_input == "s":
      self.show_status()

    elif user_input == "disable" or user_input == "d":
      self.disable_sniffing()

    elif user_input == "enable" or user_input == "e":
      self.enable_sniffing()
    
    elif user_input == "es":
      self.enable_ip_spoofing()
    
    elif user_input == "ds":
      self.disable_ip_spoofing()

    else:
            print_brk()
            print("Commands to configure sniffer:")
            print("- (s)tatus \t\t Shows if sniffing has been activated.")
            print("- (d)isable \t\t Disable sniffing.")
            print("- (e)nable \t\t Enable sniffing.")
            print("- (e)enable (s)poofing \t Enable IP spoofing.")
            print("- (d)disable (s)poofing \t Disable IP spoofing.")
            print_brk()