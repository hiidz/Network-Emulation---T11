import os
import pyshark
import json
from util import datagram_initialization


class Attacks:
    is_sniffing = False
    capture = None
    ip_address_sniffed = None

    def sniff_packet_handler(self, pkt):
        # Extract packet details
        src_port = pkt[pkt.transport_layer].srcport
        dst_port = pkt[pkt.transport_layer].dstport
        protocol = pkt.transport_layer

        if dst_port == "8200" or src_port == "8200":
            if hasattr(pkt, "data"):
                data = str(pkt.data.data)
                data = data.replace(":", "")
                data = bytes.fromhex(data).decode("utf-8")
            else:
                data = "no data"
            if "Who has IP" in data or "Gratuitous ARP" in data:
                print("PACKET FOUND: It is a ARP request")
            elif data == "no data":
                print("PACKET FOUND: No data found")
            elif "ARP Response" in data:
                print("PACKET FOUND: ARP response")
            else:

                ip_datagram = data.split("{")[2]
                attributes = ip_datagram.split(",")
                src_configured_ip = attributes[0].split(":")[1]
                dest_configured_ip = attributes[1].split(":")[1]
                if (
                    src_configured_ip == self.ip_address_sniffed
                    or dest_configured_ip == self.ip_address_sniffed
                ):
                    print(f"PACKET FOUND: Protocol: {protocol}, Data: {data}")
                else:
                    print("Not what we are sniffing for so dropping")

    def enable_sniffing(self):
        self.is_sniffing = True
        self.capture = pyshark.LiveCapture(
            interface="lo0",
            bpf_filter="port 8200",
            include_raw=True,
            use_json=True,
        )

        print("----Begin sniffing session-----")
        user_input = input("Please enter which IP address you want to sniff: ")
        self.ip_address_sniffed = user_input
        print(
            f"\n---Begin sniffing packets with IP address {self.ip_address_sniffed}---"
        )
        print("Press CTRL+C to end sniffing session")
        try:
            for pkt in self.capture.sniff_continuously(packet_count=10):
                self.sniff_packet_handler(pkt)
        except KeyboardInterrupt:
            print("\n----Ended sniffing session-----")
            self.capture.close()
        finally:
            # End the capture session
            self.capture.close()

    def handle_sniffer_input(self):
        print("Commands to configure sniffer:")
        print("- (e)nable \t\t Enable sniffing.")

        user_input = input("> ")

        if user_input == "enable" or user_input == "e":
            self.enable_sniffing()

        else:
            print("Commands to configure sniffer:")
            print("- (e)nable \t\t Enable sniffing.")
