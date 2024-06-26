import base64
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def datagram_initialization(string):
    # Remove the braces from the string
    string = string[1:-1]

    # Extract data/payload
    data_index = string.find("data:") + len("data:")
    data_value = string[data_index:]
    string = string[:data_index]

    # Split the string by comma to separate key-value pairs
    pairs = string.split(",")

    # Create a dictionary to store the key-value pairs
    result = {}

    # Iterate through each key-value pair
    for pair in pairs:
        # Split each pair by colon to separate key and value
        key, value = pair.split(":")
        # Remove leading and trailing spaces from key and value
        key = key.strip()
        value = value.strip()
        # Add key-value pair to the dictionary
        result[key] = value

    # Add back data/payload
    result["data"] = data_value

    return result


pattern = {
    "frame": r"\{src:[a-zA-Z\d]{2},dest:[a-zA-Z\d]{2},dataLength:\d+,data:.+\}",
    "packet": r"\{src:0x[0-9a-fA-F]+,dest:0x[0-9a-fA-F]+,protocol:\w+,dataLength:\d+,data:.+\}",
    "arp_request": r"^Who has IP:*",
    "arp_response": r"^ARP Response\|(?P<ip_address>0x[0-9a-fA-F]+) is at (?P<mac_address>[^\s]+)$",
    "gratitous_arp": r"^Gratuitous ARP\|(?P<ip_address>0x[0-9a-fA-F]+) is now at (?P<mac_address>[^\s]+)$",
    "dhcp_offer": r"^DHCP Server Offer\|(null|(0x[a-fA-F0-9]{2}))$",
    "dhcp_discover": r"^DHCP Client Discover\|url:(.*)$",
    "dhcp_request": r"^DHCP Client Request\|(0x[a-fA-F0-9]{2})$",
    "dhcp_acknowledgement": r"^DHCP Server Acknowledgement\|ip:(null|(0x[a-fA-F0-9]{2})),dns_ip:(null|(0x[a-fA-F0-9]{2}))$",
    "dhcp_release": r"^DHCP Client Release\|(0x[a-fA-F0-9]{2})$",
    "dns_ip_broadcast": r"^DNS IP\|0x[a-fA-F0-9]{2}",
    "routing_setup": r"Routing Setup\|(0x[0-9a-fA-F]{2})\|(0x[0-9a-fA-F]{2})",
    "routing_acknowledgement": r"Routing Acknowledgement\|(True|False)",
    # {ip}|{netmask}|{port}|{self.routing_table}"
    "routing_router_setup": r"Routing Setup Router\|(0x[0-9a-fA-F]{2})\|(0x[0-9a-fA-F]{2})\|(\d+)\|(.+)",
    "routing_router_acknowledgement": r"Routing Router Acknowledgement\|(0x[0-9a-fA-F]{2})\|(0x[0-9a-fA-F]{2})\|(\d+)\|(.+)",
    "routing_broadcast": r"Routing Table Broadcast\|(.+)"
}


# Convert dictionary to JSON string
def dict_to_json_string(data_dict):
    return json.dumps(data_dict)


# Convert JSON string to dictionary
def json_string_to_dict(json_string):
    return json.loads(json_string)


def encrypt(plaintext, encryption_key):
    # Convert plaintext to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    # Also ensure the encryption_key is in bytes
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode()

    # Pad plaintext to be a multiple of 16 bytes (AES block size)
    padded_plaintext = pad(plaintext, AES.block_size)

    # Create a new AES cipher
    cipher = AES.new(encryption_key, AES.MODE_ECB)

    # Encrypt the padded plaintext
    encrypted = cipher.encrypt(padded_plaintext)

    # Encode encrypted data in base64 to make it safe for transport or storage
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt(encrypted_text, encryption_key):
    # Decode the encrypted text from base64
    decoded_encrypted_text = base64.b64decode(encrypted_text)

    # Create a new AES cipher
    cipher = AES.new(encryption_key, AES.MODE_ECB)

    # Decrypt the data
    decrypted = cipher.decrypt(decoded_encrypted_text)

    # Unpad the decrypted data and return it as a string
    unpadded_decrypted = unpad(decrypted, AES.block_size)

    return unpadded_decrypted.decode('utf-8')


def is_data_encrypted(data):
    # Check if data is binary
    if isinstance(data, bytes):
        try:
            # Attempt to decode to UTF-8 string
            decoded_data = data.decode('utf-8')

            # Check if the decoded data is JSON
            json.loads(decoded_data)
            return False
        except (UnicodeDecodeError, json.JSONDecodeError):
            return True  # Data is binary and not JSON, could be encrypted

    # If it's not binary, check if it's a JSON string
    try:
        json.loads(data)
        return False
    except json.JSONDecodeError:
        return True

    return False  # Default case if no other conditions are met


def ensure_bytes(key):
    """
    Ensure that the key is in bytes format.

    Args:
    key (str or bytes): The key to be converted to bytes.

    Returns:
    bytes: The key in bytes format.
    """
    if isinstance(key, str):
        # Convert string to bytes
        return key.encode()
    elif isinstance(key, bytes):
        # Key is already in bytes
        return key
    else:
        raise TypeError("Key must be a string or bytes, not {}".format(type(key).__name__))


def bytes_to_string(byte_data):
    """
    Convert bytes to a string.

    Args:
    byte_data (bytes): The byte data to be converted to a string.

    Returns:
    str: The byte data converted to a string.
    """
    if isinstance(byte_data, bytes):
        # Convert bytes to string
        return byte_data.decode()
    else:
        raise TypeError("Input must be bytes, not {}".format(type(byte_data).__name__))


def encrypt_ip_datagram(ip_datagram, encryption_key, dest_ip):
    print("Starting encrypt_ip_datagram function")
    json_string_ip_datagram = dict_to_json_string(ip_datagram)
    print(f"JSON string: {json_string_ip_datagram}")
    bytes_ip_datagram = ensure_bytes(json_string_ip_datagram)
    print(f"Bytes IP Datagram: {bytes_ip_datagram}")
    encrypted_ip_datagram = encrypt(bytes_ip_datagram, encryption_key)
    print(f"Encrypted IP Datagram: {encrypted_ip_datagram}")
    src_ip = ip_datagram["src"]
    destination_ip = dest_ip
    protocol = "encrypted"
    length = len(encrypted_ip_datagram)

    # Construct new payload with base64 encoded encrypted data
    new_payload = f"{{src:{src_ip},dest:{destination_ip},protocol:{protocol},dataLength:{length},data:{encrypted_ip_datagram}}}"
    new_ip_datagram = datagram_initialization(new_payload)

    print("Completed encrypt_ip_datagram function")
    return new_ip_datagram
