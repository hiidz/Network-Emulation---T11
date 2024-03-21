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
    try:
        # Try to parse the data as JSON
        json.loads(data)
        return False  # Data is JSON, so probably not encrypted
    except json.JSONDecodeError:
        return True  # Data is not JSON, could be encrypted


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
