def datagram_initialization(string):
    # Remove the braces from the string
    string = string[1:-1]

    # Extract data/payload
    data_index = string.find('data:') + len('data:')
    data_value = string[data_index:]
    string = string[:data_index]

    # Split the string by comma to separate key-value pairs
    pairs = string.split(',')
    

    # Create a dictionary to store the key-value pairs
    result = {}

    # Iterate through each key-value pair
    for pair in pairs:
        # Split each pair by colon to separate key and value
        key, value = pair.split(':')
        # Remove leading and trailing spaces from key and value
        key = key.strip()
        value = value.strip()
        # Add key-value pair to the dictionary
        result[key] = value

    # Add back data/payload
    result['data'] = data_value

    return result


frame_pattern = r"\{src:[a-zA-Z\d]{2},dest:[a-zA-Z\d]{2},dataLength:\d+,data:.+\}"
packet_pattern = r"\{src:0x[0-9a-fA-F]+,dest:0x[0-9a-fA-F]+,protocol:\w+,dataLength:\d+,data:.+\}"
arp_request_pattern = r"^Who has IP:*"
gratitous_arp_pattern = r"^Gratuitous ARP*"

