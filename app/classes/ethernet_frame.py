class EthernetFrame:
    ethernet_frame = {}

    def __init__(self):
        self.ethernet_frame = {}

    def create(self, src_mac, dest_mac, data):

        self.ethernet_frame['src'] = src_mac
        self.ethernet_frame['dest'] = dest_mac
        self.ethernet_frame['dataLength'] = len(data)
        self.ethernet_frame['data'] = data

        return self.ethernet_frame

    def convert_to_valid_payload(self):
        extracted_data = self.ethernet_frame['data']['data']

        str_payload = str(self.ethernet_frame)
        print(str_payload)

        payload_trimmed = str_payload.replace(' ', '').replace("'", "")
        split_string = payload_trimmed.rsplit("data:", 1)
        final_payload = split_string[0] + "data:" + extracted_data + "}}"

        return final_payload

    def extract_data(self):
        return self.ethernet_frame['data']

    def get(self):
        return self.ethernet_frame
