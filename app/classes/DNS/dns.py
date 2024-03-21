class DNS_Protocol:
    # URL : IP Address
    dns_cache = {}

    def __init__(self):
        self.dns_cache = {}

    def lookup_dns_cache(self, url):
        dns_websites = self.dns_cache.keys()
        if url in dns_websites:
            return self.dns_cache[url]
        else:
            return None

    def add_dns_record(self, url: str, ip_address: str):
        self.dns_cache[url] = ip_address

    def remove_record(self, url):
        if self.dns_cache.get(url) is not None:
            del self.dns_cache[url]

    def get_dns_cache(self):
        return self.dns_cache
