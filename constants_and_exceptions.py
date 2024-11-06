DNS_PORT = 2053
ROOT_SERVERS = ['192.58.128.30', "198.41.0.4", "199.9.14.201", "192.33.4.12",]


class DNSFormatError(Exception):
    pass


class DNSNXDomainError(Exception):
    pass


class DNSTimeoutError(Exception):
    pass


class DNSError(Exception):
    pass
