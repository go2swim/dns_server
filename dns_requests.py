import socket

from constants_and_exceptions import (
    ROOT_SERVERS,
    DNSError,
    DNSNXDomainError,
    DNSTimeoutError,
    DNSFormatError,
)
from dns_parsing import create_dns_request, DNSParser


class DNSResolver:
    def __init__(self, max_iterations=8, timeout=2):
        self.max_iterations = max_iterations
        self.timeout = timeout

    def resolve(self, domain):
        current_servers = ROOT_SERVERS

        for _ in range(self.max_iterations):
            for server in current_servers:
                try:
                    response = self._query_dns(server, domain)
                    print(f"Response from {server}: {response}")

                    answers, authority, additional = DNSParser.parse_dns_response(
                        response
                    )
                    ip_addresses = self._extract_ip_addresses(answers)

                    if ip_addresses:
                        return ip_addresses

                    next_servers = self._get_next_servers(authority, additional)
                    if next_servers:
                        current_servers = next_servers
                        break
                except (
                    DNSTimeoutError,
                    DNSNXDomainError,
                    DNSFormatError,
                    DNSError,
                ) as e:
                    print(f"Error with server {server}: {e}")
                    continue
        return None

    def _query_dns(self, server, domain):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        dns_request = create_dns_request(domain)
        sock.sendto(dns_request, (server, 53))
        response, _ = sock.recvfrom(512)
        sock.close()
        return response

    def _extract_ip_addresses(self, answers):
        return [answer[2] for answer in answers if answer[1] in (1, 28)]

    def _get_next_servers(self, authority, additional):
        next_servers = []
        for record in authority:
            if record[1] == 2:
                ns_ip = self._find_ip(additional, record[2])
                if ns_ip:
                    next_servers.append(ns_ip)
                else:

                    ns_ips = self.resolve(record[2])
                    if ns_ips:
                        next_servers.extend(ns_ips)
        return next_servers

    def _find_ip(self, additional, ns_name):
        return next(
            (
                record[2]
                for record in additional
                if record[0] == ns_name and record[1] in (1, 28)
            ),
            None,
        )
