from constants_and_exceptions import DNS_PORT
from dns_parsing import parse_dns_query, ServerResponseParser
from dns_requests import DNSResolver
import socket


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", DNS_PORT))
    print("DNS сервер запущен...")

    while True:
        data, addr = sock.recvfrom(6413)
        print('a')
        domain = parse_dns_query(data)

        if domain:
            print(f"Запрос получен для домена: {domain}")
            ip = DNSResolver().resolve(domain)

            print(f'ip: {ip}')
            response = ServerResponseParser.create_dns_response(data, ip[0]) if ip \
                else ServerResponseParser.create_error_response(data)
            sock.sendto(response, addr)


if __name__ == "__main__":
    start_server()