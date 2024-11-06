import socket
import struct


def create_dns_query(domain):
    request_id = 0x1234
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(
        ">HHHHHH", request_id, flags, qdcount, ancount, nscount, arcount
    )

    question = b""
    for part in domain.split("."):
        question += struct.pack("B", len(part)) + part.encode("utf-8")
    question += b"\x00"

    qtype = 1
    qclass = 1
    question += struct.pack(">HH", qtype, qclass)

    return header + question


def send_dns_query(domain, server_ip="127.0.0.1", server_port=2053):
    query = create_dns_query(domain)

    print(query)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(query, (server_ip, server_port))

        try:
            response, _ = sock.recvfrom(512)
            print("Ответ от сервера получен:")
            print(response)
        except socket.timeout:
            print("Время ожидания ответа истекло")


send_dns_query("yandex.maps.me")
