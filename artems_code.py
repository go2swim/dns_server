import socket
import struct
import random
ROOT_SERVERS = ['192.58.128.30', "198.41.0.4", "199.9.14.201", "192.33.4.12",]


def iterative_query(domain_name: str) -> list[str]:
    next_servers = ROOT_SERVERS
    dns_query_a, transaction_id = create_dns_query(domain_name, query_type=1)  # IPv4
    dns_query_aaaa, _ = create_dns_query(domain_name, query_type=28)  # IPv6
    all_ips = []

    for _ in range(10):
        for server in next_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2.0)
                    # IPv4
                    sock.sendto(dns_query_a, (server, 53))
                    response, _ = sock.recvfrom(512)
                    answers, authority, additional = parse_dns_response(response)
                    all_ips.extend([answer[2] for answer in answers if answer[1] == 1])

                    # IPv6
                    sock.sendto(dns_query_aaaa, (server, 53))
                    response, _ = sock.recvfrom(512)
                    answers, authority, additional = parse_dns_response(response)
                    all_ips.extend([answer[2] for answer in answers if answer[1] == 28])

                    if all_ips:
                        return all_ips

                    next_servers = []
                    for record in authority:
                        if record[1] == 2:  # NS
                            ns_name = record[2]
                            ns_ip = get_ip_from_additional(additional, ns_name)
                            if ns_ip:
                                next_servers.append(ns_ip)
                            else:
                                ns_ip = iterative_query(ns_name)
                                if ns_ip:
                                    next_servers.extend(ns_ip)
                    if next_servers:
                        break
            except socket.timeout:
                print(f"✨ Ooopsie! Server {server} timed out! ✨")
    return all_ips


def get_ip_from_additional(additional, ns_name):
    for record in additional:
        if record[1] in [1, 28] and record[0] == ns_name:
            return record[2]
    return None


def parse_dns_response(response):
    header = struct.unpack(">HHHHHH", response[:12])
    answer_rrs = header[3]
    authority_rrs = header[4]
    additional_rrs = header[5]

    offset = 12
    while response[offset] != 0:
        offset += 1
    offset += 5

    answers, offset = extract_records(answer_rrs, offset, response)
    authority, offset = extract_records(authority_rrs, offset, response)
    additional, offset = extract_records(additional_rrs, offset, response)

    return answers, authority, additional


def extract_records(count: int, offset: int, response: bytes) -> tuple[list, int]:
    records: list[tuple[str, str, str | bytes]] = []
    for _ in range(count):
        name, offset = get_domain_name(response, offset)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset:offset + 10])
        offset += 10
        rdata = response[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1:  # A
            ip = ".".join(map(str, rdata))
            records.append((name, rtype, ip))
        elif rtype == 2:  # NS
            ns_name, _ = get_domain_name(response, offset - rdlength)
            records.append((name, rtype, ns_name))
        elif rtype == 5:  # CNAME
            cname, _ = get_domain_name(response, offset - rdlength)
            records.append((name, rtype, cname))
        elif rtype == 28:  # AAAA
            ipv6 = ":".join(f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, rdlength, 2))
            records.append((name, rtype, ipv6))
        else:
            records.append((name, rtype, rdata))

    return records, offset


def build_response(data: bytes, ip_addresses) -> bytes:
    id = data[:2]
    flags = b'\x81\x80'
    qdcount = b'\x00\x01'
    ancount = struct.pack('!H', len(ip_addresses))
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    question = data[12:]
    response = id + flags + qdcount + ancount + nscount + arcount + question

    for ip, ip_type in ip_addresses:
        name = b'\xc0\x0c'
        rclass = b'\x00\x01'
        ttl = struct.pack('!I', 60)

        if ip_type == 1: # A
            rtype = b'\x00\x01'
            rdlength = b'\x00\x04'
            rdata = socket.inet_aton(ip)
        else: # AAAA
            rtype = b'\x00\x1c'
            rdlength = b'\x00\x10'
            rdata = socket.inet_pton(socket.AF_INET6, ip)

        response += name + rtype + rclass + ttl + rdlength + rdata
    return response


def create_dns_query(domain: str, query_type: int) -> tuple[bytes, int]:
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    dns_header = struct.pack(">HHHHHH", transaction_id, flags, questions, answer_rrs,
                             authority_rrs, additional_rrs)
    domain_parts = domain.split(".")
    query_name = b''.join(struct.pack("B", len(part)) + part.encode() for part in domain_parts) + b'\x00'
    query_class = 1
    dns_question = struct.pack(">HH", query_type, query_class)

    dns_query = dns_header + query_name + dns_question
    return dns_query, transaction_id


def get_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    parts = []
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            sub_name, _ = get_domain_name(data, pointer)
            parts.append(sub_name)
            offset += 2
            break
        if length == 0:
            offset += 1
            break
        offset += 1
        parts.append(data[offset:offset + length].decode())
        offset += length

    return ".".join(parts), offset


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('172.22.208.1', 53))
        print("✨ Сервер запущен на порту 53 ✨")
        print("✨ Ожидание запроса... ✨")

        while True:
            data, address = server.recvfrom(512)
            print(f"✨ Получен запрос от {address}: {data} ✨")
            domain, offset = get_domain_name(data, 12)
            if domain == "1.0.0.127.in-addr.arpa":
                continue
            print(f"✨ Поиск IPv4 и IPv6 для {domain} ✨")
            ipv4_and_ipv6 = [(ip, 1) for ip in iterative_query(domain_name=domain) if ":" not in ip] + \
                            [(ip, 28) for ip in iterative_query(domain_name=domain) if ":" in ip]
            print(f"✨ Список адресов для {domain}: {ipv4_and_ipv6}")
            server.sendto(build_response(data, ipv4_and_ipv6), address)
            break


if __name__ == '__main__':
    run_server()
