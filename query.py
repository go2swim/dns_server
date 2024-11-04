import socket
import struct


def create_dns_query(domain):
    # Идентификатор запроса (произвольный уникальный ID, например, 0x1234)
    request_id = 0x1234
    flags = 0x0100  # Стандартный запрос (флаги)
    qdcount = 1  # Один вопрос
    ancount = 0  # Без ответов
    nscount = 0  # Без авторитетных записей
    arcount = 0  # Без дополнительных записей

    # Заголовок DNS-запроса
    header = struct.pack(">HHHHHH", request_id, flags, qdcount, ancount, nscount, arcount)

    # Кодирование домена
    question = b""
    for part in domain.split("."):
        question += struct.pack("B", len(part)) + part.encode("utf-8")
    question += b"\x00"  # Окончание вопроса

    qtype = 1  # Запись типа A (IPv4)
    qclass = 1  # Класс IN (интернет)
    question += struct.pack(">HH", qtype, qclass)

    return header + question


def send_dns_query(domain, server_ip="127.0.0.1", server_port=2053):
    query = create_dns_query(domain)

    print(query)
    # Создаем UDP-сокет и отправляем запрос
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)  # Таймаут для получения ответа
        sock.sendto(query, (server_ip, server_port))
#dig yandex.maps.me @127.0.0.1
        # Получаем ответ
        try:
            response, _ = sock.recvfrom(512)
            print("Ответ от сервера получен:")
            print(response)
        except socket.timeout:
            print("Время ожидания ответа истекло")

# domain = dns.name.from_text('google.com')
# print(dns.message.make_query(domain, dns.rdatatype.ANY))
# print(create_dns_query("example.com"))
send_dns_query('yandex.maps.me')
