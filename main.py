import socket  # Импортируем модуль socket для сетевого взаимодействия
import struct  # Импортируем struct для работы с байтовыми данными

# Определяем порт для DNS-запросов (53)
DNS_PORT = 2053

# Указываем IP-адреса корневых DNS-серверов для начального поиска
ROOT_SERVERS = [
    '192.58.128.30',
    # "8.8.8.8",
    # "8.8.4.4"
]

class DNSFormatError(Exception):
    pass

class DNSNXDomainError(Exception):
    pass

class DNSTimeoutError(Exception):
    pass

class DNSError(Exception):
    pass

def resolve(domain):
    current_servers = ROOT_SERVERS  # Начинаем с корневых серверов
    max_iterations = 8  # Ограничение на количество итераций

    for _ in range(max_iterations):
        for server in current_servers:
            try:
                # Отправляем запрос к текущему серверу
                response = query_dns(server, domain)
                print(f'Response from {server}: {response}')

                # Извлекаем A и AAAA записи
                answers, authority, additional = parse_dns_response(response)

                # Проверяем, есть ли IP-адреса в ответах
                for answer in answers:
                    if answer[1] in (1, 28):  # A или AAAA запись
                        return answer[2]  # Возвращаем первый найденный IP

                # Получаем следующий набор серверов из NS-записей
                next_servers = get_next_servers(authority, additional)
                if next_servers:
                    current_servers = next_servers
                    break
            except DNSTimeoutError:
                print(f"Timeout on server {server}")
                continue
            except DNSNXDomainError:
                print(f"NXDOMAIN: Domain does not exist for {domain}")
                return None
            except DNSFormatError as e:
                print(f"Format error with server {server}: {e}")
                continue
            except DNSError as e:
                print(f"Error with server {server}: {e}")
                continue

    return None  # Возвращаем None, если IP не найден

def get_next_servers(authority, additional):
    next_servers = []
    for record in authority:
        if record[1] == 2:  # NS-запись
            ns_name = record[2]
            ns_ip = get_ip_from_additional(additional, ns_name)
            if ns_ip:
                next_servers.append(ns_ip)
            else:
                # Если IP для NS-записи не найден, резолвим его рекурсивно
                ns_ips = resolve(ns_name)
                if ns_ips:
                    next_servers.extend(ns_ips)
    return next_servers


# Вспомогательная функция для извлечения IP из дополнительных записей
def get_ip_from_additional(additional, ns_name):
    for record in additional:
        if record[0] == ns_name and record[1] in (1, 28):  # Проверяем A или AAAA запись
            return record[2]
    return None


def query_dns(server, domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем UDP-сокет
    sock.settimeout(2)  # Устанавливаем таймаут на 2 секунды

    # Формируем DNS-запрос для указанного домена
    dns_request = create_dns_request(domain)

    # Отправляем запрос и получаем ответ
    print(f'server: {server}')
    sock.sendto(dns_request, (server, 53))
    response, _ = sock.recvfrom(512)  # 512 байт для стандартного DNS-ответа
    sock.close()
    return response  # Возвращаем ответ

# Создаем запрос для доменного имени
def create_dns_request(domain):
    request_id = 0x1234  # Уникальный ID запроса
    flags = 0x0000  # Устанавливаем флаг для нерекурсивного поиска
    qdcount = 1  # Количество вопросов (1 для обычного запроса)
    ancount = 0  # Ответов нет
    nscount = 0  # Авторитетных записей нет
    arcount = 0  # Дополнительных записей нет

    # Заголовок запроса
    header = struct.pack(">HHHHHH", request_id, flags, qdcount, ancount, nscount, arcount)

    # Кодируем домен в формате DNS (например, 'www.example.com')
    question = b''
    for part in domain.split('.'):
        question += struct.pack("B", len(part)) + part.encode('utf-8')
    question += b'\x00'  # Завершающий нулевой байт

    # Тип запроса (A) и класс (IN)
    qtype = 1  # Запись типа A (IPv4-адрес)
    qclass = 1  # Интернет-класс (IN)
    question += struct.pack(">HH", qtype, qclass)

    return header + question  # Возвращаем полный запрос

# \x124\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00C\x00\x04]\xb8\xd7\x0e
# | ID | flags |QDCount|ANCount|NSCount|ARCount|                           domen                       |    | IPv4 |   IN  |   |   TTL  |RDLENGTH|    ip    |
#                 Headers                      |                  Question                             |               Answer

def parse_dns_response(data):
    transaction_id, flags, qd_count, an_count, ns_count, ar_count, offset = parse_header(data)

    # Проверка на NXDOMAIN в флагах
    if check_nxdomain(flags):
        raise DNSNXDomainError("Domain does not exist (NXDOMAIN)")

    # Пропускаем секцию вопросов
    offset = skip_questions(data, offset, qd_count)

    # Секции ответов, авторитетные записи и дополнительные записи
    answers = parse_records(data, offset, an_count)
    authority = parse_records(data, offset, ns_count)
    additional = parse_records(data, offset, ar_count)

    return answers, authority, additional

def parse_header(data):
    try:
        transaction_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        raise DNSFormatError("Invalid DNS header format")
    offset = 12
    return transaction_id, flags, qd_count, an_count, ns_count, ar_count, offset

def check_nxdomain(flags):
    rcode = flags & 0x000F  # Код возврата - последние 4 бита флагов
    return rcode == 3  # Код возврата 3 означает NXDOMAIN

def skip_questions(data, offset, qd_count):
    try:
        for _ in range(qd_count):
            while data[offset] != 0:
                offset += 1 + data[offset]
            offset += 5  # Пропустить нулевой байт и тип+класс
    except IndexError:
        raise DNSFormatError("Invalid question section format")
    return offset

def parse_records(data, offset, count):
    records = []
    for _ in range(count):
        record, offset = parse_record(data, offset)
        records.append(record)
    return records

def parse_record(data, offset):
    name, offset = parse_name(data, offset)
    try:
        record_type, record_class, ttl, data_length = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        record_data = data[offset:offset + data_length]
        offset += data_length
    except struct.error:
        raise DNSFormatError("Invalid record format")
    except IndexError:
        raise DNSFormatError("Unexpected end of data while parsing record")

    if record_type == 1:  # A запись
        ip = ".".join(map(str, record_data))
        return (name, record_type, ip), offset
    elif record_type == 2:  # NS запись
        ns_name, _ = parse_name(data, offset - data_length)
        return (name, record_type, ns_name), offset
    else:
        return (name, record_type, record_data), offset

def parse_name(data, offset):
    labels = []
    try:
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:  # Указатель
                pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                offset += 2
                labels.append(parse_name(data, pointer)[0])
                break
            else:
                offset += 1
                labels.append(data[offset:offset + length].decode())
                offset += length
    except IndexError:
        raise DNSFormatError("Invalid name format")
    return ".".join(labels), offset


# Запускаем сервер, который слушает DNS-запросы
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", DNS_PORT))  # Привязываем сокет ко всем интерфейсам
    print("DNS сервер запущен...")

    while True:
        data, addr = sock.recvfrom(512)  # Получаем данные и адрес клиента
        domain = parse_dns_query(data)  # Парсим запрос

        if domain:
            print(f"Запрос получен для домена: {domain}")
            ip = resolve(domain)  # Ищем IP-адрес

            # Формируем ответ в зависимости от наличия IP-адреса
            if ip:
                print(f'ip {ip}')
                response = create_dns_response(data, ip)
            else:
                response = create_error_response(data)

            sock.sendto(response, addr)  # Отправляем ответ клиенту

# Парсим DNS-запрос для получения доменного имени
def parse_dns_query(data):
    domain = []
    offset = 12  # Начало секции Question после заголовка
    length = data[offset]

    while length != 0:
        offset += 1
        domain.append(data[offset:offset + length].decode())  # Добавляем часть домена
        offset += length
        length = data[offset]

    return ".".join(domain)  # Возвращаем полное доменное имя

# Создаем DNS-ответ с IP-адресом
def create_dns_response(query_data, ip):
    request_id = query_data[:2]  # ID запроса
    flags = struct.pack(">H", 0x8180)  # Флаги для стандартного ответа
    qdcount = struct.pack(">H", 1)  # Один вопрос
    ancount = struct.pack(">H", 1)  # Один ответ
    nscount = struct.pack(">H", 0)
    arcount = struct.pack(">H", 0)

    question = query_data[12:]  # Вопросная часть запроса
    answer = b"\xc0\x0c"  # Указатель на доменное имя
    answer += struct.pack(">HHI", 1, 1, 300)  # Тип A, Класс IN, TTL
    answer += struct.pack(">H", 4)  # Длина RDATA
    answer += bytes(map(int, ip.split('.')))  # IP-адрес

    return request_id + flags + qdcount + ancount + nscount + arcount + question + answer

# Формируем ответ на случай ошибки
def create_error_response(query_data):
    request_id = query_data[:2]
    flags = struct.pack(">H", 0x8183)  # Код ошибки: 3 (NXDOMAIN)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = query_data[12:]

    return request_id + flags + counts + question

# Запускаем DNS-сервер, если скрипт запускается как основной
if __name__ == "__main__":
    start_server()
