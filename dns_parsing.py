import struct


def create_dns_request(domain):
    request_id = 0x1234
    flags = 0x0000
    qdcount, ancount, nscount, arcount = 1, 0, 0, 0
    header = struct.pack(">HHHHHH", request_id, flags, qdcount, ancount, nscount, arcount)

    question = b''.join(struct.pack("B", len(part)) + part.encode('utf-8') for part in domain.split('.')) + b'\x00'
    qtype, qclass = 1, 1
    question += struct.pack(">HH", qtype, qclass)

    return header + question


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


class ServerResponseParser:
    @staticmethod
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

    @staticmethod
    def create_error_response(query_data):
        request_id = query_data[:2]
        flags = struct.pack(">H", 0x8183)  # Код ошибки: 3 (NXDOMAIN)
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        question = query_data[12:]

        return request_id + flags + counts + question


class DNSParser:
    @staticmethod
    def parse_dns_response(data):
        transaction_id, flags, qd_count, an_count, ns_count, ar_count, offset = DNSParser._parse_header(data)

        if DNSParser._check_nxdomain(flags):
            from constants_and_exceptions import DNSNXDomainError
            raise DNSNXDomainError("Domain does not exist (NXDOMAIN)")

        offset = DNSParser._skip_questions(data, offset, qd_count)
        answers = DNSParser._parse_records(data, offset, an_count)
        authority = DNSParser._parse_records(data, offset, ns_count)
        additional = DNSParser._parse_records(data, offset, ar_count)

        return answers, authority, additional

    @staticmethod
    def _parse_header(data):
        try:
            transaction_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack(">HHHHHH", data[:12])
        except struct.error:
            from constants_and_exceptions import DNSFormatError
            raise DNSFormatError("Invalid DNS header format")
        offset = 12
        return transaction_id, flags, qd_count, an_count, ns_count, ar_count, offset

    @staticmethod
    def _check_nxdomain(flags):
        rcode = flags & 0x000F  # Код возврата - последние 4 бита флагов
        return rcode == 3  # Код возврата 3 означает NXDOMAIN

    @staticmethod
    def _skip_questions(data, offset, qd_count):
        try:
            for _ in range(qd_count):
                while data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 5  # Пропустить нулевой байт и тип+класс
        except IndexError:
            from constants_and_exceptions import DNSFormatError
            raise DNSFormatError("Invalid question section format")
        return offset

    @staticmethod
    def _parse_records(data, offset, count):
        records = []
        for _ in range(count):
            record, offset = DNSParser._parse_record(data, offset)
            records.append(record)
        return records

    @staticmethod
    def _parse_record(data, offset):
        name, offset = DNSParser._parse_name(data, offset)
        try:
            record_type, record_class, ttl, data_length = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            record_data = data[offset:offset + data_length]
            offset += data_length
        except struct.error:
            from constants_and_exceptions import DNSFormatError
            raise DNSFormatError("Invalid record format")
        except IndexError:
            from constants_and_exceptions import DNSFormatError
            raise DNSFormatError("Unexpected end of data while parsing record")

        if record_type == 1:  # A запись
            ip = ".".join(map(str, record_data))
            return (name, record_type, ip), offset
        elif record_type == 2:  # NS запись
            ns_name, _ = DNSParser._parse_name(data, offset - data_length)
            return (name, record_type, ns_name), offset
        else:
            return (name, record_type, record_data), offset

    @staticmethod
    def _parse_name(data, offset):
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
                    labels.append(DNSParser._parse_name(data, pointer)[0])
                    break
                else:
                    offset += 1
                    labels.append(data[offset:offset + length].decode())
                    offset += length
        except IndexError:
            from constants_and_exceptions import DNSFormatError
            raise DNSFormatError("Invalid name format")
        return ".".join(labels), offset
