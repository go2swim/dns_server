import unittest
from dns_requests import DNSResolver


class TestExtractIP(unittest.TestCase):
    def test1(self):
        resolver = DNSResolver()
        ips = resolver.resolve('urfu.ru')
        self.assertEqual(ips, '0.0.0.0')


    # def test_valid_response_with_ipv4(self):
    #     # Корректный DNS-ответ с IP-адресом 93.184.215.14 (example.com)
    #     response = b'\x124\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x02X\x00\x04]\xb8\xd7\x0e'
    #     expected_ip = "93.184.215.14"
    #     self.assertEqual(extract_ip(response), expected_ip)
    #
    # def test_response_without_answer(self):
    #     # DNS-ответ без секции Answer
    #     response = b'\x124\x85\x80\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    #     self.assertIsNone(extract_ip(response))
    #
    # def test_invalid_format(self):
    #     # Некорректный ответ с незначительными данными
    #     response = b'\x00\x00\x00\x00'
    #     self.assertIsNone(extract_ip(response))
    #
    # def test_response_with_non_ipv4_answer(self):
    #     # Ответ с записью другого типа вместо IPv4
    #     response = b'\x124\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x1c\x00\x01\x00\x00\x02X\x00\x10\x24\x01\xdb\x08\x85\xa3\x00\x00\x00\x00\x8a\x2e\x03\x70\x73\x34'  # IPv6 адрес
    #     self.assertIsNone(extract_ip(response))


if __name__ == "__main__":
    unittest.main()
