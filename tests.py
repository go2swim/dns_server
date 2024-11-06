import unittest
from dns_requests import DNSResolver


class TestExtractIP(unittest.TestCase):
    def test1(self):
        resolver = DNSResolver()
        ips = resolver.resolve("urfu.ru")
        self.assertEqual(ips, ['93.88.179.201'])

    def test2(self):
        resolver = DNSResolver()
        ips = resolver.resolve("ya.ru")
        self.assertEqual(ips, ['77.88.44.242', '5.255.255.242', '77.88.55.242'])


if __name__ == "__main__":
    unittest.main()
