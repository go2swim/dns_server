import unittest
from dns_requests import DNSResolver


class TestExtractIP(unittest.TestCase):
    def test1(self):
        resolver = DNSResolver()
        ips = resolver.resolve("urfu.ru")
        self.assertEqual(ips, "0.0.0.0")

    #

    #

    #


if __name__ == "__main__":
    unittest.main()
