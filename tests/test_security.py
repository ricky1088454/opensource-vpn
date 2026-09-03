import unittest

from server import is_public_hostname, is_public_ip, validate_target_url


class TestSecurityValidation(unittest.TestCase):
    def test_is_public_ip_rejects_private_and_loopback(self):
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("::1"))

    def test_is_public_ip_accepts_public_example(self):
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("1.1.1.1"))

    def test_is_public_hostname_rejects_when_any_result_private(self):
        def fake_resolver(_hostname, _port, type=None):  # noqa: ARG001
            return [
                (None, None, None, None, ("93.184.216.34", 0)),
                (None, None, None, None, ("127.0.0.1", 0)),
            ]

        self.assertFalse(is_public_hostname("mixed.example", resolver=fake_resolver))

    def test_validate_target_url_checks_scheme(self):
        with self.assertRaises(ValueError):
            validate_target_url("file:///etc/passwd")

    def test_validate_target_url_rejects_private_ip_host(self):
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
