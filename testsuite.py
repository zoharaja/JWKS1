import unittest
import coverage
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import base64

cov = coverage.Coverage()
cov.start()

from project1.views import gen_store_key, keys_store

class TestKeyGen(unittest.TestCase):
    def test_gen_store_key(self):
        key_id = gen_store_key()
        self.assertTrue(key_id.startswith('key-'))
        self.assertIn(key_id, keys_store)
        key_info = keys_store[key_id]
        self.assertIsInstance(key_info['priv_key'], rsa.RSAPrivateKey)
        self.assertIsInstance(key_info['public_key'], rsa.RSAPublicKey)
        self.assertIsInstance(key_info['expiry'], datetime.datetime)

if __name__ == '__main__':
    unittest.main()

# Stop coverage measurement and save results
cov.stop()
cov.save()

# Generate coverage report
cov.report()

# Optionally, generate an HTML report
cov.html_report()
