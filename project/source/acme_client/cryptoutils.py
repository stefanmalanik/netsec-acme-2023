import math
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization as serial
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from base64 import urlsafe_b64encode as b64_enc
import base64

class CryptoUtils:
    def __init__(self) -> None:
        self.key = None
        self.cert = None

        self.kid = None

        self.csr = None
        self.csr_priv_key = None
    
    def gen_key(self):
        if self.key is None:
            self.key = rsa.generate_private_key(65537, 2048)
        return self.key
    
    def set_kid(self, kid):
        self.kid = kid

    @classmethod
    def get_json_dmp(cls, inp: dict):
        import json
        jsn = json.dumps(inp, sort_keys=True, separators=(',', ':'))
        return jsn.encode()
        

    @classmethod
    def to_b64(cls, inp):
        if isinstance(inp, bytes):
            return  base64.urlsafe_b64encode(inp).decode().strip('=')
        if isinstance(cls, str):
            return  base64.urlsafe_b64encode(bytes(inp, 'utf-8')).decode().strip('=')
        else:
            assert(isinstance(inp, dict))
            return  base64.urlsafe_b64encode(cls.get_json_dmp(inp)).decode().strip('=')
    @classmethod
    def from_b64(cls, inp):
        if isinstance(inp, str):
            inp = inp.encode()
        return  base64.urlsafe_b64decode(inp + b'==')
    
    @classmethod
    def get_serial_key(cls, key):
        if isinstance(key, rsa.RSAPrivateKey):
            return key.private_bytes(
                encoding=serial.Encoding.PEM,
                format=serial.PrivateFormat.PKCS8,
                encryption_algorithm=serial.NoEncryption()
            )
        else:
            return key.public_bytes(
                encoding=serial.Encoding.PEM,
                format=serial.PrivateFormat.PKCS8,
                encryption_algorithm=serial.NoEncryption()
            )

    def _get_jwk(self):
        assert(self.key)
        n = self.key.public_key().public_numbers().n
        e = self.key.public_key().public_numbers().e
        n = self.to_b64(n.to_bytes(math.ceil(n.bit_length() / 8), 'big'))
        e = self.to_b64(e.to_bytes(math.ceil(e.bit_length() / 8), 'big'))

        jwk = {
            'kty': 'RSA',
            'n': n,
            'e': e,
        }
        return jwk

    def _header(self, nonce, url, use_kid=False):
        assert(self.key)

        header = {"alg": "RS256",
                 "nonce": nonce,
                 "url": url}

        if use_kid:
            assert(self.kid)
            header['kid'] = self.kid
        else:
            # Create jwk
            header['jwk'] = self._get_jwk()
        return self.to_b64(header)

    def create_jwt(self, nonce, url, payload, use_kid=False):
        assert(self.key)

        jwt = {
            "protected": self._header(nonce, url, use_kid),
            "payload": self.to_b64(payload)
        }
        to_sign = (jwt["protected"] + "." + jwt["payload"]).encode()
        signed = self.key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
        jwt["signature"] = self.to_b64(signed)

        return jwt
    
    def create_http_key_auth(self, token):
        jwk = self._get_jwk()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.get_json_dmp(jwk))
        thumbprint = self.to_b64(digest.finalize())
        return '.'.join([token, thumbprint])
    
    def create_dns_key_auth(self, token):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.create_http_key_auth(token).encode()) 
        return self.to_b64(digest.finalize())

    def create_csr(self, dn_list):
        if dn_list:
            self.csr_priv_key = rsa.generate_private_key(65537, 4096)
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, dn_list[0])
            ]))
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(x) for x in dn_list]), 
                critical=True)
            
            self.csr = builder.sign(self.csr_priv_key, hashes.SHA256())
        assert(self.csr)
        return self.to_b64(self.csr.public_bytes(serial.Encoding.DER))

    @classmethod
    def transform_cert_to_der(cls, cert):
        if isinstance(cert, str):
            cert = cert.encode()
        cert = x509.load_pem_x509_certificates(cert)
        return cls.to_b64(cert[0].public_bytes(serial.Encoding.DER))


        
    
        


