#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-07
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
import re
import random
import hashlib
import binascii
from datetime import datetime, timedelta
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.extensions import _key_identifier_from_public_key
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import \
    Encoding, PrivateFormat, PublicFormat


class CryptoError(Exception):
    pass


def hexdigest(s):
    return hashlib.sha256(s).hexdigest()


# key


CURVE_MAPPING = {getattr(ec, n).name: getattr(ec, n)
                 for n in dir(ec) if n.startswith('SEC')}


def generate_rsa(bits=2048):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend())


def generate_ec(curve):
    return ec.generate_private_key(CURVE_MAPPING[curve],
                                   backend=default_backend())


def hexdigest_publickey(pkey):
    return binascii.b2a_hex(_key_identifier_from_public_key(pkey)).upper()


def get_keyid(pkey):
    return hexdigest_publickey(pkey.public_key())[-16:].decode('utf-8')


def load_privatekey(bkey, password=None):
    return serialization.load_pem_private_key(
        bkey, password=password, backend=default_backend())


def dump_privatekey(pkey, encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=None):
    if not encryption_algorithm:
        encryption_algorithm = serialization.NoEncryption()
    return pkey.private_bytes(encoding=encoding, format=format,
                              encryption_algorithm=encryption_algorithm)


def load_publickey(bkey):
    return serialization.load_pem_public_key(bkey, backend=default_backend())


def dump_publickey(pkey, encoding=Encoding.PEM,
                   format=PublicFormat.SubjectPublicKeyInfo):
    return pkey.public_bytes(encoding=encoding, format=format)


def parse_privatekey(pkey):
    if isinstance(pkey, rsa.RSAPrivateKey):
        sn = pkey.private_numbers()
        pn = pkey.public_key().public_numbers()
        p = {'type': 'RSAPrivateKey',
             'size': pkey.public_key().key_size,
             'n': hex(pn.n)[2:-1].upper(),
             'e': hex(pn.e)[2:].strip('L').upper(),
             'd': hex(sn.d)[2:-1].upper(),
             'p': hex(sn.p)[2:-1].upper(),
             'q': hex(sn.q)[2:-1].upper()}
    elif isinstance(pkey, rsa.RSAPublicKey):
        pn = pkey.public_numbers()
        p = {'type': 'RSAPublicKey',
             'size': pkey.key_size,
             'n': hex(pn.n)[2:-1].upper(),
             'e': hex(pn.e)[2:].strip('L').upper()}
    elif isinstance(pkey, ec.EllipticCurvePrivateKey):
        sn = pkey.private_numbers()
        pn = pkey.public_key().public_numbers()
        p = {'type': 'ECCPrivateKey',
             'curve': pn.curve.name,
             'size': pn.curve.key_size,
             'x': hex(pn.x)[2:-1].upper(),
             'y': hex(pn.y)[2:-1].upper(),
             'private': hex(sn.private_value).upper()[2:-1].upper()}
    elif isinstance(pkey, ec.EllipticCurvePublicKey):
        pn = pkey.public_numbers()
        p = {'type': 'ECCPublicKey',
             'curve': pn.curve.name,
             'size': pn.curve.key_size,
             'x': hex(pn.x)[2:-1].upper(),
             'y': hex(pn.y)[2:-1].upper()}
    return p


OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None)


PSS = padding.PSS(
    mgf=padding.MGF1(algorithm=hashes.SHA1()),
    salt_length=padding.PSS.MAX_LENGTH)


def pubkey_sign(pkey, msg):
    if isinstance(pkey, rsa.RSAPrivateKey):
        return pkey.sign(msg, PSS, hashes.SHA256())
    elif isinstance(pkey, ec.EllipticCurvePrivateKey):
        return pkey.sign(msg, ec.ECDSA(hashes.SHA256()))
    else:
        raise Exception('unknown public key type')


def pubkey_verify(pkey, msg, sig):
    if isinstance(pkey, rsa.RSAPublicKey):
        return pkey.verify(sig, msg, PSS, hashes.SHA256())
    elif isinstance(pkey, ec.EllipticCurvePublicKey):
        return pkey.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    else:
        raise Exception('unknown public key type')


# cert


def cert_fingerprint(cert):
    return binascii.b2a_hex(cert.fingerprint(hashes.SHA256())).upper()


def get_cert_dgst(cert):
    return cert_fingerprint(cert)[-16:].decode('utf-8')


def gen_sub_name_str(name, delimiter=', '):
    return delimiter.join(['%s=%s' % (n.oid._name, n.value)
                           for n in name if n.oid._name != 'Unknown OID'])


NAME_MAPPING = (
    ('cn', NameOID.COMMON_NAME),
    ('country', NameOID.COUNTRY_NAME),
    ('province', NameOID.STATE_OR_PROVINCE_NAME),
    ('city', NameOID.LOCALITY_NAME),
    ('org', NameOID.ORGANIZATION_NAME),
    ('ou',  NameOID.ORGANIZATIONAL_UNIT_NAME),
    ('email', NameOID.EMAIL_ADDRESS),
)

KEY_USAGE_NAMES = [
    'digital_signature', 'content_commitment', 'key_encipherment',
    'data_encipherment', 'key_agreement', 'key_cert_sign',
    'crl_sign', 'encipher_only', 'decipher_only']


EXTENDED_KEY_USAGE_MAPPING = {
    u._name: u
    for u in [ExtendedKeyUsageOID.SERVER_AUTH,
              ExtendedKeyUsageOID.CLIENT_AUTH,
              ExtendedKeyUsageOID.CODE_SIGNING,
              ExtendedKeyUsageOID.EMAIL_PROTECTION,
              ExtendedKeyUsageOID.TIME_STAMPING,
              ExtendedKeyUsageOID.OCSP_SIGNING]
}


def generate_req(pkey, data):
    name = [x509.NameAttribute(m, data[n])
            for n, m in NAME_MAPPING if data.get(n)]
    csr = x509.CertificateSigningRequestBuilder()\
              .subject_name(x509.Name(name))
    if data.get('ca'):
        csr = csr.add_extension(
            x509.BasicConstraints(True, None), critical=False)
        kw = {n: False for n in KEY_USAGE_NAMES}
        kw['key_cert_sign'] = True
        kw['crl_sign'] = True
        csr = csr.add_extension(x509.KeyUsage(**kw), critical=False)
    if data.get('alternative'):
        alternative = [x509.DNSName(d.strip())
                       for d in data['alternative'].split(',')]
        csr = csr.add_extension(
            x509.SubjectAlternativeName(alternative), critical=False)
    if data.get('usage'):
        usage = [EXTENDED_KEY_USAGE_MAPPING[data['usage']], ]
        csr = csr.add_extension(x509.ExtendedKeyUsage(usage), critical=False)
    return csr.sign(pkey, hashes.SHA256(), default_backend())


def dump_certificate_request(csr):
    return csr.public_bytes(Encoding.PEM)


def load_certificate_request(bcsr):
    return x509.load_pem_x509_csr(bcsr, default_backend())


def selfsign_req(csr, issuer_pkey, serial=None, days=3650):
    if not serial:  # FIXME: 排重
        serial = random.getrandbits(64)
    cert = x509.CertificateBuilder()\
               .subject_name(csr.subject)\
               .issuer_name(csr.subject)\
               .public_key(csr.public_key())\
               .serial_number(serial)\
               .not_valid_before(datetime.utcnow())\
               .not_valid_after(datetime.utcnow()+timedelta(days=10))
    cert._extensions = csr.extensions._extensions
    subkeyid = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
    cert = cert.add_extension(subkeyid, critical=False)
    authkeyid = _key_identifier_from_public_key(issuer_pkey.public_key())
    authkeyid = x509.AuthorityKeyIdentifier(
        authkeyid, [x509.DirectoryName(csr.subject), ], serial)
    cert = cert.add_extension(authkeyid, critical=False)
    return cert.sign(issuer_pkey, hashes.SHA256(), default_backend())


def sign_req(csr, issuer_cert, issuer_pkey, serial=None, days=3650):
    if not serial:  # FIXME: 排重
        serial = random.getrandbits(64)
    cert = x509.CertificateBuilder()\
               .subject_name(csr.subject)\
               .issuer_name(issuer_cert.subject)\
               .public_key(csr.public_key())\
               .serial_number(serial)\
               .not_valid_before(datetime.utcnow())\
               .not_valid_after(datetime.utcnow()+timedelta(days=10))
    cert._extensions = csr.extensions._extensions
    subkeyid = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
    cert = cert.add_extension(subkeyid, critical=False)
    authkeyid = _key_identifier_from_public_key(issuer_pkey.public_key())
    authkeyid = x509.AuthorityKeyIdentifier(
        authkeyid, [x509.DirectoryName(issuer_cert.subject), ],
        issuer_cert.serial_number)
    cert = cert.add_extension(authkeyid, critical=False)
    return cert.sign(issuer_pkey, hashes.SHA256(), default_backend())


def dump_certificate(cert, encoding=Encoding.PEM):
    return cert.public_bytes(encoding=encoding)


def load_certificate(bcert):
    return x509.load_pem_x509_certificate(bcert, default_backend())


re_pem = re.compile(
    b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def split_pems(bpems):
    return re_pem.findall(bpems)


def to_pkcs12(bkey, bcert, bcacerts, passphrase=None):
    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(
        crypto.load_certificate(crypto.FILETYPE_PEM, bcert))
    if bkey:
        pkcs12.set_privatekey(
            crypto.load_privatekey(crypto.FILETYPE_PEM, bkey))
    if bcacerts:
        pkcs12.set_ca_certificates(
            [crypto.load_certificate(crypto.FILETYPE_PEM, c)
             for c in bcacerts])
    return pkcs12.export(passphrase=passphrase)


class CertReader(object):

    ATTR_MAPPING = {
        'usage': ExtensionOID.KEY_USAGE,
        'extusage': ExtensionOID.EXTENDED_KEY_USAGE,
        'alternative': ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        'subkeyid': ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        'authkeyid': ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    }

    def __init__(self, c):
        self.c = c

    @property
    def sn(self):
        return hex(self.c.serial_number)[2:].strip('L').upper()

    @property
    def dgst(self):
        return get_cert_dgst(self.c)

    @property
    def keyid(self):
        return get_keyid(self.c)

    @property
    def subject(self):
        return gen_sub_name_str(self.c.subject)

    @property
    def cn(self):
        return self.c.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value

    @property
    def ca(self):
        try:
            ext = self.c.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS)
        except (x509.extensions.ExtensionNotFound, AttributeError):
            return False
        return ext.value.ca

    def __getattr__(self, name):
        if name in self.__dict__:
            return self.__dict__[name]
        if name in self.ATTR_MAPPING:
            try:
                ext = self.c.extensions.get_extension_for_oid(
                    self.ATTR_MAPPING[name])
            except (x509.extensions.ExtensionNotFound, AttributeError):
                return
            return self.read_ext(ext.value)
        raise AttributeError(name)

    def read_ext(self, v):
        if isinstance(v, x509.BasicConstraints):
            return v.ca
        elif isinstance(v, x509.KeyUsage):
            return ', '.join(['%s=%s' % (n, getattr(v, n))
                              for n in KEY_USAGE_NAMES[:-2]])
        elif isinstance(v, x509.ExtendedKeyUsage):
            return ', '.join([u._name for u in v])
        elif isinstance(v, x509.SubjectAlternativeName):
            return ', '.join(v.value for v in v)
        elif isinstance(v, x509.SubjectKeyIdentifier):
            return binascii.b2a_hex(v.digest).upper().decode('utf-8')
        elif isinstance(v, x509.AuthorityKeyIdentifier):
            return binascii.b2a_hex(v. key_identifier)\
                           .upper().decode('utf-8')
        elif isinstance(v, x509.OCSPNoCheck):
            return True
        elif isinstance(v, x509.TLSFeature):
            return True

    def extensions(self):
        for ext in self.c.extensions:
            yield ext.oid._name, self.read_ext(ext.value)
