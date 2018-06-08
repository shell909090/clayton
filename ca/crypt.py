#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-07
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
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
    return hexdigest_publickey(pkey.public_key())[-16:]


def load_privatekey(strkey):
    return serialization.load_pem_private_key(
        bytes(strkey), password=None, backend=default_backend())


def dump_privatekey(pkey, encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=None):
    if not encryption_algorithm:
        encryption_algorithm = serialization.NoEncryption()
    return pkey.private_bytes(encoding=encoding, format=format,
                              encryption_algorithm=encryption_algorithm)


def dump_publickey(pkey, encoding=Encoding.PEM,
                   format=PublicFormat.SubjectPublicKeyInfo):
    return pkey.public_key().public_bytes(encoding=encoding, format=format)


def parse_privatekey(pkey):
    if isinstance(pkey, rsa.RSAPrivateKey):
        sn = pkey.private_numbers()
        pn = pkey.public_key().public_numbers()
        p = {'type': 'RSAPrivateKey',
             'size': pkey.public_key().key_size,
             'n': hex(pn.n).upper()[2:-1].upper(),
             'e': hex(pn.e).upper()[2:].strip('L').upper(),
             'd': hex(sn.d).upper()[2:-1].upper(),
             'p': hex(sn.p).upper()[2:-1].upper(),
             'q': hex(sn.q).upper()[2:-1].upper()}
    elif isinstance(pkey, rsa.RSAPublicKey):
        pn = pkey.public_numbers()
        p = {'type': 'RSAPublicKey',
             'size': pkey.key_size,
             'n': hex(pn.n).upper()[2:-1].upper(),
             'e': hex(pn.e).upper()[2:].strip('L').upper()}
    elif isinstance(pkey, ec.EllipticCurvePrivateKey):
        sn = pkey.private_numbers()
        pn = pkey.public_key().public_numbers()
        p = {'type': 'ECCPrivateKey',
             'curve': pn.curve.name,
             'size': pn.curve.key_size,
             'x': hex(pn.x).upper()[2:-1].upper(),
             'y': hex(pn.y).upper()[2:-1].upper(),
             'private': hex(sn.private_value).upper()[2:-1].upper()}
    elif isinstance(pkey, ec.EllipticCurvePublicKey):
        pn = pkey.public_numbers()
        p = {'type': 'ECCPublicKey',
             'curve': pn.curve.name,
             'size': pn.curve.key_size,
             'x': hex(pn.x).upper()[2:-1].upper(),
             'y': hex(pn.y).upper()[2:-1].upper()}
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
    return cert_fingerprint(cert)[-16:]


def generate_subj_str(sub):
    return ', '.join(['%s = %s' % i for i in sub.get_components()])


def gen_sub_name_str(name):
    return ', '.join(['%s = %s' % (n.oid._name, n.value)
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
        usage = x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False)
        csr = csr.add_extension(usage, critical=False)
    if data.get('alternative'):
        alternative = [x509.DNSName(d.strip())
                       for d in data['alternative'].split(',')]
        csr = csr.add_extension(
            x509.SubjectAlternativeName(alternative), critical=False)
    if data.get('usage'):
        csr = csr.add_extension(
            x509.ExtendedKeyUsage([
                EXTENDED_KEY_USAGE_MAPPING[data['usage']], ]),
            critical=False)
    return csr.sign(pkey, hashes.SHA256(), default_backend())


def dump_certificate_request(csr):
    return csr.public_bytes(Encoding.PEM)


def load_certificate_request(strcsr):
    return x509.load_pem_x509_csr(strcsr, default_backend())


def selfsign_req(csr, issuer_pkey, serial=None, days=3650):
    if not serial:
        # serial = x509.random_serial_number()
        serial = random.getrandbits(64)
        # FIXME: 排重
    cert = x509.CertificateBuilder()\
               .subject_name(csr.subject)\
               .issuer_name(csr.subject)\
               .public_key(csr.public_key())\
               .serial_number(serial)\
               .not_valid_before(datetime.utcnow())\
               .not_valid_after(datetime.utcnow()+timedelta(days=10))
    cert._extensions = csr.extensions._extensions
    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False)
    cert = cert.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_pkey.public_key()),
        critical=False)
    return cert.sign(issuer_pkey, hashes.SHA256(), default_backend())


def sign_req(csr, issuer_cert, issuer_pkey, serial=None, days=3650):
    if not serial:
        # serial = x509.random_serial_number()
        serial = random.getrandbits(64)
        # FIXME: 排重
    cert = x509.CertificateBuilder()\
               .subject_name(csr.subject)\
               .issuer_name(issuer_cert.subject)\
               .public_key(csr.public_key())\
               .serial_number(serial)\
               .not_valid_before(datetime.utcnow())\
               .not_valid_after(datetime.utcnow()+timedelta(days=10))
    cert._extensions = csr.extensions._extensions
    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False)
    cert = cert.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_cert.public_key()),
        critical=False)
    return cert.sign(issuer_pkey, hashes.SHA256(), default_backend())


def dump_certificate(cert, encoding=Encoding.PEM):
    return cert.public_bytes(encoding=encoding)


def load_certificate(strcert):
    return x509.load_pem_x509_certificate(bytes(strcert), default_backend())


re_pem = re.compile(
    '-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def split_pems(strpems):
    return re_pem.findall(strpems)


def verify(strpems):
    certs = [crypto.load_certificate(crypto.FILETYPE_PEM, strpem)
             for strpem in strpems]
    # if strkey:
    #     pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, strkey)
    #     num1 = pkey.to_cryptography_key().public_key().public_numbers()
    #     num2 = certs[0].get_pubkey().to_cryptography_key().public_numbers()
    #     if num1 != num2:
    #         raise CryptoError('pubkey not match')

    if len(certs) > 1:
        store = crypto.X509Store()
        for cert in certs:
            store.add_cert(cert)
        store_ctx = crypto.X509StoreContext(store, certs[0])
        store_ctx.verify_certificate()


def cert_cn(cert):
    return cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value


def cert_subject_keyid(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return binascii.b2a_hex(ext.value.digest).upper()
    except x509.ExtensionNotFound:
        return


def cert_alternative(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ', '.join(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return


def cert_authkeyid(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        return binascii.b2a_hex(ext.value.key_identifier).upper()
    except x509.ExtensionNotFound:
        return


def cert_ca(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS)
        return ext.value.ca, ext.value.path_length
    except x509.ExtensionNotFound:
        return


def cert_extusage(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID. EXTENDED_KEY_USAGE)
        return ', '.join([u._name for u in ext.value])
    except x509.ExtensionNotFound:
        return


def cert_usage(cert):
    names = ['digital_signature', 'content_commitment',
             'key_encipherment', 'data_encipherment',
             'key_agreement', 'key_cert_sign', 'crl_sign']
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE)
        return ', '.join([n for n in names if getattr(ext.value, n)])
    except x509.ExtensionNotFound:
        return


def to_pkcs12(strkey, strcert, str_ca_certs, passphrase=None):
    pkcs12 = crypto.PKCS12()
    pkcs12.set_certificate(
        crypto.load_certificate(crypto.FILETYPE_PEM, strcert))
    if strkey:
        pkcs12.set_privatekey(
            crypto.load_privatekey(crypto.FILETYPE_PEM, strkey))
    if str_ca_certs:
        pkcs12.set_ca_certificates(
            [crypto.load_certificate(crypto.FILETYPE_PEM, c)
             for c in str_ca_certs])
    return pkcs12.export(passphrase=passphrase)


# def main():
    # with open('/tmp/keys/rsa.key', 'rb') as fi:
    #     pkey = load_privatekey(fi.read())
    # data = {
    #     'cn': '*.shell.org',
    #     'country': 'CN',
    #     'province': 'SH',
    #     'city': 'SH',
    #     'org': 'home',
    #     'ou': 'home',
    #     'email': 'shell@shell.org',
    #     'alternative': '*.shell1.org, *.baidu.com',
    #     'usage': 'serverAuth',
    #     'ca': True,
    # }
    # csr = generate_req(pkey, data)
    # strcsr = dump_certificate_request(csr)
    # print(strcsr)
    # cert = selfsign_req(csr, pkey)
    # strcert = dump_certificate(cert)
    # print(strcert)

    # with open('/tmp/keys/ca.crt', 'rb') as fi:
    #     cert = crypto.load_certificate(crypto.FILETYPE_PEM, fi.read())
    # print(generate_subj_str(cert.get_subject()))

    # with open('/tmp/keys/test.crt', 'rb') as fi:
    #     certchain = fi.read()
    # strpems = split_pems(certchain)
    # with open('/tmp/keys/test.key', 'rb') as fi:
    #     strkey = fi.read()
    # verify(strpems, strkey)

    # cert = x509.load_pem_x509_certificate(strpems[0], default_backend())

    # print(gen_sub_name_str(cert.subject))
    # print(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)

    # ext = cert.extensions.get_extension_for_oid(
    #     x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    # print(binascii.b2a_hex(ext.value.digest).upper())
    # ext = cert.extensions.get_extension_for_oid(
    #     x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    # print(ext.value.get_values_for_type(x509.DNSName))
    # ext = cert.extensions.get_extension_for_oid(
    #     x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    # print(binascii.b2a_hex(ext.value.key_identifier).upper())

# def main():
#     csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
#         # Provide various details about who we are.
#         x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
#         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
#         x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
#         x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
#         x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
#     ])).add_extension(
#         x509.SubjectAlternativeName([
#             x509.DNSName(u"mysite.com"),
#             x509.DNSName(u"www.mysite.com"),
#             x509.DNSName(u"subdomain.mysite.com"),
#         ]),
#         critical=False,
#     ).sign(key, hashes.SHA256(), default_backend())
#     with open("path/to/csr.pem", "wb") as f:
#         f.write(csr.public_bytes(serialization.Encoding.PEM))


# def main():
#     with open('/tmp/keys/a.crt', 'rb') as fi:
#         cert = load_certificate(fi.read())
#     print(cert_usage(cert))


def main():
    with open('/tmp/keys/rsa.key', 'rb') as fi:
        pkey = load_privatekey(fi.read())
    print(parse_privatekey(pkey))

    with open('/tmp/keys/ecc.key', 'rb') as fi:
        pkey = load_privatekey(fi.read())
    print(parse_privatekey(pkey))


if __name__ == '__main__':
    main()
