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
import hashlib
import binascii
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CryptoError(Exception):
    pass


def hexdigest(s):
    return hashlib.sha256(s).hexdigest()


def generate_key(bits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, bits)
    return pkey


def generate_subj_str(sub):
    return ', '.join(['%s = %s' % i for i in sub.get_components()])


def gen_sub_name_str(name):
    return ', '.join(['%s = %s' % (n.oid._name, n.value)
                      for n in name if n.oid._name != 'Unknown OID'])


def set_subject(subj, data):
    mapping = (
        ('cn', 'commonName'),
        ('country', 'countryName'),
        ('province', 'stateOrProvinceName'),
        ('city', 'localityName'),
        ('org', 'organizationName'),
        ('ou', 'organizationalUnitName'),
        ('email', 'emailAddress'),
    )
    for n, m in mapping:
        if data.get(n):
            setattr(subj, m, data[n])


def generate_req(pkey, data):
    req = crypto.X509Req()
    set_subject(req.get_subject(), data)

    exts = []
    if data.get('ca'):
        exts.append(crypto.X509Extension(
            b"basicConstraints", True, b'CA:TRUE'))
        exts.append(crypto.X509Extension(
            b"keyUsage", True, b"keyCertSign, cRLSign"))
    if data.get('alternative'):
        exts.append(crypto.X509Extension(
            b"subjectAltName", False, bytes(data['alternative'])))
    if data.get('usage'):
        exts.append(crypto.X509Extension(
            b"extendedKeyUsage", False, bytes(data['usage'])))
    # certificatePolicies
    # crl
    # crlDistributionPoints=URI:http://myhost.com/myca.crl
    req.add_extensions(exts)
    req.set_pubkey(pkey)
    req.sign(pkey, b"sha256")
    return req


def selfsign_cert(req, issuer_pkey, serial,
                  days=3650, digest=b'sha256'):
    cert = crypto.X509()
    cert.set_pubkey(req.get_pubkey())
    cert.set_subject(req.get_subject())
    cert.add_extensions(req.get_extensions())
    cert.add_extensions([crypto.X509Extension(
        b"subjectKeyIdentifier", False, b"hash", subject=cert)])
    cert.add_extensions([crypto.X509Extension(
        b"authorityKeyIdentifier", False, b"keyid:always", issuer=cert)])
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(86400*days)
    cert.set_issuer(req.get_subject())
    cert.sign(issuer_pkey, digest)
    return cert


# def sign_cert(req, issuer_cert, issuer_pkey,
#               serial, days, digest=b'sha256'):
#     cert = crypto.X509()
#     cert.set_pubkey(req.get_pubkey())
#     cert.set_subject(req.get_subject())
#     cert.add_extensions(req.get_extensions())
#     cert.set_serial_number(serial)
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(86400*days)
#     cert.set_issuer(issuer_cert.get_subject())
#     cert.sign(issuer_pkey, digest)
#     return cert


re_pem = re.compile(
    '-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def split_pems(strpems):
    return re_pem.findall(strpems)


def verify(strpems, strkey):
    certs = [crypto.load_certificate(crypto.FILETYPE_PEM, strpem)
             for strpem in strpems]
    if strkey:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, strkey)
        num1 = pkey.to_cryptography_key().public_key().public_numbers()
        num2 = certs[0].get_pubkey().to_cryptography_key().public_numbers()
        if num1 != num2:
            raise CryptoError('pubkey not match')

    if len(certs) > 1:
        store = crypto.X509Store()
        for cert in certs:
            store.add_cert(cert)
        store_ctx = crypto.X509StoreContext(store, certs[0])
        store_ctx.verify_certificate()


def read_cert(strpem):
    cert = x509.load_pem_x509_certificate(strpem, default_backend())
    cn = cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME)[0].value

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        keyid = binascii.b2a_hex(ext.value.digest).upper()
    except x509.ExtensionNotFound:
        keyid = None
    print('keyid:', keyid)

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        alternative = ', '.join(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        alternative = None
    print('alternative:', alternative)

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        authkeyid = binascii.b2a_hex(ext.value.key_identifier).upper()
    except x509.ExtensionNotFound:
        authkeyid = None
    print('authkeyid:', authkeyid)

    return cn, keyid, alternative, authkeyid


def main():
    # with open('rsa1.key', 'rb') as fi:
    #     pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, fi.read())
    # data = {
    #     'cn': '*.shell.org',
    #     'country': 'CN',
    #     'province': 'SH',
    #     'city': 'SH',
    #     'org': 'home',
    #     'ou': 'home',
    #     'email': 'shell@shell.org',
    #     'alternative': 'DNS: *.shell1.org',
    #     'usage': 'serverAuth',
    #     'ca': True,
    # }
    # req = generate_req(pkey, data)
    # strreq = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    # print(strreq)
    # cert = selfsign_cert(req, pkey, 100032948179213841892735194759)
    # strcert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    # print(strcert)

    # with open('/tmp/keys/ca.crt', 'rb') as fi:
    #     cert = crypto.load_certificate(crypto.FILETYPE_PEM, fi.read())
    # print(generate_subj_str(cert.get_subject()))

    with open('/tmp/keys/test.crt', 'rb') as fi:
        certchain = fi.read()
    strpems = split_pems(certchain)
    with open('/tmp/keys/test.key', 'rb') as fi:
        strkey = fi.read()
    verify(strpems, strkey)

    cert = x509.load_pem_x509_certificate(strpems[0], default_backend())

    print(gen_sub_name_str(cert.subject))
    print(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)

    ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    print(binascii.b2a_hex(ext.value.digest).upper())
    ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    print(ext.value.get_values_for_type(x509.DNSName))
    ext = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    print(binascii.b2a_hex(ext.value.key_identifier).upper())


if __name__ == '__main__':
    main()
