#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-09
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
from pprint import pprint

from cryptography import exceptions

import crypt


def test_onekey(pkey):
    dgst = crypt.get_keyid(pkey)
    dgst_pub = crypt.hexdigest_publickey(pkey.public_key())
    print(dgst, dgst_pub)

    bkey = crypt.dump_privatekey(pkey)
    pkey1 = crypt.load_privatekey(bkey)
    dgst1 = crypt.get_keyid(pkey1)
    assert(dgst == dgst1)

    bpub = crypt.dump_publickey(pkey.public_key())
    ppub1 = crypt.load_publickey(bpub)
    dgst_pub1 = crypt.hexdigest_publickey(ppub1)
    assert(dgst_pub == dgst_pub1)

    pprint(crypt.parse_privatekey(pkey))


def test_key():
    print('rsa')
    test_onekey(crypt.generate_rsa())
    print('ecc')
    test_onekey(crypt.generate_ec('secp256r1'))


def test_sign():
    pkey = crypt.generate_rsa()
    with open('/dev/urandom', 'rb') as fi:
        msg = fi.read(224)
    sig = crypt.pubkey_sign(pkey, msg)
    crypt.pubkey_verify(pkey.public_key(), msg, sig)
    sig = b'' + sig[:-1]
    try:
        crypt.pubkey_verify(pkey.public_key(), msg, sig)
        print('sig successed, wrong.')
    except exceptions.InvalidSignature:
        print('sig wrong, ok.')


X509DATA = {
    'cn': '*.shell.org',
    'country': 'CN',
    'province': 'SH',
    'city': 'SH',
    'org': 'home',
    'ou': 'home',
    'email': 'shell@shell.org',
    'alternative': '*.shell1.org, *.baidu.com',
    'usage': 'serverAuth',
    'ca': True,
}


def test_selfsign():
    print('selfsign')
    pkey = crypt.generate_rsa()
    csr = crypt.generate_req(pkey, X509DATA)
    bcsr = crypt.dump_certificate_request(csr)
    print(bcsr)

    csr1 = crypt.load_certificate_request(bcsr)
    cert = crypt.selfsign_req(csr1, pkey)
    bcert = crypt.dump_certificate(cert)
    print(bcert)
    print(crypt.gen_sub_name_str(cert.subject))
    print(cert.not_valid_before)
    print(cert.not_valid_after)
    return pkey, bcsr, bcert


def test_cert_parse(pkey, bcert):
    print('cert parse')
    cert = crypt.load_certificate(bcert)
    assert(crypt.cert_cn(cert) == X509DATA['cn'])
    assert(crypt.cert_ca(cert)[0] == X509DATA['ca'])
    assert(crypt.cert_extusage(cert) == X509DATA['usage'])
    assert(crypt.cert_alternative(cert) == X509DATA['alternative'])
    assert(crypt.cert_subject_keyid(cert).decode('utf-8')[-16:]
           == crypt.get_keyid(pkey))
    assert(crypt.cert_auth_keyid(cert).decode('utf-8')[-16:]
           == crypt.get_keyid(pkey))

    print(crypt.get_cert_dgst(cert))
    print(hex(cert.serial_number)[2:].strip('L').upper())


def test_csr(pkey, bcsr):
    print('csr parse')
    csr = crypt.load_certificate_request(bcsr)
    assert(crypt.cert_cn(csr) == X509DATA['cn'])
    assert(crypt.cert_ca(csr)[0] == X509DATA['ca'])
    assert(crypt.cert_extusage(csr) == X509DATA['usage'])
    assert(crypt.cert_alternative(csr) == X509DATA['alternative'])


def main():
    # test_key()
    # test_sign()
    pkey, bcsr, bcert = test_selfsign()
    # test_cert_parse(pkey, bcert)
    # test_csr(pkey, bcsr)
    reader = crypt.CSRReader(crypt.load_certificate_request(bcsr))
    print(list(reader.extensions()))


if __name__ == '__main__':
    main()
