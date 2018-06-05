#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-05-11
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
import re
import base64
import hashlib
import datetime
import tempfile
import StringIO
import subprocess
from os import path


try:
    from settings import BASE_DIR
except:
    BASE_DIR = path.dirname(path.dirname(path.realpath(__file__)))


DTFMT = '%b %d %H:%M:%S %Y GMT'


class CryptoError(Exception):
    pass


# basic


def digest(s):
    return hashlib.sha256(s).digest()


def hexdigest(s):
    return hashlib.sha256(s).hexdigest()


def encrypt_data(pwd, data):
    with tempfile.NamedTemporaryFile() as src:
        src.write(data)
        src.flush()
        p = subprocess.check_output([
            'openssl', 'enc', '-aes-256-cbc', '-e', '-k', str(pwd),
            '-a', '-in', src.name])
    return p


def decrypt_data(pwd, data):
    with tempfile.NamedTemporaryFile() as src:
        src.write(data)
        src.flush()
        p = subprocess.check_output([
            'openssl', 'enc', '-aes-256-cbc', '-d', '-k', str(pwd),
            '-a', '-in', src.name])
    return p


# pubkeys


# openssl ecparam -genkey -name prime192v1
# openssl genrsa 2048
def create_key():
    output = subprocess.check_output(['openssl', 'genrsa', '2048'])
    return output


# openssl ec -pubout
# openssl rsa -pubout
# openssl pkey -pubout
def key_extract_pub(key):
    p = subprocess.Popen(['openssl', 'rsa', '-pubout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    o = p.communicate(key)[0]
    if p.returncode != 0:
        raise CryptoError('extract failed')
    return o


def key_modulus(key):
    p = subprocess.Popen(
        ['openssl', 'rsa', '-modulus', '-noout'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    return p.communicate(key)[0]


def encrypt_key(s, pwd):
    p = subprocess.Popen(
        ['openssl', 'rsa', '-aes128', '-passout', 'pass:'+pwd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    return p.communicate(s)[0]


def key_encrypt(pub, data):
    if data.startswith('KMSRSA:') or data.startswith('KMSAES:'):
        raise CryptoError('encrypted data')
    if len(data) >= 128:
        raise CryptoError('not support yet')
    return 'KMSRSA:' + base64.b64encode(key_encrypt_block(pub, data))


# openssl pkeyutl -encrypt -pubin -inkey rsa.pub
# openssl rsautl -encrypt -pubin -inkey keyfile.name
def key_encrypt_block(pub, data):
    with tempfile.NamedTemporaryFile() as keyfile:
        keyfile.write(pub)
        keyfile.flush()
        p = subprocess.Popen(
            ['openssl', 'rsautl', '-encrypt',
             '-pubin', '-inkey', keyfile.name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        o = p.communicate(data)[0]
        if p.returncode != 0:
            raise CryptoError('encrypt failed')
        return o


RE_KEY = re.compile(
    '-+BEGIN .*? PRIVATE KEY-+.*?-+END .*? PRIVATE KEY-+\n', re.S)


def get_keylist(key):
    if '\n-----BEGIN' in key:
        return [c for c in RE_KEY.findall(key)]
    return [key, ]


def key_decrypt(key, data):
    if data.startswith('KMSRSA:'):
        keys = get_keylist(key)
        data = base64.b64decode(data[7:])
        for key in keys:
            try:
                return key_decrypt_block(key, data)
            except CryptoError:
                pass
        raise CryptoError('decrypt failed')
    else:
        raise CryptoError('unrecognized data')


def key_decrypt_block(key, data):
    with tempfile.NamedTemporaryFile() as keyfile:
        keyfile.write(key)
        keyfile.flush()
        p = subprocess.Popen(
            ['openssl', 'rsautl', '-decrypt', '-inkey', keyfile.name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        o = p.communicate(data)[0]
        if p.returncode != 0:
            raise CryptoError('decrypt failed')
        return o


# certs


def create_cert_selfsign(key, subj, days=365):
    with tempfile.NamedTemporaryFile() as keyfile:
        keyfile.write(key)
        keyfile.flush()
        output = subprocess.check_output([
            'openssl', 'req', '-new', '-x509', '-days', str(days),
            '-key', keyfile.name, '-subj', subj])
        return output


def create_req(key, subj, days=365):
    with tempfile.NamedTemporaryFile() as keyfile:
        keyfile.write(key)
        keyfile.flush()
        output = subprocess.check_output([
            'openssl', 'req', '-new', '-days', str(days),
            '-key', keyfile.name, '-subj', subj])
        return output


def sign_req(cacrt, cakey, req, serial, days=365):
    tmpdir = tempfile.mkdtemp()
    # TODO: for security, chmod of tmpdir
    try:
        with open(path.join(tmpdir, 'ca.crt'), 'wb') as fo:
            fo.write(cacrt)
        with open(path.join(tmpdir, 'ca.key'), 'wb') as fo:
            fo.write(cakey)
        with open(path.join(tmpdir, 'req.csr'), 'wb') as fo:
            fo.write(req)
        with open(path.join(BASE_DIR, 'openssl.cnf'), 'rb') as fi:
            cnf = fi.read()
        cnf = cnf.format(dir=tmpdir)
        with open(path.join(tmpdir, 'openssl.cnf'), 'wb') as fo:
            fo.write(cnf)
        with open(path.join(tmpdir, 'index.txt'), 'wb') as fo:
            pass
        with open(path.join(tmpdir, 'serial'), 'wb') as fo:
            fo.write(serial)
        p = subprocess.Popen(
            ['openssl', 'ca', '-batch',
             '-config', path.join(tmpdir, 'openssl.cnf'),
             '-extensions', 'server_cert', '-days', str(days), '-notext',
             '-in', path.join(tmpdir, 'req.csr')],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        o = p.communicate(req)[0]
        if p.returncode != 0:
            raise CryptoError('sign failed')
        return o
    finally:
        shutil.rmtree(tmpdir)


def cert_extract_pub(cert):
    p = subprocess.Popen(['openssl', 'x509', '-pubkey', '-noout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    o = p.communicate(cert)[0]
    if p.returncode != 0:
        raise CryptoError('extract failed')
    return o


def read_cert(cert):
    p = subprocess.Popen(['openssl', 'x509', '-text', '-noout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    o = p.communicate(cert)[0]
    if p.returncode != 0:
        raise CryptoError('extract failed')
    buf = StringIO.StringIO(o)
    attrs = {}
    it = iter(buf)
    for line in it:
        line = line.strip()
        if line.startswith('Subject:'):
            subject = line.split(': ', 1)[1]
            a = dict([c.split(' = ', 1) for c in subject.split(', ')])
            attrs.update(a)
            attrs['subject'] = subject.strip()
        elif line.startswith('Issuer:'):
            attrs['issuer'] = line.split(': ', 1)[1].strip()
        elif line.startswith('Not Before:'):
            attrs['notbefore'] = datetime.datetime.strptime(
                line.split(': ', 1)[1].strip(), DTFMT)
        elif line.startswith('Not After :'):
            attrs['notafter'] = datetime.datetime.strptime(
                line.split(': ', 1)[1].strip(), DTFMT)
        elif line.startswith('Serial Number:'):
            attrs['sn'] = next(it).strip()
        elif line.startswith('X509v3 Subject Key Identifier'):
            attrs['subkeyid'] = next(it).strip()
        elif line.startswith('X509v3 Authority Key Identifier'):
            attrs['authkeyid'] = next(it).strip()
            if attrs['authkeyid'].startswith('keyid:'):
                attrs['authkeyid'] = attrs['authkeyid'][6:]
        elif line.startswith('X509v3 Basic Constraints'):
            attrs['ca'] = (next(it).strip() == 'CA:TRUE')
    return attrs


def pkcs12(key, crt, pwd):
    p = subprocess.Popen(
        ['openssl', 'pkcs12', '-export', '-passout', 'pass:'+pwd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    return p.communicate(key+crt)[0]


def x509_modulus(crt):
    p = subprocess.Popen(
        ['openssl', 'x509', '-modulus', '-noout'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    return p.communicate(crt)[0]


def verify_file(key, crt, intcrt, ca=None):
    if key_modulus(key) != x509_modulus(crt):
        raise CryptoError('cert and key not match')
    with tempfile.NamedTemporaryFile() as inter:
        inter.write(intcrt)
        inter.flush()
        cmd = ['openssl', 'verify', '-untrusted', inter.name, ]
        if ca:
            cmd.extend(['-trusted', ca])
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.communicate(crt)
        if p.returncode != 0:
            raise CryptoError('verify chain failed')


re_pem = re.compile(
    '-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def verify(key, crt):
    crts = re_pem.findall(crt)

    if len(crts) > 2:
        with tempfile.NamedTemporaryFile() as ca:
            ca.write(crts[2])
            ca.flush()
            verify_file(key, crts[0], crts[1], ca.name)
            return key, crts

    if len(crts) > 1:
        verify_file(key, crts[0], crts[1])
        return key, crts

    if len(crts) > 0 and key:
        if key_modulus(key) != x509_modulus(crts[0]):
            raise CryptoError('cert and key not match')
        return key, crts
