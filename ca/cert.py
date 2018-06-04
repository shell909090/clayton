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
import hashlib
import datetime
import tempfile
import StringIO
import subprocess

DTFMT = '%b %d %H:%M:%S %Y GMT'


def read_cert(s):
    p = subprocess.Popen(['openssl', 'x509', '-text', '-noout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    o = p.communicate(s)[0]
    if p.returncode != 0:
        raise Exception('extract failed')
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


def encrypt(s, pwd):
    p = subprocess.Popen(['openssl', 'enc', '-aes128', '-k', pwd],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    return p.communicate(s)[0]


def encrypt_key(s, pwd):
    p = subprocess.Popen(['openssl', 'rsa', '-aes128', '-passout', 'pass:'+pwd],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    return p.communicate(s)[0]


def pkcs12(key, crt, pwd):
    p = subprocess.Popen(['openssl', 'pkcs12', '-export', '-passout', 'pass:'+pwd],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    return p.communicate(key+crt)[0]


def x509_modulus(crt):
    p = subprocess.Popen(['openssl', 'x509', '-modulus', '-noout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    return p.communicate(crt)[0]


def key_modulus(key):
    p = subprocess.Popen(['openssl', 'rsa', '-modulus', '-noout'],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    return p.communicate(key)[0]


def verify_file(key, crt, intcrt, ca=None):
    if key_modulus(key) != x509_modulus(crt):
        raise Exception('cert and key not match')
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
            raise Exception('verify chain failed')


re_pem = re.compile('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


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
            raise Exception('cert and key not match')
        return key, crts


def digest(s):
    return hashlib.sha256(s).digest()


def hexdigest(s):
    return hashlib.sha256(s).hexdigest()
