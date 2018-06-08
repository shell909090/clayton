#!/usr/bin/python
# -*- coding: utf-8 -*-
import binascii

from django import forms
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect

from cryptography import exceptions
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# import cert
import crypt
from .models import PubKey, Cert
from .forms import (BuildRSAForm, BuildECForm, TextForm, DoubleTextForm,
                    ImpKeyForm, ImpCertForm, ReqForm, SignForm)
from .tables import KeyTable, CertTable


# key


def list_key(request, dgst):
    q = PubKey.objects
    if dgst:
        q = q.filter(dgst=dgst)
    tab = KeyTable(q.all(), request=request)
    return render(request, 'ca/list_key.html', {'tab': tab})


def detail_key(request, dgst):
    obj = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(obj.key)
    p = crypt.parse_privatekey(pkey)
    tab = CertTable(Cert.objects.filter(key_id=dgst).all(), request=request)
    pm = {
        'obj': obj,
        'p': p,
        'rsa': p['type'].startswith('RSA'),
        'tab': tab,
    }
    return render(request, 'ca/detail_key.html', pm)


def remove_key(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    okey.delete()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def build_rsa(request):
    if request.method != 'POST':
        form = BuildRSAForm()
        return render(request, 'ca/post.html', {'form': form})
    form = BuildRSAForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    size = form.cleaned_data['size']
    pkey = crypt.generate_rsa(size)
    strkey = crypt.dump_privatekey(pkey)
    dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=dgst, keytype=1, size=size, key=strkey)
    okey.save()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def build_ec(request):
    if request.method != 'POST':
        form = BuildECForm()
        return render(request, 'ca/post.html', {'form': form})
    form = BuildECForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    curve = form.cleaned_data['curve']
    pkey = crypt.generate_ec(curve)
    size = pkey.public_key().public_numbers().curve.key_size
    strkey = crypt.dump_privatekey(pkey)
    dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=dgst, keytype=3, size=size, key=strkey)
    okey.save()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def encrypt(request, dgst):
    if request.method != 'POST':
        form = TextForm()
        return render(request, 'ca/post.html', {'form': form})
    form = TextForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    msg = bytes(form.cleaned_data['txt'])
    enc = pkey.public_key().encrypt(msg, crypt.OAEP)
    print(enc)
    return render(request, 'ca/show_msg.html',
                  {'msg': binascii.b2a_base64(enc)})


def decrypt(request, dgst):
    if request.method != 'POST':
        form = TextForm()
        return render(request, 'ca/post.html', {'form': form})
    form = TextForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    enc = binascii.a2b_base64(form.cleaned_data['txt'])
    msg = pkey.decrypt(bytes(enc), crypt.OAEP)
    return render(request, 'ca/show_msg.html', {'msg': msg})


def sign(request, dgst):
    if request.method != 'POST':
        form = TextForm()
        return render(request, 'ca/post.html', {'form': form})
    form = TextForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    s = crypt.pubkey_sign(pkey, bytes(form.cleaned_data['txt']))
    return render(request, 'ca/show_msg.html',
                  {'msg': binascii.b2a_base64(s)})


def verify(request, dgst):
    if request.method != 'POST':
        form = DoubleTextForm()
        return render(request, 'ca/post.html', {'form': form})
    form = DoubleTextForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/post.html', {'form': form})
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    sig = bytes(binascii.a2b_base64(form.cleaned_data['txt2']))
    try:
        crypt.pubkey_verify(pkey.public_key(),
                            bytes(form.cleaned_data['txt1']), sig)
        msg = 'OK'
    except exceptions.InvalidSignature:
        msg = 'failed'
    return render(request, 'ca/show_msg.html', {'msg': msg})


def imp_key(strkey):
    pkey = crypt.load_privatekey(strkey)
    dgst = crypt.get_keyid(pkey)
    p = crypt.parse_privatekey(pkey)
    typeid = {v: k for k, v in PubKey.KEY_CHOICES}[p['type']]
    q = PubKey.objects.filter(dgst=dgst)
    if q.count() == 0:
        okey = PubKey(dgst, keytype=typeid, size=p['size'], key=strkey)
        okey.save()
    else:
        okey = q.get()
    return okey


def import_key(request):
    if request.method != 'POST':
        form = ImpKeyForm()
        return render(request, 'ca/import_pem.html', {'form': form})
    form = ImpKeyForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'ca/import_pem.html', {'form': form})

    imp_key(form.cleaned_data['prikey'].read())
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def export_key(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    resp = HttpResponse(okey.key, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % okey.dgst
    return resp


def export_pubkey(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    strpub = crypt.dump_publickey(pkey)
    resp = HttpResponse(strpub, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % okey.dgst
    return resp


def export_sshpub(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    strpub = crypt.dump_publickey(pkey, encoding=Encoding.OpenSSH,
                                  format=PublicFormat.OpenSSH)
    return render(request, 'ca/show_msg.html', {'msg': strpub})


def build_req(request, dgst):
    if request.method != 'POST':
        form = ReqForm()
        return render(request, 'ca/build_req.html', {'form': form})
    form = ReqForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/build_req.html', {'form': form})

    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.key)
    csr = crypt.generate_req(pkey, form.cleaned_data)

    if form.cleaned_data['selfsign']:
        cert = crypt.selfsign_req(csr, pkey)
        strcert = crypt.dump_certificate(cert)
        ocert = imp_cert(strcert)
        return HttpResponseRedirect(
            reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))

    strcsr = crypt.dump_certificate_request(csr)
    resp = HttpResponse(strcsr, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % okey.dgst
    return resp


# cert


def list_cert(request, dgst):
    certs = Cert.objects
    if dgst:
        certs = certs.filter(dgst=dgst)
    tab = CertTable(certs.all(), request=request)
    return render(request, 'ca/list_cert.html', {'tab': tab})


def detail_cert(request, dgst):
    obj = Cert.objects.get(dgst=dgst)
    cert = crypt.load_certificate(obj.certfile)
    tab = CertTable(Cert.objects.filter(issuer=obj).all(), request=request)
    p = {
        'obj': obj,
        'cert': cert,
        'ca': bool(crypt.cert_ca(cert)),
        'authkeyid': crypt.cert_authkeyid(cert),
        'extusage': crypt.cert_extusage(cert),
        'usage': crypt.cert_usage(cert),
        'tab': tab,
    }
    return render(request, 'ca/detail_cert.html', p)


def imp_cert(strpem):
    cert = crypt.load_certificate(strpem)
    dgst = crypt.get_cert_dgst(cert)
    q = Cert.objects.filter(dgst=dgst)
    if q.count() != 0:
        ocert = q.get()
        return ocert

    issuer = None
    q = Cert.objects.filter(keyid=crypt.cert_authkeyid(cert))
    if q.count() != 0:
        issuer = q.get()

    ocert = Cert(
        dgst=dgst,
        status=0,
        sn=hex(cert.serial_number)[2:].strip('L').upper(),
        sub=crypt.gen_sub_name_str(cert.subject),
        cn=crypt.cert_cn(cert),
        notbefore=cert.not_valid_before,
        notafter=cert.not_valid_after,
        issuer=issuer,
        ca=bool(crypt.cert_ca(cert)),
        keyid=crypt.cert_subject_keyid(cert),
        alternative=crypt.cert_alternative(cert),
        certfile=strpem,
        key_id=crypt.get_keyid(cert))
    ocert.save()
    return ocert


def import_pem(request):
    if request.method != 'POST':
        form = ImpCertForm()
        return render(request, 'ca/import_pem.html', {'form': form})
    form = ImpCertForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'ca/import_pem.html', {'form': form})

    certchain = form.cleaned_data['certchain'].read()
    strpems = list(crypt.split_pems(certchain))
    crypt.verify(strpems)

    for strpem in strpems[::-1]:
        imp_cert(strpem)
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


def remove_cert(request, dgst):
    crt = Cert.objects.get(dgst=dgst)
    crt.delete()
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


def build_cert(request, dgst):
    if request.method != 'POST':
        form = ReqForm()
        form.fields['selfsign'].widget = forms.HiddenInput()
        return render(request, 'ca/build_req.html', {'form': form})
    form = ReqForm(request.POST)
    form.fields['selfsign'].widget = forms.HiddenInput()
    if not form.is_valid():
        return render(request, 'ca/build_req.html', {'form': form})

    issuer_ocert = Cert.objects.get(dgst=dgst)
    issuer_cert = crypt.load_certificate(issuer_ocert.certfile)
    issuer_key = crypt.load_privatekey(issuer_ocert.key.key)

    pkey = crypt.generate_rsa(2048)
    strkey = crypt.dump_privatekey(pkey)
    key_dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=key_dgst, keytype=1, size=2048, key=strkey)
    okey.save()

    csr = crypt.generate_req(pkey, form.cleaned_data)
    cert = crypt.sign_req(csr, issuer_cert, issuer_key)
    strcert = crypt.dump_certificate(cert)
    ocert = imp_cert(strcert)
    return HttpResponseRedirect(
        reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))


# FIXME: 确认过程
def sign_req(request, dgst):
    if request.method != 'POST':
        form = SignForm()
        return render(request, 'ca/sign_req.html', {'form': form})
    form = SignForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'ca/sign_req.html', {'form': form})

    issuer_ocert = Cert.objects.get(dgst=dgst)
    issuer_cert = crypt.load_certificate(issuer_ocert.certfile)
    issuer_pkey = crypt.load_privatekey(issuer_ocert.key.key)

    strcsr = form.cleaned_data['req'].read()
    csr = crypt.load_certificate_request(strcsr)
    cert = crypt.sign_req(csr, issuer_cert, issuer_pkey,
                          days=int(form.cleaned_data['days'] or '3650'))
    strcert = crypt.dump_certificate(cert)
    ocert = imp_cert(strcert)
    return HttpResponseRedirect(
        reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))


def export_pem(request, dgst):
    ocert = Cert.objects.get(dgst=dgst)
    resp = HttpResponse(ocert.certfile, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % ocert.dgst
    return resp


def export_der(request, dgst):
    ocert = Cert.objects.get(dgst=dgst)
    cert = crypt.load_certificate(ocert.certfile)
    strcert = crypt.dump_certificate(cert, Encoding.DER)
    resp = HttpResponse(strcert, content_type="application/pkix-cert")
    resp['Content-Disposition'] = 'inline; filename=%s.der' % ocert.dgst
    return resp


def export_chain(request, dgst):
    certs = []
    ocert = Cert.objects.get(dgst=dgst)
    while ocert:
        certs.append(ocert.certfile)
        ocert = ocert.issuer
    certs.pop(-1)
    resp = HttpResponse('\n'.join(certs),
                        content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % dgst
    return resp


def export_pkcs12(request, dgst):
    certs = []
    ocert = Cert.objects.get(dgst=dgst)
    strkey = ocert.key.key
    while ocert:
        certs.append(ocert.certfile)
        ocert = ocert.issuer
    # TODO: passphrase
    strpkcs12 = crypt.to_pkcs12(strkey, certs.pop(0), certs)
    resp = HttpResponse(strpkcs12, content_type="application/x-pkcs12")
    resp['Content-Disposition'] = 'inline; filename=%s.p12' % dgst
    return resp


def revoke_cert(request, dgst):
    pass


def show_crl(request, dgst):
    pass
