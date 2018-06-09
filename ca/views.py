#!/usr/bin/python
# -*- coding: utf-8 -*-
import binascii

from django import forms
from django.core import exceptions as djerr
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect

from django_filters.views import FilterView
from django_tables2.views import SingleTableMixin

from cryptography import exceptions
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import crypt
from .models import PubKey, Cert
from . import forms as caforms
from . import tables, filters


# key


class ListKeyView(SingleTableMixin, FilterView):
    table_class = tables.PubKeyTable
    model = PubKey
    template_name = 'ca/list_key.html'
    filterset_class = filters.PubKeyFilter


def detail_key(request, dgst):
    obj = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(obj.dat)
    p = crypt.parse_privatekey(pkey)
    certs = Cert.objects.filter(key_id=dgst).all()
    tab = tables.CertTable(certs, request=request)
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
    return HttpResponseRedirect(reverse('ca:list_key'))


def build_rsa(request):
    if request.method != 'POST':
        form = caforms.BuildRSAForm()
        p = {'title': 'build rsa', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.BuildRSAForm(request.POST)
    if not form.is_valid():
        p = {'title': 'build rsa', 'form': form}
        return render(request, 'ca/post.html', p)
    size = form.cleaned_data['size']
    pkey = crypt.generate_rsa(size)
    bkey = crypt.dump_privatekey(pkey)
    dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=dgst, keytype=1, size=size, dat=bkey)
    okey.save()
    return HttpResponseRedirect(reverse('ca:list_key'))


def build_ec(request):
    if request.method != 'POST':
        form = caforms.BuildECForm()
        p = {'title': 'build ec', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.BuildECForm(request.POST)
    if not form.is_valid():
        p = {'title': 'build ec', 'form': form}
        return render(request, 'ca/post.html', p)
    curve = form.cleaned_data['curve']
    pkey = crypt.generate_ec(curve)
    size = pkey.public_key().public_numbers().curve.key_size
    bkey = crypt.dump_privatekey(pkey)
    dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=dgst, keytype=3, size=size, dat=bkey)
    okey.save()
    return HttpResponseRedirect(reverse('ca:list_key'))


def encrypt(request, dgst):
    if request.method != 'POST':
        form = caforms.TextForm()
        p = {'title': 'encrypt message', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.TextForm(request.POST)
    if not form.is_valid():
        p = {'title': 'encrypt message', 'form': form}
        return render(request, 'ca/post.html', p)
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    msg = form.cleaned_data['txt'].encode('utf-8')
    enc = pkey.public_key().encrypt(msg, crypt.OAEP)
    p = {
        'title': 'encrypt message',
        'msg': binascii.b2a_base64(enc).decode('utf-8')
    }
    return render(request, 'ca/show_msg.html', p)


def decrypt(request, dgst):
    if request.method != 'POST':
        form = caforms.TextForm()
        p = {'title': 'decrypt message', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.TextForm(request.POST)
    if not form.is_valid():
        p = {'title': 'decrypt message', 'form': form}
        return render(request, 'ca/post.html', p)
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    enc = binascii.a2b_base64(form.cleaned_data['txt'])
    msg = pkey.decrypt(enc, crypt.OAEP)
    p = {
        'title': 'decrypt message',
        'msg': msg.decode('utf-8'),
    }
    return render(request, 'ca/show_msg.html', p)


def sign(request, dgst):
    if request.method != 'POST':
        form = caforms.TextForm()
        p = {'title': 'sign message', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.TextForm(request.POST)
    if not form.is_valid():
        p = {'title': 'sign message', 'form': form}
        return render(request, 'ca/post.html', p)
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    msg = form.cleaned_data['txt'].encode('utf-8')
    sig = crypt.pubkey_sign(pkey, msg)
    p = {
        'title': 'sign message',
        'msg': binascii.b2a_base64(sig).decode('utf-8'),
    }
    return render(request, 'ca/show_msg.html', p)


def verify(request, dgst):
    if request.method != 'POST':
        form = caforms.DoubleTextForm()
        p = {'title': 'verify sign', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.DoubleTextForm(request.POST)
    if not form.is_valid():
        p = {'title': 'verify sign', 'form': form}
        return render(request, 'ca/post.html', p)
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    msg = form.cleaned_data['txt1'].encode('utf-8')
    sig = binascii.a2b_base64(form.cleaned_data['txt2'])
    try:
        crypt.pubkey_verify(pkey.public_key(), msg, sig)
        msg = 'OK'
    except exceptions.InvalidSignature:
        msg = 'failed'
    p = {
        'title': 'verify sign',
        'msg': msg,
    }
    return render(request, 'ca/show_msg.html', p)


def imp_key(bkey):
    pkey = crypt.load_privatekey(bkey)
    dgst = crypt.get_keyid(pkey)
    p = crypt.parse_privatekey(pkey)
    typeid = {v: k for k, v in PubKey.KEY_CHOICES}[p['type']]
    q = PubKey.objects.filter(dgst=dgst)
    if q.count() == 0:
        okey = PubKey(dgst, keytype=typeid, size=p['size'], dat=bkey)
        okey.save()
    else:
        okey = q.get()
    return okey


def import_key(request):
    if request.method != 'POST':
        form = caforms.UploadForm()
        p = {'title': 'import key', 'form': form}
        return render(request, 'ca/post_file.html', p)
    form = caforms.UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        p = {'title': 'import key', 'form': form}
        return render(request, 'ca/post_file.html', p)

    imp_key(form.cleaned_data['upload'].read())
    return HttpResponseRedirect(reverse('ca:list_key'))


def export_key(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    resp = HttpResponse(okey.dat, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % okey.dgst
    return resp


def export_pubkey(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    bpub = crypt.dump_publickey(pkey.public_key())
    resp = HttpResponse(bpub, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % okey.dgst
    return resp


def export_sshpub(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    bpub = crypt.dump_publickey(
        pkey.public_key(),
        encoding=Encoding.OpenSSH,
        format=PublicFormat.OpenSSH)
    p = {'title': 'ssh public key', 'msg': bpub.decode('utf-8')}
    return render(request, 'ca/show_msg.html', p)


def build_req(request, dgst):
    if request.method != 'POST':
        form = caforms.ReqForm()
        p = {'title': 'build cert request', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.ReqForm(request.POST)
    if not form.is_valid():
        p = {'title': 'build cert request', 'form': form}
        return render(request, 'ca/post.html', p)

    okey = PubKey.objects.get(dgst=dgst)
    pkey = crypt.load_privatekey(okey.dat)
    csr = crypt.generate_req(pkey, form.cleaned_data)

    if form.cleaned_data['selfsign']:
        cert = crypt.selfsign_req(csr, pkey)
        bcert = crypt.dump_certificate(cert)
        ocert = imp_cert(bcert)
        return HttpResponseRedirect(
            reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))

    bcsr = crypt.dump_certificate_request(csr)
    resp = HttpResponse(bcsr, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % okey.dgst
    return resp


# cert


# def list_cert(request, dgst):
#     q = Cert.objects
#     if dgst:
#         q = q.filter(dgst=dgst)
#     tab = tables.CertTable(q.all(), request=request)
#     return render(request, 'ca/list_cert.html', {'tab': tab})


class ListCertView(SingleTableMixin, FilterView):
    table_class = tables.CertTable
    model = Cert
    template_name = 'ca/list_cert.html'
    filterset_class = filters.CertFilter


def detail_cert(request, dgst):
    obj = Cert.objects.get(dgst=dgst)
    cert = crypt.load_certificate(obj.dat)
    certs = Cert.objects.filter(issuer=obj).all()
    tab = tables.CertTable(certs, request=request)
    # TODO: display chain
    p = {
        'obj': obj,
        'cert': cert,
        'ca': crypt.cert_ca(cert)[0],
        'authkeyid': crypt.cert_auth_keyid(cert),
        'extusage': crypt.cert_extusage(cert),
        'usage': crypt.cert_usage(cert),
        'tab': tab,
    }
    return render(request, 'ca/detail_cert.html', p)


def imp_cert(bcert):
    cert = crypt.load_certificate(bcert)
    dgst = crypt.get_cert_dgst(cert)
    q = Cert.objects.filter(dgst=dgst)
    if q.count() != 0:
        ocert = q.get()
        return ocert

    issuer = None
    q = Cert.objects.filter(keyid=crypt.cert_auth_keyid(cert))
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
        ca=crypt.cert_ca(cert)[0],
        keyid=crypt.cert_subject_keyid(cert),
        alternative=crypt.cert_alternative(cert),
        dat=bcert,
        key_id=crypt.get_keyid(cert))
    ocert.save()
    return ocert


def import_pem(request):
    if request.method != 'POST':
        form = caforms.UploadForm()
        p = {'title': 'import cert', 'form': form}
        return render(request, 'ca/post_file.html', p)
    form = caforms.UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        p = {'title': 'import cert', 'form': form}
        return render(request, 'ca/post_file.html', p)

    certchain = form.cleaned_data['upload'].read()
    bcerts = list(crypt.split_pems(certchain))
    # crypt.verify(bpems)

    for bcert in bcerts[::-1]:
        imp_cert(bcert)
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


def remove_cert(request, dgst):
    crt = Cert.objects.get(dgst=dgst)
    crt.delete()
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


def build_cert(request, dgst):
    if request.method != 'POST':
        form = caforms.ReqForm()
        form.fields['selfsign'].widget = forms.HiddenInput()
        p = {'title': 'build cert', 'form': form}
        return render(request, 'ca/post.html', p)
    form = caforms.ReqForm(request.POST)
    form.fields['selfsign'].widget = forms.HiddenInput()
    if not form.is_valid():
        p = {'title': 'build cert', 'form': form}
        return render(request, 'ca/post.html', p)

    issuer_ocert = Cert.objects.get(dgst=dgst)
    issuer_cert = crypt.load_certificate(issuer_ocert.dat)
    issuer_key = crypt.load_privatekey(issuer_ocert.key.dat)

    pkey = crypt.generate_rsa(2048)
    bkey = crypt.dump_privatekey(pkey)
    key_dgst = crypt.get_keyid(pkey)
    okey = PubKey(dgst=key_dgst, keytype=1, size=2048, dat=bkey)
    okey.save()

    csr = crypt.generate_req(pkey, form.cleaned_data)
    cert = crypt.sign_req(csr, issuer_cert, issuer_key)
    strcert = crypt.dump_certificate(cert)
    ocert = imp_cert(strcert)
    return HttpResponseRedirect(
        reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))


def sign_req(request, dgst):
    if request.method != 'POST':
        form = caforms.SignForm()
        p = {'title': 'import cert', 'form': form}
        return render(request, 'ca/post_file.html', p)

    form = caforms.SignForm(request.POST, request.FILES)
    if form.is_valid():
        bcsr = form.cleaned_data['req'].read()
        csr = crypt.load_certificate_request(bcsr)
        form = caforms.SignConfirmForm({
            'csr': bcsr.decode('utf-8'), 'days': '3650'})
        p = {'obj': crypt.CSRReader(csr), 'form': form}
        return render(request, 'ca/sign_confirm.html', p)

    form = caforms.SignConfirmForm(request.POST, request.FILES)
    if not form.is_valid():
        p = {'title': 'import cert', 'form': form}
        return render(request, 'ca/post_file.html', p)

    issuer_ocert = Cert.objects.get(dgst=dgst)
    issuer_cert = crypt.load_certificate(issuer_ocert.dat)
    issuer_pkey = crypt.load_privatekey(issuer_ocert.key.dat)

    bcsr = form.cleaned_data['csr'].encode('utf-8')
    csr = crypt.load_certificate_request(bcsr)
    cert = crypt.sign_req(csr, issuer_cert, issuer_pkey,
                          days=int(form.cleaned_data['days'] or '3650'))
    bcert = crypt.dump_certificate(cert)
    ocert = imp_cert(bcert)
    return HttpResponseRedirect(
        reverse('ca:detail_cert', kwargs={'dgst': ocert.dgst}))


def export_pem(request, dgst):
    ocert = Cert.objects.get(dgst=dgst)
    resp = HttpResponse(ocert.dat, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % ocert.dgst
    return resp


def export_der(request, dgst):
    ocert = Cert.objects.get(dgst=dgst)
    cert = crypt.load_certificate(ocert.dat)
    strcert = crypt.dump_certificate(cert, Encoding.DER)
    resp = HttpResponse(strcert, content_type="application/pkix-cert")
    resp['Content-Disposition'] = 'inline; filename=%s.der' % ocert.dgst
    return resp


def export_chain(request, dgst):
    certs = []
    ocert = Cert.objects.get(dgst=dgst)
    while ocert:
        certs.append(ocert.dat)
        ocert = ocert.issuer
    certs.pop(-1)
    resp = HttpResponse(b'\n'.join(certs),
                        content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.pem' % dgst
    return resp


def export_pkcs12(request, dgst):
    certs = []
    ocert = Cert.objects.get(dgst=dgst)
    try:
        bkey = ocert.key.dat
    except djerr.ObjectDoesNotExist:
        bkey = None
    while ocert:
        certs.append(ocert.dat)
        ocert = ocert.issuer
    # TODO: passphrase
    strpkcs12 = crypt.to_pkcs12(bkey, certs.pop(0), certs)
    resp = HttpResponse(strpkcs12, content_type="application/x-pkcs12")
    resp['Content-Disposition'] = 'inline; filename=%s.p12' % dgst
    return resp


def revoke_cert(request, dgst):
    pass


def show_crl(request, dgst):
    pass
