import binascii

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from django_tables2 import RequestConfig
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import cert
import crypt
from .models import PubKey, Cert
from .forms import ImpKeyForm, ImpCertForm, ReqForm, SignForm
from .tables import KeyTable, CertTable


# key


def list_key(request, dgst):
    q = PubKey.objects
    if dgst:
        q = q.filter(dgst=dgst)
    tab = KeyTable(q.all())
    RequestConfig(request).configure(tab)
    return render(request, 'ca/list_key.html', {'tab': tab})


def build_key(request):
    pkey = crypt.generate_key()  # TODO: size?
    strkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    strpub = crypto.dump_publickey(crypto.FILETYPE_PEM, pkey)
    dgst = crypt.hexdigest(strpub)[-16:].upper()
    okey = PubKey(dgst=dgst, pub=strpub, key=strkey)
    okey.save()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def delete_key(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    okey.delete()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def build_req(request, dgst):
    if request.method != 'POST':
        form = ReqForm()
        return render(request, 'ca/build_req.html', {'form': form})
    form = ReqForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/import_req.html', {'form': form})

    okey = PubKey.objects.get(dgst=dgst)
    # if form.cleaned_data['selfsign']:
    #     subj = form.get_subj()
    #     crtfile = cert.create_cert_selfsign(
    #         okey.key, subj,
    #         form.cleaned_data.get('days') or '3650')
    #     imp_crt(okey.key, crtfile)
    #     return HttpResponseRedirect(
    #         reverse('ca:list_cert', kwargs={'dgst': ''}))

    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, okey.key)
    req = crypt.generate_req(pkey, form.cleaned_data)

    # TODO:
    # if form.cleaned_data['selfsign']:
    #     cert = crypt.selfsign_cert(req, pkey, serial='')

    strreq = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    resp = HttpResponse(strreq, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % okey.dgst
    return resp


def imp_key(strkey):
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, strkey)
    strpub = crypto.dump_publickey(crypto.FILETYPE_PEM, pkey)
    dgst = crypt.hexdigest(strpub)[-16:].upper()
    q = PubKey.objects.filter(dgst=dgst)
    if q.count() == 0:
        okey = PubKey(dgst, pub=strpub, key=strkey)
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

    strkey = form.cleaned_data['prikey'].read()
    imp_key(strkey)
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def export_key(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    resp = HttpResponse(okey.key, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % okey.dgst
    return resp


def export_pubkey(request, dgst):
    okey = PubKey.objects.get(dgst=dgst)
    resp = HttpResponse(okey.pub, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % okey.dgst
    return resp


# cert


def list_cert(request, dgst):
    certs = Cert.objects
    if dgst:
        certs = certs.filter(dgst=dgst)
    tab = CertTable(certs.all())
    RequestConfig(request).configure(tab)
    return render(request, 'ca/list_cert.html', {'tab': tab})


def cert_detail(request, dgst):
    # if request.method != 'POST':
    #     form = CertForm()
    #     return render(request, 'ca/build_cert.html', {'form': form})
    # form = CertForm(request.POST)
    # if form.is_valid():
    #     pass
    pass


def imp_cert(strpem, okey=None):
    dgst = crypt.hexdigest(strpem)[-16:].upper()
    q = Cert.objects.filter(dgst=dgst)
    if q.count() != 0:
        ocert = q.get()
        return ocert

    cn, keyid, alternative, authkeyid = crypt.read_cert(strpem)

    issuer = None
    if authkeyid:
        q = Cert.objects.filter(keyid=authkeyid)
        if q.count() != 0:
            issuer = q.get()

    sn = hex(cert.serial_number)[2:].upper().strip('L')
    ocert = Cert(
        dgst=dgst, status=0, sn=sn,
        sub=crypt.gen_sub_name_str(cert.subject), cn=cn,
        notbefore=cert.not_valid_before, notafter=cert.not_valid_after,
        issuer=issuer, keyid=keyid, alternative=alternative,
        certfile=strpem, key=okey)
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
    strkey = form.cleaned_data['prikey'].read()
    strpems = list(crypt.split_pems(certchain))
    crypt.verify(strpems, strkey)

    okey = imp_key(strkey)
    for strpem in strpems[::-1]:
        imp_cert(strpem)
    imp_cert(strpems[0], okey)
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


def delete_cert(request, dgst):
    crt = Cert.objects.get(dgst=dgst)
    crt.delete()
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': ''}))


# build_key, build_key_server, build_inter
# ca, vtype, managed crl
def build_cert(request):
    # if request.method != 'POST':
    #     form = CertForm()
    #     return render(request, 'ca/build_cert.html', {'form': form})
    # form = CertForm(request.POST)
    # if form.is_valid():
    #     pass
    pass


def sign_req(request, dgst):
    if request.method != 'POST':
        form = SignForm()
        return render(request, 'ca/sign_req.html', {'form': form})
    form = SignForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'ca/sign_req.html', {'form': form})

    cacrt = Cert.objects.get(dgst=dgst)
    cakey = cacrt.key
    csrfile = form.cleaned_data['req'].read()
    sn = ''
    crt = cert.sign_req(cacrt.certfile, cakey.key, csrfile,
                        sn, days=form.cleaned_data['days'] or '3650')
    imp_crt(None, crt)
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': dgst}))


def export_pem(request, dgst):
    pass


def export_der(request, dgst):
    pass


def export_chain(request, dgst):
    pass


def export_pkcs12(request, dgst):
    pass


def mail_me(request, dgst):
    pass


def revoke_cert(request, dgst):
    pass


def show_crl(request, dgst):
    pass
