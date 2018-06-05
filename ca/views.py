from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from django_tables2 import RequestConfig

import cert
from .models import PubKey, Cert
from .forms import ImpCertForm, ReqForm, SignForm
from .tables import KeyTable, CertTable


# key


def list_key(request, dgst):
    keys = PubKey.objects
    if dgst:
        keys = keys.filter(dgst=dgst)
    tab = KeyTable(keys.all())
    RequestConfig(request).configure(tab)
    return render(request, 'ca/list_key.html', {'tab': tab})


# TODO: size?
def build_key(request):
    pri = cert.create_key()
    pub = cert.key_extract_pub(pri)
    dgst = cert.hexdigest(pri)[-16:]
    key = PubKey(dgst=dgst, pub=pub, key=pri)
    key.save()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def delete_key(request, dgst):
    key = PubKey.objects.get(dgst=dgst)
    key.delete()
    return HttpResponseRedirect(
        reverse('ca:list_key', kwargs={'dgst': ''}))


def build_req(request, dgst):
    if request.method != 'POST':
        form = ReqForm()
        return render(request, 'ca/build_req.html', {'form': form})
    form = ReqForm(request.POST)
    if not form.is_valid():
        return render(request, 'ca/import_req.html', {'form': form})

    key = PubKey.objects.get(dgst=dgst)
    if form.cleaned_data['selfsign']:
        subj = form.get_subj()
        crtfile = cert.create_cert_selfsign(
            key.key, subj,
            form.cleaned_data.get('days') or '3650')
        imp_crt(key.key, crtfile)
        return HttpResponseRedirect(
            reverse('ca:list_cert', kwargs={'dgst': ''}))

    subj = form.get_subj()
    reqfile = cert.create_req(
        key.key, subj,
        form.cleaned_data.get('days') or '3650')
    resp = HttpResponse(reqfile, content_type="application/x-pem-file")
    resp['Content-Disposition'] = 'inline; filename=%s.csr' % key.dgst
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


def imp_crt(key, crt):
    dgst = cert.hexdigest(crt)[-16:]
    if Cert.objects.filter(dgst=dgst).count():
        return

    k = None
    kdgst = cert.hexdigest(key)[-16:]
    if key:
        q = PubKey.objects.filter(dgst=kdgst)
        if q.count() == 0:
            k = PubKey(kdgst, key=key)
            k.save()
        else:
            k = q.get()

    attrs = cert.read_cert(crt)

    issuer = None
    q = Cert.objects.filter(sub=attrs['issuer'], keyid=attrs['authkeyid'])
    if q.count():
        issuer = q.get()
    c = Cert(
        dgst=dgst, status=0, sn=attrs['sn'],
        sub=attrs['subject'], cn=attrs['CN'],
        notbefore=attrs['notbefore'], notafter=attrs['notafter'],
        issuer=issuer, usage='', vtype=0, keyid=attrs['subkeyid'],
        ca=attrs['ca'], alternative='', certfile=crt, key=k)
    c.save()


def import_pem(request):
    if request.method != 'POST':
        form = ImpCertForm()
        return render(request, 'ca/import_pem.html', {'form': form})
    form = ImpCertForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, 'ca/import_pem.html', {'form': form})

    certchain = form.cleaned_data['certchain'].read()
    prikey = form.cleaned_data['prikey'].read()
    prikey, crts = cert.verify(prikey, certchain)
    for crt in crts[:1:-1]:
        imp_crt(None, crt)
    imp_crt(prikey, crts[0])
    dgst = cert.hexdigest(crts[0])[-16:]
    return HttpResponseRedirect(
        reverse('ca:list_cert', kwargs={'dgst': dgst}))


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


# password?
def export_key(request, dgst):
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
