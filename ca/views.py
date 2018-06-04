from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

import cert
from .models import PubKey, Cert
from .forms import CertForm


def list_ca(request):
    pass


def build_ca(request):
    pass


def cert_detail(request, dgst):
    pass


def list_cert(request, dgst):
    certs = Cert.objects
    if dgst:
        certs = certs.filter(dgst=dgst)
    return render(request, 'ca/list_cert.html', {'certs': certs.all()})


def imp_crt(key, crt):
    dgst = cert.hexdigest(crt)
    if Cert.objects.filter(dgst=dgst).count():
        return

    k = None
    kdgst = cert.hexdigest(key)
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
        dgst=dgst, status=0, sn=attrs['sn'], sub=attrs['subject'],
        email='', cn=attrs.get('cn', ''),
        notbefore=attrs['notbefore'], notafter=attrs['notafter'],
        issuer=issuer, usage='', vtype=0, keyid=attrs['subkeyid'],
        ca=attrs['ca'], alternative='', certfile=crt, key=k)
    c.save()


def import_pem(request):
    if request.method != 'POST':
        form = CertForm()
        return render(request, 'ca/import_pem.html', {'form': form})
    form = CertForm(request.POST, request.FILES)
    if form.is_valid():
        certchain = form.cleaned_data['certchain'].read()
        prikey = form.cleaned_data['prikey'].read()
        prikey, crts = cert.verify(prikey, certchain)
        for crt in crts[:1:-1]:
            imp_crt(None, crt)
        imp_crt(prikey, crts[0])
        dgst = cert.hexdigest(crts[0])
        return HttpResponseRedirect(
            reverse('ca:list_cert', kwargs={'dgst': dgst}))


# build_key, build_key_server, build_inter
# ca, vtype, managed crl
def build_cert(request):
    pass


def build_req(request):
    pass


def sign_req(request, dgst):
    pass


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
