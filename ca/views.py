from django.shortcuts import render

# Create your views here.


def list_ca(request):
    pass


def build_ca(request):
    pass


def cert_detail(request, dgst):
    pass


def list_cert(request, dgst):
    pass


def import_pem(request):
    pass


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
