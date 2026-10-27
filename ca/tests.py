from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from django.test import TestCase
from django.urls import reverse

from . import crypt
from .models import Cert, PubKey


class CertificateWorkflowTests(TestCase):
    def test_issue_and_export_chain(self):
        response = self.client.post(reverse('ca:build_rsa'), {'size': 2048})
        self.assertEqual(response.status_code, 302)
        key = PubKey.objects.get()
        response = self.client.post(reverse('ca:build_req', args=[key.pk]), {
            'cn': 'Test Root CA', 'ca': True, 'selfsign': True,
        })
        self.assertEqual(response.status_code, 302)
        root = Cert.objects.get()
        response = self.client.post(reverse('ca:build_cert', args=[root.pk]), {
            'cn': 'localhost', 'alternative': 'localhost', 'usage': 'serverAuth',
        })
        self.assertEqual(response.status_code, 302)
        leaf = Cert.objects.exclude(pk=root.pk).get()
        root_cert = crypt.load_certificate(root.dat)
        leaf_cert = crypt.load_certificate(leaf.dat)
        leaf_cert.verify_directly_issued_by(root_cert)
        self.assertTrue(root_cert.extensions.get_extension_for_class(
            x509.BasicConstraints).critical)
        self.assertEqual(leaf.issuer, root)
        self.assertEqual(leaf.authkeyid, root.keyid)
        self.assertEqual(leaf_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),
            ['localhost'])
        for name in ['detail_cert', 'export_pem', 'export_der', 'export_chain']:
            self.assertEqual(self.client.get(reverse('ca:' + name, args=[leaf.pk])).status_code, 200)
        response = self.client.get(reverse('ca:export_pkcs12', args=[leaf.pk]))
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            response.content, None)
        self.assertEqual(crypt.get_keyid(private_key), leaf.key_id)
        self.assertEqual(certificate, leaf_cert)
        self.assertEqual(chain, [root_cert])

    def test_ec_and_requested_validity(self):
        key = crypt.generate_ec('secp256r1')
        csr = crypt.generate_req(key, {'cn': 'EC Root', 'ca': True})
        root = crypt.selfsign_req(csr, key, days=30)
        root.verify_directly_issued_by(root)
        self.assertEqual(root.not_valid_after_utc - root.not_valid_before_utc,
                         timedelta(days=30))
        leaf_key = crypt.generate_rsa()
        leaf_csr = crypt.generate_req(leaf_key, {'cn': 'localhost'})
        leaf = crypt.sign_req(leaf_csr, root, key, days=7)
        leaf.verify_directly_issued_by(root)
        self.assertEqual(leaf.not_valid_after_utc - leaf.not_valid_before_utc,
                         timedelta(days=7))

    def test_invalid_validity_is_rejected_by_form(self):
        from .forms import SignConfirmForm
        for days in ['-1', '0', 'abc']:
            self.assertFalse(SignConfirmForm({'csr': 'request', 'days': days}).is_valid())
