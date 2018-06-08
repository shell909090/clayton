from django.contrib import admin

from .models import PubKey, Cert
# import cert
# import forms


# class CertAdmin(admin.ModelAdmin):
#     form = forms.ImpCertForm
#     list_display = ('dgst', 'sn', 'sub', 'cn',
#                     'notbefore', 'notafter')
#     list_display_links = None
#     actions = ['disable_cert', 'enable_cert', 'list_tokens',
#                'export_cert', 'export_key', 'export_p12',
#                'backup']
#     list_filter = ['status', ]
#     search_fields = ['domain', ]

#     def save_model(self, request, obj, form, change):
#         obj.certchain = form.cleaned_data['certchain'].read()
#         obj.prikey = form.cleaned_data['prikey'].read()
#         cert.verify(obj.prikey, obj.certchain)
#         attrs = cert.read_cert(obj.certchain)
#         for name in ['sn', 'subject', 'issuer', 'notbefore', 'notafter']:
#             setattr(obj, name, attrs[name])
#         obj.domain = attrs['CN']
#         obj.alternative = ''
#         obj.status = 0
#         super(CertAdmin, self).save_model(request, obj, form, change)

    # def disable_cert(self, request, queryset):
    #     for obj in queryset:
    #         obj.status = 1
    #         obj.save()

    # def enable_cert(self, request, queryset):
    #     for obj in queryset:
    #         obj.status = 0
    #         obj.save()

    # def list_tokens(self, request, queryset):
    #     obj = queryset.get()
    #     return HttpResponse(obj.cid)

    # def export_cert(self, request, queryset):
    #     crt = queryset.get()
    #     resp = HttpResponse(crt.certchain, content_type='plain/text')
    #     resp['Content-Disposition'] = 'attachment; filename=%s.crt' % crt.domain
    #     return resp

    # def export_key(self, request, queryset):
    #     crt = queryset.get()
    #     resp = HttpResponse(cert.encrypt_key(crt.prikey, '123123'),
    #                         content_type='plain/text')
    #     resp['Content-Disposition'] = 'attachment; filename=%s.key' % crt.domain
    #     return resp

    # def export_p12(self, request, queryset):
    #     crt = queryset.get()
    #     resp = HttpResponse(cert.pkcs12(crt.prikey, crt.certchain, '123123'),
    #                         content_type='application/octet-stream')
    #     resp['Content-Disposition'] = 'attachment; filename=%s.p12' % crt.domain
    #     return resp

    # def backup(self, request, queryset):
    #     buf = StringIO.StringIO()
    #     writer = csv.writer(buf)
    #     for crt in queryset.all():
    #         writer.writerow((crt.certchain, crt.prikey))
    #     e = cert.encrypt(zlib.compress(buf.getvalue()), '123123')
    #     resp = HttpResponse(e, content_type='application/octet-stream')
    #     resp['Content-Disposition'] = 'attachment; filename=db.bak'
    #     return resp


admin.site.register(Cert)

admin.site.register(PubKey)
