from django.contrib import admin

from .models import Athlete, MedicalCertificate

admin.site.register(Athlete)
admin.site.register(MedicalCertificate)
