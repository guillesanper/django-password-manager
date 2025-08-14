from django.contrib import admin
from .models import PasswordEntry,MasterKey
# Register your models here.

admin.site.register(PasswordEntry)
admin.site.register(MasterKey)
