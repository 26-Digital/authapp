from django.contrib.auth.models import AbstractUser, UserManager
from django.db import models
from django.conf import settings

class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    permissions = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    roles = models.ManyToManyField(Role, related_name='users')
    objects = UserManager()

    def __str__(self):
        return self.username