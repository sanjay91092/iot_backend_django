from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='user')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'

class Device(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )
    name = models.CharField(max_length=255, unique=True)
    type = models.CharField(max_length=100)
    customerid = models.CharField(max_length=50)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='inactive')
    last_reading = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'devices'

    def __str__(self):
        return f"{self.name} ({self.type}) | Type: {self.last_reading}"
    

class DeviceData(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    data_type = models.CharField(max_length=100)
    customerid = models.CharField(max_length=50)
    value = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'device_data'

    def __str__(self):
        return f"DeviceData: {self.device.name} | Type: {self.data_type} | Value: {self.value} | Timestamp: {self.timestamp}"

