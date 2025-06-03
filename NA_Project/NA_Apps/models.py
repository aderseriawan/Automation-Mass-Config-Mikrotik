# from django.db import models

# # Create your models here.
# class Device(models.Model):
#     ip_address = models.CharField(max_length=20)
#     hostname = models.CharField(max_length=50)
#     username = models.CharField(max_length=20)
#     password = models.CharField(max_length=20)
#     ssh_port = models.IntegerField(default=22)
    
#     VENDOR_CHOICES = (
#         ('mikrotik', 'Mikrotik'),
#         ('cisco', 'Cisco')
#     )
#     vendor = models.CharField(max_length=50, choices=VENDOR_CHOICES)
    
#     def __str__(self):
#         return"{}. {}".format(self.id, self.ip_address)
    
# class Log(models.Model):
#     target = models.CharField(max_length=255)
#     action = models.CharField(max_length=255)
#     status = models.CharField(max_length=255)
#     time = models.DateTimeField(null=True)
#     messages = models.CharField(max_length=255, blank=True)
    
#     def __str__(self):
#         return "{} - {} - {}".format(self.target, self.action, self.status)



from django.db import models
from django.utils import timezone
from segmentation.models import Segmentation


class Device(models.Model):
    DEVICE_CATEGORY_CHOICES = (
        ('router_end_point', 'Router End Point'),
        ('router_failover', 'Router Failover'),
        ('radio_bts', 'Radio BTS'),
        ('radio_station', 'Radio Station'),
        ('router_bridging', 'Router Bridging'),
    )
    
    ip_address = models.GenericIPAddressField(unique=True)
    hostname   = models.CharField(max_length=100, blank=True)
    username   = models.CharField(max_length=50)
    password   = models.CharField(max_length=255)
    api_port   = models.PositiveIntegerField(null=True, blank=True)
    ssh_port   = models.PositiveIntegerField(default=22)
    vendor     = models.CharField(max_length=30, default="mikrotik")
    device_category = models.CharField(max_length=30, choices=DEVICE_CATEGORY_CHOICES, default='router_end_point')
    segmentation = models.ForeignKey(Segmentation, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or '-'})"


class Log(models.Model):
    ACTION_CHOICES = [
        ("Configure",   "Configure"),
        ("Verify",      "Verify"),
        ("Connect API", "Connect API"),
    ]
    STATUS_CHOICES = [
        ("Success", "Success"),
        ("Error",   "Error"),
    ]

    target   = models.CharField(max_length=255)
    action   = models.CharField(max_length=30,  choices=ACTION_CHOICES)
    status   = models.CharField(max_length=10,  choices=STATUS_CHOICES)
    time     = models.DateTimeField(default=timezone.now)
    messages = models.TextField(blank=True)
    command  = models.TextField(blank=True)
    output   = models.TextField(blank=True)

    class Meta:
        ordering = ["-id"]      # log terbaru tampil duluan

    def __str__(self):
        return f"[{self.time:%Y-%m-%d %H:%M:%S}] {self.target} → {self.action} ({self.status})"
