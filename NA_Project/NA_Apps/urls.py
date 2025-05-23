from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),
    path('devices/', views.devices, name='devices'),
    path('devices/edit/', views.edit_devices, name='edit_devices'),
    path('configure/', views.configure, name='configure'),
    path('configure/ssh/', views.configure_ssh, name='configure_ssh'),
    path('verify_config/', views.verify_config, name='verify_config'),
    path('verify_config/ssh/', views.verify_config_ssh, name='verify_config_ssh'),
    path('mass_add_device', views.mass_add_device, name='mass_add_device'),
    path('mass_add_device/template', views.download_template, name='download_template'),
    path('hapus_perangkat/', views.hapus_perangkat, name='hapus_perangkat'),
    path('mass_delete_log', views.mass_delete_log, name='mass_delete_log'),
    path('log/', views.log, name='log'),
    path('device_logs/', views.device_logs, name='device_logs'),
    path('verify_logs/', views.verify_logs, name='verify_logs'),
]
# NA_Apps/urls.py
