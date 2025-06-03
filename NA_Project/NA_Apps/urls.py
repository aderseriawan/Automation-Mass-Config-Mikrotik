from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('devices/', views.devices, name='devices'),
    path('device/<int:pk>/json/', views.device_json, name='device_json'),
    path('device/<int:pk>/save/', views.device_save, name='device_save'),
    path('device/<int:pk>/delete/', views.device_delete, name='device_delete'),
    path('device/add/', views.device_add, name='device_add'),
    path('devices/bulk-delete/', views.bulk_delete_devices, name='bulk_delete_devices'),
    path('mass_add_device/', views.mass_add_device, name='mass_add_device'),
    path('hapus_perangkat/', views.hapus_perangkat, name='hapus_perangkat'),
    path('edit_devices/', views.edit_devices, name='edit_devices'),
    path('download_template/', views.download_template, name='download_template'),
    path('download_device_template/', views.download_device_template, name='download_device_template'),
    path('configure/', views.configure, name='configure'),
    path('verify_config/', views.verify_config, name='verify_config'),
    path('verify_config_ssh/', views.verify_config_ssh, name='verify_config_ssh'),
    path('configure_ssh/', views.configure_ssh, name='configure_ssh'),
    path('log/', views.log, name='log'),
    path('clear-logs/', views.clear_logs, name='clear_logs'),
    path('export-logs/', views.export_logs, name='export_logs'),
    path('mass_delete_log/', views.mass_delete_log, name='mass_delete_log'),
    path('devices/filter/', views.filter_devices, name='filter_devices'),
]
# NA_Apps/urls.py
