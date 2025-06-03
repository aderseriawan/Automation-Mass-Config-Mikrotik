from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),
    # Device routes
    path('devices/', views.devices, name='devices'),
    path('device/<int:pk>/json/', views.device_json, name='device_json'),
    path('device/<int:pk>/save/', views.device_save, name='device_save'),
    path('device/<int:pk>/delete/', views.device_delete, name='device_delete'),
    path('device/add/', views.device_add, name='device_add'),
    path('devices/bulk-delete/', views.bulk_delete_devices, name='bulk_delete_devices'),
    # Legacy device routes (kept for backwards compatibility)
    path('devices/edit/', views.edit_devices, name='edit_devices'),
    path('hapus_perangkat/', views.hapus_perangkat, name='hapus_perangkat'),
    path('mass_add_device/', views.mass_add_device, name='mass_add_device'),
    path('mass_add_device/template/', views.download_template, name='download_template'),
    # Config routes
    path('configure/', views.configure, name='configure'),
    path('configure/ssh/', views.configure_ssh, name='configure_ssh'),
    path('verify_config/', views.verify_config, name='verify_config'),
    path('verify_config/ssh/', views.verify_config_ssh, name='verify_config_ssh'),
    # Logs routes
    path('logs/', views.logs, name='logs'),  # New unified logs view
    path('logs/clear/', views.clear_logs, name='clear_logs'),
    # Legacy log routes (kept for backwards compatibility)
    path('log/', views.log, name='log'),
    path('mass_delete_log/', views.mass_delete_log, name='mass_delete_log'),
    path('device_logs/', views.device_logs, name='device_logs'),
    path('verify_logs/', views.log, name='verify_logs'),  # Redirect verify_logs to log
]
# NA_Apps/urls.py
