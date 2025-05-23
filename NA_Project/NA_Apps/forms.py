from django import forms
from django import forms

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=100, required=False)
    file = forms.FileField()
    
class MassAddDeviceForm(forms.Form):
    ip_range = forms.CharField(label='IP Range (e.g., 192.168.1.1/24)', required=True)
    hostname = forms.CharField(label='Hostname', max_length=50, required=True)
    username = forms.CharField(label='Username', max_length=20, required=True)
    password = forms.CharField(label='Password', max_length=20, required=True, widget=forms.PasswordInput)
    ssh_port = forms.IntegerField(label='SSH Port', initial=22)
    vendor = forms.ChoiceField(choices=[('mikrotik', 'Mikrotik'), ('cisco', 'Cisco')], required=True)
