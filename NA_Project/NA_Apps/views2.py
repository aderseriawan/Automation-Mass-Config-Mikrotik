from django.http import HttpResponse
from django.shortcuts import render, HttpResponse, get_object_or_404, redirect
from .models import Device, Log
import paramiko
import datetime
import time
from django.contrib import messages
from .forms import UploadFileForm
import ipaddress
from .models import Log
import pandas as pd
# Create your views here.

# @login_required
# def halaman_utama(request):
#     return render(request, 'home.html')
def mass_delete_log(request):
    logs = Log.objects.all()
    
    if request.method == "POST":
        selected_logs = request.POST.getlist('log')
        if selected_logs:
            Log.objects.filter(id__in=selected_logs).delete()
            messages.success(request, "Selected logs have been successfully deleted.")
        else:
            messages.error(request, "No logs were selected for deletion.")
    
    context = {
        'logs': logs
    }
    
    return render(request, 'mass_delete_log.html', context)

def log(request):
    # Ambil parameter sorting dari URL (default 'target')
    sort_by = request.GET.get('sort_by', 'target')
    order = request.GET.get('order', 'asc')

    # Ambil semua log
    logs = Log.objects.all()

    # Sorting berdasarkan parameter
    if sort_by == 'target':
        # Sorting berdasarkan IP
        logs = sorted(logs, key=lambda log: ipaddress.ip_address(log.target), reverse=(order == 'desc'))
    elif sort_by == 'status':
        # Sorting berdasarkan status
        logs = sorted(logs, key=lambda log: log.status, reverse=(order == 'desc'))
    elif sort_by == 'time':
        # Sorting berdasarkan waktu
        logs = logs.order_by(f"{'-' if order == 'desc' else ''}time")

    # Siapkan order berikutnya (toggle antara 'asc' dan 'desc')
    next_order = 'desc' if order == 'asc' else 'asc'
    devices = Device.objects.all()   # ← tambahkan ini
    context = {
        'logs': logs,
        'current_sort': sort_by,
        'current_order': order,
        'next_order': next_order,
        'devices': devices,
    }
    return render(request, 'log.html', context)

def verify_config(request):
    if request.method == "POST":
        result = []
        selected_device_id = request.POST.getlist('device')
        mikrotik_command = request.POST['mikrotik_command'].splitlines()
        cisco_command = request.POST['cisco_command'].splitlines()
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=dev.ip_address,port=dev.ssh_port,username=dev.username,password=dev.password)
                
                if dev.vendor.lower() == 'mikrotik':
                    for cmd in mikrotik_command:
                        stdin,stdout,stderr = ssh_client.exec_command(cmd)
                        result.append("Result on {}".format(dev.ip_address))
                        result.append(stdout.read().decode())
                else:
                    conn = ssh_client.invoke_shell()
                    conn.send('terminal length 0\n')
                    for cmd in cisco_command:
                        result.append("Result on {}".format(dev.ip_address))
                        conn.send(cmd + "\n")
                        time.sleep(1)
                        output = conn.recv(65535)
                        result.append(output.decode())
                log = Log(target=dev.ip_address, action="Verify Config", status="Success", time=datetime.datetime.now(), messages="No Error")
                log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Verify Config", status="Error", time=datetime.datetime.now(), messages=e)
                log.save()
                          
                        
        result = '\n'.join(result)
        return render(request, 'verify_result.html', {'result':result})
    else:
        devices = Device.objects.all()
        context = {
            'devices': devices,
            'mode': 'Verify Config'
        }
        return render(request, 'config.html', context)
    

            

def configure(request):
    devices = Device.objects.all()
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        mikrotik_command = request.POST['mikrotik_command'].splitlines()
        cisco_command = request.POST['cisco_command'].splitlines()
        for x in selected_device_id:
            try:
                dev = get_object_or_404(Device, pk=x)
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(hostname=dev.ip_address,port=dev.ssh_port,username=dev.username,password=dev.password)
            
                if dev.vendor.lower() == 'cisco':
                    conn = ssh_client.invoke_shell()
                    conn.send("cont t\n")
                    for cmd in cisco_command:
                        conn.send(cmd + "\n")
                        time.sleep(1)
                else:
                    for cmd in mikrotik_command:
                        ssh_client.exec_command(cmd)
                log = Log(target=dev.ip_address, action="Configure", status="Success", time=datetime.datetime.now(), messages="No Error")
                log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Configure", status="Error", time=datetime.datetime.now(), messages=e)
                log.save()
                          
        return redirect('home')
    else:
        devices = Device.objects.all()
        context = { 
                'devices': devices,
                'mode': 'Configure'
        }
        return render(request, 'config.html', context)

def devices(request):
    all_devices = Device.objects.all()
    context = {
        'all_device': all_devices
    }
    
    return render(request, 'devices.html', context)

def home(request):
    all_device = Device.objects.all()
    cisco_device = Device.objects.filter(vendor="cisco")
    mikrotik_device = Device.objects.filter(vendor="mikrotik")
    last_event = Log.objects.all().order_by('-id')[:10]
    
    context = {
        'all_device': len(all_device),
        'cisco_device': len(cisco_device),
        'mikrotik_device': len(mikrotik_device),
        'last_event': last_event
    }
    return render(request, 'home.html', context)

def mass_add_device(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            # Process the uploaded Excel file
            excel_file = request.FILES['file']
            df = pd.read_excel(excel_file)

            # Iterate over each row in the DataFrame and add devices
            for _, row in df.iterrows():
                try:
                    Device.objects.create(
                        ip_address=row['IP'],
                        hostname=row['Hostname'],
                        username=row['Username'],
                        password=row['Password'],
                        ssh_port=row['SSH Port'],
                        vendor=row['Vendor']
                    )
                    Log.objects.create(
                        target=row['IP'],
                        action='Add Device',
                        status='Success'
                    )
                except Exception as e:
                    Log.objects.create(
                        target=row['IP'],
                        action='Add Device',
                        status='Failed',
                        messages=str(e)
                    )
            return redirect('home')
    else:
        form = UploadFileForm()

    return render(request, 'upload.html', {'form': form})
# def mass_add_device(request):
#     if request.method == 'POST':
#         form = MassAddDeviceForm(request.POST)
#         if form.is_valid():
#             ip_range = form.cleaned_data['ip_range']
#             hostname = form.cleaned_data['hostname']
#             username = form.cleaned_data['username']
#             password = form.cleaned_data['password']
#             ssh_port = form.cleaned_data['ssh_port']
#             vendor = form.cleaned_data['vendor']

#             try:
#                 # Generate all IPs from the provided subnet
#                 network = ipaddress.ip_network(ip_range, strict=False)
#                 devices_added = 0

#                 for ip in network.hosts():  # Skip network and broadcast addresses
#                     Device.objects.create(
#                         ip_address=str(ip),
#                         hostname=hostname,
#                         username=username,
#                         password=password,
#                         ssh_port=ssh_port,
#                         vendor=vendor
#                     )
#                     devices_added += 1

#                 messages.success(request, f"{devices_added} devices successfully added!")
#                 return redirect('mass_add_device')
#             except ValueError as e:
#                 messages.error(request, f"Invalid IP range: {e}")
#         else:
#             messages.error(request, "Invalid form input.")
#     else:
#         form = MassAddDeviceForm()

#     return render(request, 'mass_add_device.html', {'form': form})

def hapus_perangkat(request):
    if request.method == 'POST':
        # Get list of selected devices
        selected_devices = request.POST.getlist('devices')
        
        # Delete the selected devices
        Device.objects.filter(id__in=selected_devices).delete()
        
        return redirect('home')  # Redirect to some device list page after deletion

    # Fetch all devices for display
    devices = Device.objects.all()

    return render(request, 'hapus_perangkat.html', {'devices': devices})


# def hapus_perangkat_view(request):
#     message = ''
#     if request.method == 'POST':
#         subnet = request.POST.get('subnet')
#         if subnet:
#             message = hapus_perangkat_berdasarkan_subnet(subnet)
    
#     return render(request, 'hapus_perangkat.html', {'message': message})