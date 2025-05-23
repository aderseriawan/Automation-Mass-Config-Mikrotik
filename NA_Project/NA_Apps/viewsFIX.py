# NA_Apps/views.py

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import Device, Log
import socket
import paramiko
from django.utils import timezone
import time
from django.contrib import messages
from .forms import UploadFileForm
import ipaddress
import pandas as pd

def mass_delete_log(request):
    logs = Log.objects.all()
    if request.method == "POST":
        selected_logs = request.POST.getlist('log')
        if selected_logs:
            Log.objects.filter(id__in=selected_logs).delete()
            messages.success(request, "Selected logs have been successfully deleted.")
        else:
            messages.error(request, "No logs were selected for deletion.")
    return render(request, 'mass_delete_log.html', {'logs': logs})


def log(request):
    sort_by    = request.GET.get('sort_by', 'target')
    order      = request.GET.get('order', 'asc')
    logs       = Log.objects.all()

    if sort_by == 'target':
        logs = sorted(logs,
                      key=lambda l: ipaddress.ip_address(l.target),
                      reverse=(order=='desc'))
    elif sort_by == 'status':
        logs = sorted(logs,
                      key=lambda l: l.status,
                      reverse=(order=='desc'))
    elif sort_by == 'time':
        logs = logs.order_by(f"{'-' if order=='desc' else ''}time")

    next_order = 'desc' if order=='asc' else 'asc'
    devices    = Device.objects.all()

    context = {
        'logs': logs,
        'devices': devices,
        'current_sort': sort_by,
        'current_order': order,
        'next_order': next_order,
    }
    return render(request, 'log.html', context)


def verify_config(request):
    if request.method != "POST":
        devices = Device.objects.all()
        return render(request, 'config.html', {
            'devices': devices,
            'mode': 'Verify Config'
        })

    result        = []
    cmds_mikrotik = request.POST['mikrotik_command'].splitlines()
    cmds_cisco    = request.POST['cisco_command'].splitlines()

    for dev_id in request.POST.getlist('device'):
        dev = get_object_or_404(Device, pk=dev_id)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((dev.ip_address, dev.ssh_port))

            transport = paramiko.Transport(sock)
            sec = transport.get_security_options()
            sec.digests = ['hmac-sha1', 'hmac-md5']        # match server offer

            transport.start_client()
            transport.auth_password(dev.username, dev.password)

            ssh = paramiko.SSHClient()
            ssh._transport = transport

            if dev.vendor.lower() == 'mikrotik':
                for cmd in cmds_mikrotik:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    result.append(f"Result on {dev.ip_address}")
                    result.append(stdout.read().decode())
            else:
                shell = transport.open_session()
                shell.get_pty()
                shell.invoke_shell()
                shell.send('terminal length 0\n')
                for cmd in cmds_cisco:
                    result.append(f"Result on {dev.ip_address}")
                    shell.send(cmd + "\n")
                    time.sleep(1)
                    result.append(shell.recv(65535).decode())

            Log.objects.create(
                target=dev.ip_address,
                action="Verify Config",
                status="Success",
                time=timezone.now(),
                messages="No Error"
            )
        except Exception as e:
            Log.objects.create(
                target=dev.ip_address,
                action="Verify Config",
                status="Error",
                time=timezone.now(),
                messages=str(e)
            )
        finally:
            try: transport.close()
            except: pass
            try: sock.close()
            except: pass

    return render(request, 'verify_result.html', {
        'result': '\n'.join(result)
    })


def configure(request):
    if request.method != "POST":
        devices = Device.objects.all()
        return render(request, 'config.html', {
            'devices': devices,
            'mode': 'Configure'
        })

    cmds_mikrotik = request.POST['mikrotik_command'].splitlines()
    cmds_cisco    = request.POST['cisco_command'].splitlines()

    for dev_id in request.POST.getlist('device'):
        dev = get_object_or_404(Device, pk=dev_id)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((dev.ip_address, dev.ssh_port))

            transport = paramiko.Transport(sock)
            sec = transport.get_security_options()
            sec.digests = ['hmac-sha1', 'hmac-md5']

            transport.start_client()
            transport.auth_password(dev.username, dev.password)

            ssh = paramiko.SSHClient()
            ssh._transport = transport

            if dev.vendor.lower() == 'cisco':
                shell = transport.open_session()
                shell.get_pty()
                shell.invoke_shell()
                shell.send("terminal length 0\n")
                for cmd in cmds_cisco:
                    shell.send(cmd + "\n")
                    time.sleep(1)
            else:
                for cmd in cmds_mikrotik:
                    ssh.exec_command(cmd)

            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Success",
                time=timezone.now(),
                messages="No Error"
            )
        except Exception as e:
            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Error",
                time=timezone.now(),
                messages=str(e)
            )
        finally:
            try: transport.close()
            except: pass
            try: sock.close()
            except: pass

    return redirect('home')


def devices(request):
    all_devices = Device.objects.all()
    return render(request, 'devices.html', {'all_device': all_devices})


def home(request):
    all_dev      = Device.objects.all()
    cisco_dev    = Device.objects.filter(vendor="cisco")
    mikrotik_dev = Device.objects.filter(vendor="mikrotik")
    last_event   = Log.objects.order_by('-id')[:10]
    return render(request, 'home.html', {
        'all_device': len(all_dev),
        'cisco_device': len(cisco_dev),
        'mikrotik_device': len(mikrotik_dev),
        'last_event': last_event
    })


def mass_add_device(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            df = pd.read_excel(request.FILES['file'])
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
                        status='Success',
                        time=timezone.now()
                    )
                except Exception as e:
                    Log.objects.create(
                        target=row['IP'],
                        action='Add Device',
                        status='Failed',
                        time=timezone.now(),
                        messages=str(e)
                    )
            return redirect('home')
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})


def hapus_perangkat(request):
    if request.method == 'POST':
        Device.objects.filter(id__in=request.POST.getlist('devices')).delete()
        return redirect('home')
    devices = Device.objects.all()
    return render(request, 'hapus_perangkat.html', {'devices': devices})
