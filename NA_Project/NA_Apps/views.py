# NA_Apps/views.py
from __future__ import annotations

from django.shortcuts import render, redirect, get_object_or_404
from django.utils     import timezone
from django.contrib   import messages
from django.db        import transaction
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
import xlsxwriter
from io import BytesIO

from .models          import Device, Log
from .forms           import UploadFileForm
from .mikrotik_api_bulk import open_api, exec_cli

import ipaddress, pandas as pd
import socket
import paramiko
import time


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {username}!')
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
            
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('login')

# Protect all views with login_required
@login_required(login_url='login')
def home(request):
    return render(request, "home.html", {
        "all_device": Device.objects.count(),
        "mikrotik_device": Device.objects.filter(vendor__iexact="mikrotik").count(),
        "logs": Log.objects.all()[:10],
    })


# ╭────────────────────── LOG VIEW & MASS DELETE ───────────────────╮
@login_required(login_url='login')
def mass_delete_log(request):
    log_type = request.GET.get('type', 'config')  # Default to config logs
    
    if request.method == "POST":
        if log_type == 'config':
            # Delete configuration related logs
            Log.objects.filter(action__in=["Configure", "Connect API"]).delete()
            messages.success(request, "Configuration logs deleted successfully.")
            return redirect("log")
        elif log_type == 'verify':
            # Delete verify logs
            Log.objects.filter(action="Verify").delete()
            messages.success(request, "Verify logs deleted successfully.")
            return redirect("verify_logs")
        else:
            # Delete device management logs
            Log.objects.filter(action="Add Device").delete()
            messages.success(request, "Device logs deleted successfully.")
            return redirect("device_logs")

    # Filter logs based on type
    if log_type == 'config':
        logs = Log.objects.filter(action__in=["Configure", "Connect API"])
        title = "Clear Configuration Logs"
        return_url = 'log'
    elif log_type == 'verify':
        logs = Log.objects.filter(action="Verify")
        title = "Clear Verify Logs"
        return_url = 'verify_logs'
    else:
        logs = Log.objects.filter(action="Add Device")
        title = "Clear Device Logs"
        return_url = 'device_logs'

    # Get all devices for hostname lookup
    devices = Device.objects.all()

    return render(request, "mass_delete_log.html", {
        "logs": logs,
        "devices": devices,
        "title": title,
        "return_url": return_url,
        "log_type": log_type
    })


@login_required(login_url='login')
def log(request):
    sort_by = request.GET.get("sort_by", "target")
    order   = request.GET.get("order", "asc")

    # Filter hanya untuk log konfigurasi (Configure dan Connect API)
    qs = Log.objects.filter(action__in=["Configure", "Connect API"])
    
    # Add hostname information to logs
    logs_with_hostname = []
    for log in qs:
        try:
            device = Device.objects.get(ip_address=log.target)
            hostname = device.hostname or '-'
        except Device.DoesNotExist:
            hostname = '-'
        
        log.hostname = hostname  # Tambahkan hostname ke objek log
        logs_with_hostname.append(log)
    
    # Sort logs
    if sort_by == "target":
        logs_with_hostname = sorted(logs_with_hostname, 
                                  key=lambda l: ipaddress.ip_address(l.target),
                                  reverse=(order == "desc"))
    elif sort_by == "hostname":
        logs_with_hostname = sorted(logs_with_hostname,
                                  key=lambda l: l.hostname.lower(),
                                  reverse=(order == "desc"))
    elif sort_by == "status":
        logs_with_hostname = sorted(logs_with_hostname,
                                  key=lambda l: l.status,
                                  reverse=(order == "desc"))
    elif sort_by == "time":
        if order == "desc":
            logs_with_hostname = sorted(logs_with_hostname,
                                      key=lambda l: l.time,
                                      reverse=True)
        else:
            logs_with_hostname = sorted(logs_with_hostname,
                                      key=lambda l: l.time)

    # Handle export to Excel
    if request.GET.get('export') == 'excel':
        return export_logs_to_excel(logs_with_hostname, "Configuration_Logs")

    return render(request, "log.html", {
        "logs": logs_with_hostname,
        "devices": Device.objects.all(),
        "current_sort": sort_by,
        "current_order": order,
        "next_order": "desc" if order == "asc" else "asc",
        "log_type": "Configuration Logs"
    })

@login_required(login_url='login')
def verify_logs(request):
    sort_by = request.GET.get("sort_by", "target")
    order   = request.GET.get("order", "asc")

    # Filter only verify logs
    qs = Log.objects.filter(action="Verify")
    
    # Add hostname information to logs
    logs_with_hostname = []
    for log in qs:
        try:
            device = Device.objects.get(ip_address=log.target)
            hostname = device.hostname or '-'
        except Device.DoesNotExist:
            hostname = '-'
        
        log.hostname = hostname
        logs_with_hostname.append(log)
    
    # Sort logs
    if sort_by == "target":
        logs_with_hostname = sorted(logs_with_hostname, 
                                  key=lambda l: ipaddress.ip_address(l.target),
                                  reverse=(order == "desc"))
    elif sort_by == "hostname":
        logs_with_hostname = sorted(logs_with_hostname,
                                  key=lambda l: l.hostname.lower(),
                                  reverse=(order == "desc"))
    elif sort_by == "status":
        logs_with_hostname = sorted(logs_with_hostname,
                                  key=lambda l: l.status,
                                  reverse=(order == "desc"))
    elif sort_by == "time":
        logs_with_hostname = sorted(logs_with_hostname,
                                  key=lambda l: l.time,
                                  reverse=(order == "desc"))

    # Handle export to Excel
    if request.GET.get('export') == 'excel':
        return export_logs_to_excel(logs_with_hostname, "Verify_Logs")

    return render(request, "log.html", {
        "logs": logs_with_hostname,
        "devices": Device.objects.all(),
        "current_sort": sort_by,
        "current_order": order,
        "next_order": "desc" if order == "asc" else "asc",
        "log_type": "Verify Logs"
    })

@login_required(login_url='login')
def device_logs(request):
    sort_by = request.GET.get("sort_by", "target")
    order   = request.GET.get("order", "asc")

    # Filter hanya untuk log device management
    qs = Log.objects.filter(action="Add Device")
    
    if sort_by == "target":
        qs = sorted(qs, key=lambda l: ipaddress.ip_address(l.target),
                    reverse=(order == "desc"))
    elif sort_by == "status":
        qs = sorted(qs, key=lambda l: l.status,
                    reverse=(order == "desc"))
    elif sort_by == "time":
        qs = qs.order_by(f"{'-' if order=='desc' else ''}time")

    return render(request, "log.html", {
        "logs": qs,
        "devices": Device.objects.all(),
        "current_sort": sort_by,
        "current_order": order,
        "next_order": "desc" if order == "asc" else "asc",
        "log_type": "Device Management Logs"
    })
# ╰──────────────────────────────────────────────────────────────────╯


# ╭────────────────── MASS-CONFIG (WRITE) VIA API ───────────────────╮
@login_required(login_url='login')
def configure(request):
    if request.method != "POST":
        return render(request, "config.html", {
            "devices": Device.objects.all(),
            "mode": "Configure",
        })

    cmds = [ln.strip() for ln in
            request.POST.get("mikrotik_command", "").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]

    for dev_id in request.POST.getlist("device"):
        dev = get_object_or_404(Device, pk=dev_id)

        if dev.vendor.lower() != "mikrotik":
            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Error",
                time=timezone.now(),
                messages="Unsupported vendor for API",
                command="\n".join(cmds)
            )
            continue

        api, pool = open_api(dev.ip_address,
                            dev.api_port or 8728,
                            dev.username,
                            dev.password)
        if api is None:
            continue

        try:
            for raw in cmds:
                exec_cli(api, raw)

            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Success",
                time=timezone.now(),
                messages=f"Configuration applied successfully via port {dev.api_port or 8728}",
                command="\n".join(cmds)
            )
        except Exception as e:
            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Error",
                time=timezone.now(),
                messages=str(e),
                command="\n".join(cmds)
            )
        finally:
            try:
                pool.disconnect()
            except:
                pass

    return redirect('log')
# ╰──────────────────────────────────────────────────────────────────╯


# ╭────────────────── VERIFY (READ-ONLY) VIA API ────────────────────╮
@login_required(login_url='login')
def verify_config(request):
    if request.method != "POST":
        return render(request, "config.html", {
            "devices": Device.objects.all(),
            "mode": "Verify",
        })

    cmds = [ln.strip() for ln in
            request.POST.get("mikrotik_command", "").splitlines()
            if ln.strip()]

    results = []

    for dev_id in request.POST.getlist("device"):
        dev = get_object_or_404(Device, pk=dev_id)

        if dev.vendor.lower() != "mikrotik":
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Error",
                time=timezone.now(),
                messages="Unsupported vendor (only MikroTik)",
                command="\n".join(cmds)
            )
            continue

        api, pool = open_api(dev.ip_address,
                            dev.api_port or 8728,
                            dev.username,
                            dev.password)
        if api is None:
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Error",
                time=timezone.now(),
                messages=f"Failed to connect to device via API (Port: {dev.api_port or 8728})",
                command="\n".join(cmds)
            )
            continue

        try:
            device_output = []
            for raw in cmds:
                try:
                    # Execute command and get output
                    output = exec_cli(api, raw)
                    
                    # Format the output for display
                    formatted_output = f"\n[{dev.ip_address}:{dev.api_port or 8728}] Command: {raw}\n"
                    formatted_output += "-" * 60 + "\n"
                    
                    if isinstance(output, list):
                        formatted_output += "\n".join(str(item) for item in output)
                    else:
                        formatted_output += str(output)
                    
                    formatted_output += "\n" + "-" * 60 + "\n"
                    device_output.append(formatted_output)

                    # Create success log with command output
                    Log.objects.create(
                        target=dev.ip_address,
                        action="Verify",
                        status="Success",
                        time=timezone.now(),
                        messages=f"Command executed successfully",
                        command=raw,
                        output=str(output)
                    )
                except Exception as cmd_error:
                    error_msg = f"Error executing '{raw}': {str(cmd_error)}"
                    device_output.append(f"\n[{dev.ip_address}:{dev.api_port or 8728}] {error_msg}\n")
                    
                    # Create error log for failed command
                    Log.objects.create(
                        target=dev.ip_address,
                        action="Verify",
                        status="Error",
                        time=timezone.now(),
                        messages=error_msg,
                        command=raw
                    )

            # Join all outputs for this device
            results.extend(device_output)

        except Exception as e:
            error_msg = f"Connection Error: {str(e)}"
            results.append(f"\n[{dev.ip_address}:{dev.api_port or 8728}] {error_msg}\n")
            
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Error",
                time=timezone.now(),
                messages=error_msg,
                command="\n".join(cmds)
            )
        finally:
            try:
                pool.disconnect()
            except:
                pass

    return redirect('verify_logs')

@login_required(login_url='login')
def verify_config_ssh(request):
    if request.method != "POST":
        return render(request, "config.html", {
            "devices": Device.objects.all(),
            "mode": "Verify",
        })

    cmds = request.POST['mikrotik_command'].splitlines()

    for dev_id in request.POST.getlist('device'):
        dev = get_object_or_404(Device, pk=dev_id)

        sock = _open_ssh_socket(dev.ip_address, dev.ssh_port or 22,
                              timeout=5, retries=2, delay=2)
        if not sock:
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Error",
                time=timezone.now(),
                messages=f"Connection failed: {dev.ip_address}:{dev.ssh_port or 22}",
                command="\n".join(cmds)
            )
            continue

        try:
            transport = paramiko.Transport(sock)
            sec = transport.get_security_options()
            sec.digests = ['hmac-sha1', 'hmac-md5']

            transport.start_client()
            transport.auth_password(dev.username, dev.password)

            ssh = paramiko.SSHClient()
            ssh._transport = transport

            output = []
            for cmd in cmds:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output.extend([
                    f"\nCommand: {cmd}",
                    stdout.read().decode(),
                    stderr.read().decode()
                ])

            output_text = "\n".join(output)
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Success",
                time=timezone.now(),
                messages="Commands executed successfully",
                command="\n".join(cmds),
                output=output_text
            )
        except Exception as e:
            Log.objects.create(
                target=dev.ip_address,
                action="Verify",
                status="Error",
                time=timezone.now(),
                messages=str(e),
                command="\n".join(cmds)
            )
        finally:
            try: transport.close()
            except: pass
            try: sock.close()
            except: pass

    return redirect('verify_logs')

@login_required(login_url='login')
def configure_ssh(request):
    if request.method != "POST":
        return render(request, "config.html", {
            "devices": Device.objects.all(),
            "mode": "Configure",
        })

    cmds = request.POST['mikrotik_command'].splitlines()

    for dev_id in request.POST.getlist('device'):
        dev = get_object_or_404(Device, pk=dev_id)

        sock = _open_ssh_socket(dev.ip_address, dev.ssh_port or 22,
                              timeout=5, retries=2, delay=2)
        if not sock:
            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Error",
                time=timezone.now(),
                messages=f"Connection failed: {dev.ip_address}:{dev.ssh_port or 22}",
                command="\n".join(cmds)
            )
            continue

        try:
            transport = paramiko.Transport(sock)
            sec = transport.get_security_options()
            sec.digests = ['hmac-sha1', 'hmac-md5']

            transport.start_client()
            transport.auth_password(dev.username, dev.password)

            ssh = paramiko.SSHClient()
            ssh._transport = transport

            output = []
            for cmd in cmds:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output.extend([stdout.read().decode(), stderr.read().decode()])

            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Success",
                time=timezone.now(),
                messages="Configuration applied successfully",
                command="\n".join(cmds)
            )
        except Exception as e:
            Log.objects.create(
                target=dev.ip_address,
                action="Configure",
                status="Error",
                time=timezone.now(),
                messages=str(e),
                command="\n".join(cmds)
            )
        finally:
            try: transport.close()
            except: pass
            try: sock.close()
            except: pass

    return redirect('log')

# ╭──────────────────────── HOME & DEVICE CRUD ──────────────────────╮
@login_required(login_url='login')
def devices(request):
    try:
        # Get all devices but don't access them yet
        devices = Device.objects.all()
        
        # Create context with devices
        context = {"all_device": devices}
        
        # Log instead of print for better production reliability
        # Django will handle this properly even if stdout is unavailable
        import logging
        logger = logging.getLogger('django')
        logger.debug(f"Found {devices.count()} devices")
        
        # Render the template with our devices context
        return render(request, "devices.html", context)
    except Exception as e:
        # Log the error instead of print
        import logging
        logger = logging.getLogger('django')
        logger.error(f"Error in devices view: {str(e)}")
        
        # Provide a more graceful error handling
        context = {
            "all_device": [],
            "error_message": "There was a problem loading the devices. Please try again later."
        }
        return render(request, "devices.html", context)


def mass_add_device(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            df = pd.read_excel(request.FILES["file"])

            with transaction.atomic():
                for _, row in df.iterrows():
                    try:
                        # Debug print untuk melihat data yang akan dimasukkan
                        print(f"Processing row: IP={row['IP']}, Password={row['Password']}")
                        
                        # Pastikan password adalah string
                        password = str(row['Password']).strip()
                        
                        Device.objects.update_or_create(
                            ip_address=row["IP"],
                            defaults={
                                'hostname': row["Hostname"],
                                'username': row["Username"],
                                'password': password,
                                'vendor': row["Vendor"],
                                'ssh_port': row.get("SSH Port", 22),
                                'api_port': row.get("API Port", 8728),
                            }
                        )
                        Log.objects.create(
                            target=row["IP"],
                            action="Add Device",
                            status="Success",
                            time=timezone.now(),
                            messages="Device added successfully"
                        )
                    except Exception as e:
                        print(f"Error adding device {row.get('IP', 'unknown')}: {str(e)}")
                        Log.objects.create(
                            target=row.get("IP", "unknown"),
                            action="Add Device",
                            status="Failed",
                            time=timezone.now(),
                            messages=str(e)
                        )
            return redirect("device_logs")
    else:
        form = UploadFileForm()

    return render(request, "upload.html", {"form": form})


def hapus_perangkat(request):
    if request.method == "POST":
        Device.objects.filter(id__in=request.POST.getlist("devices")).delete()
        return redirect("home")

    return render(request, "hapus_perangkat.html",
                  {"devices": Device.objects.all()})

@login_required(login_url='login')
def edit_devices(request):
    if request.method == "POST":
        device_ids = request.POST.getlist('devices')
        hostname = request.POST.get('hostname')
        username = request.POST.get('username')
        password = request.POST.get('password')
        ssh_port = request.POST.get('ssh_port')
        api_port = request.POST.get('api_port')
        
        # Update only the fields that were filled
        update_fields = {}
        if hostname: update_fields['hostname'] = hostname
        if username: update_fields['username'] = username
        if password: update_fields['password'] = password
        if ssh_port: 
            update_fields['ssh_port'] = int(ssh_port)  # Convert to integer
        if api_port: 
            update_fields['api_port'] = int(api_port)  # Convert to integer
        
        if update_fields:
            updated = Device.objects.filter(id__in=device_ids).update(**update_fields)
            messages.success(request, f"Successfully updated {len(device_ids)} device(s)")
        else:
            messages.warning(request, "No fields were selected for update")
        
        return redirect('devices')
        
    return redirect('devices')

def _open_ssh_socket(host, port, timeout=5, retries=2, delay=2):
    """
    Buka koneksi TCP ke host:port dengan retry dan timeout.
    Kembalikan socket jika berhasil, atau None jika gagal.
    """
    for attempt in range(1, retries + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock
        except socket.timeout:
            print(f"[Attempt {attempt}] Timeout {timeout}s ke {host}:{port}")
        except socket.error as e:
            if getattr(e, 'errno', None) == 10060:
                print(f"[Attempt {attempt}] WinError10060: {host}:{port} tidak terjawab")
            else:
                print(f"[Attempt {attempt}] Socket error: {e}")
        time.sleep(delay)
    return None

def download_template(request):
    # Create an in-memory output file
    output = BytesIO()
    
    # Create a new workbook and add a worksheet
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()
    
    # Add some formats
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#0d6efd',
        'font_color': 'white',
        'border': 1
    })
    
    required_format = workbook.add_format({
        'bg_color': '#ffebee',
        'border': 1
    })
    
    optional_format = workbook.add_format({
        'bg_color': '#f5f5f5',
        'border': 1
    })
    
    # Define headers
    headers = ['IP', 'Hostname', 'Username', 'Password', 'Vendor', 'SSH Port', 'API Port']
    
    # Write headers
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, header_format)
    
    # Add example data
    example_data = [
        ['192.168.1.1', 'Router-Core', 'admin', 'password123', 'Mikrotik', 22, 8728],
        ['192.168.1.2', 'Switch-Access', 'admin', 'password123', 'Cisco', 22, '']
    ]
    
    # Write example data
    for row, data in enumerate(example_data, start=1):
        for col, value in enumerate(data):
            format = required_format if col < 5 else optional_format
            worksheet.write(row, col, value, format)
    
    # Set column widths
    worksheet.set_column('A:A', 15)  # IP
    worksheet.set_column('B:B', 30)  # Hostname
    worksheet.set_column('C:C', 15)  # Username
    worksheet.set_column('D:D', 15)  # Password
    worksheet.set_column('E:E', 15)  # Vendor
    worksheet.set_column('F:G', 10)  # Ports
    
    # Add data validation for Vendor column
    worksheet.data_validation('E2:E1048576', {
        'validate': 'list',
        'source': ['Mikrotik', 'Cisco'],
        'error_message': 'Please select either Mikrotik or Cisco'
    })
    
    # Add data validation for port numbers
    port_validation = {
        'validate': 'integer',
        'criteria': 'between',
        'minimum': 1,
        'maximum': 65535,
        'error_message': 'Port must be between 1 and 65535'
    }
    worksheet.data_validation('F2:F1048576', port_validation)
    worksheet.data_validation('G2:G1048576', port_validation)
    
    workbook.close()
    
    # Seek to start of file
    output.seek(0)
    
    # Create the HttpResponse object with Excel mime type
    response = HttpResponse(output.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=device_template.xlsx'
    
    return response

def export_logs_to_excel(logs, filename):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Add formats
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#0d6efd',
        'font_color': 'white',
        'border': 1
    })

    # Define headers
    headers = ['Target', 'Hostname', 'Action', 'Status', 'Time', 'Messages', 'Command']
    
    # Write headers
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, header_format)

    # Write data
    for row, log in enumerate(logs, start=1):
        worksheet.write(row, 0, log.target)
        worksheet.write(row, 1, getattr(log, 'hostname', '-'))
        worksheet.write(row, 2, log.action)
        worksheet.write(row, 3, log.status)
        worksheet.write(row, 4, timezone.localtime(log.time).strftime('%Y-%m-%d %H:%M:%S'))
        worksheet.write(row, 5, log.messages)
        worksheet.write(row, 6, log.command if log.command else '')

    # Set column widths
    worksheet.set_column('A:A', 15)  # Target
    worksheet.set_column('B:B', 30)  # Hostname
    worksheet.set_column('C:C', 15)  # Action
    worksheet.set_column('D:D', 10)  # Status
    worksheet.set_column('E:E', 20)  # Time
    worksheet.set_column('F:F', 40)  # Messages
    worksheet.set_column('G:G', 40)  # Command

    workbook.close()
    output.seek(0)

    response = HttpResponse(
        output.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename={filename}_{timezone.localtime().strftime("%Y%m%d_%H%M%S")}.xlsx'
    return response
