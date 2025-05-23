# NA_Apps/mikrotik_api_bulk.py
"""
Wrapper RouterOS-api (v0.18 → v0.21+) + auto-logging ke DB.
"""

import routeros_api
import socket
import time
from django.utils            import timezone
from .models                 import Log


# ───────────────────────── CONNECT ─────────────────────────
def open_api(host, port, username, password, timeout=3):
    """
    Membuka koneksi API ke perangkat MikroTik.
    Returns:
        tuple: (api_connection, connection_pool) jika berhasil
        None: jika gagal
    """
    try:
        # Create connection
        connection = routeros_api.RouterOsApiPool(
            host=host,
            port=port,
            username=username,
            password=password,
            plaintext_login=True
        )
        
        # Try to connect with timeout
        connection.get_api()
        
        return connection.get_api(), connection
    except (socket.error, routeros_api.exceptions.RouterOsApiConnectionError) as e:
        Log.objects.create(
            target=host,
            action="Connect API",
            status="Error",
            time=timezone.now(),
            messages=f"Connection failed: {str(e)}"
        )
        return None, None
    except Exception as e:
        Log.objects.create(
            target=host,
            action="Connect API",
            status="Error",
            time=timezone.now(),
            messages=f"Unexpected error: {str(e)}"
        )
        return None, None


# ────────────────────── EXECUTE ONE CLI LINE ───────────────────────
def exec_cli(api, command):
    """
    Mengeksekusi perintah CLI via API.
    Args:
        api: RouterOS API connection
        command: Command to execute (e.g. "/system resource print")
        
    Returns:
        str: Command output
    """
    try:
        # Split command into path and params
        parts = command.strip().split()
        path = "/".join(parts[:-1]) if len(parts) > 1 else parts[0]
        
        # Get API response
        response = api.get_resource(path).get()
        
        # Format response
        if isinstance(response, list):
            # If response is a list of items
            formatted = []
            for item in response:
                if isinstance(item, dict):
                    # Format dictionary items
                    formatted.extend([f"{k}={v}" for k, v in item.items()])
                else:
                    # Add non-dictionary items as is
                    formatted.append(str(item))
            return "\n".join(formatted)
        else:
            # Return response as string
            return str(response)
            
    except Exception as e:
        raise Exception(f"Command execution failed: {str(e)}")


# helper kecil
def _dict_from_tokens(toks):
    return {k: v for k, v in
            (t.split("=", 1) for t in toks if "=" in t)}
