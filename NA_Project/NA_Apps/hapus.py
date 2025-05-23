import ipaddress
from NA_Apps.models import Device  # Pastikan model 'Device' memiliki field 'ip_address'.

def hapus_perangkat_berdasarkan_subnet(subnet_input):
    """
    Menghapus semua perangkat yang berada dalam rentang subnet yang ditentukan.
    
    :param subnet_input: Sebuah string yang mewakili subnet, misal: '192.168.11.173/24'
    """
    # Memparsing input subnet
    jaringan = ipaddress.ip_network(subnet_input, strict=False)
    
    # Mengonversi jaringan menjadi daftar semua IP dalam rentang tersebut
    ip_awal = jaringan.network_address
    ip_akhir = jaringan.broadcast_address
    
    # Query ke database untuk perangkat dengan IP dalam rentang ini
    perangkat_yang_akan_dihapus = Device.objects.filter(
        ip_address__gte=ip_awal,
        ip_address__lte=ip_akhir
    )
    
    # Melakukan penghapusan massal
    jumlah_dihapus, _ = perangkat_yang_akan_dihapus.delete()
    
    return f"Menghapus {jumlah_dihapus} perangkat di subnet {subnet_input}"

# Contoh penggunaan
# hapus_perangkat_berdasarkan_subnet('192.168.11.173/24')
