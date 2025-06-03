import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'NA_Project.settings')
django.setup()

from NA_Apps.models import Device
from segmentation.models import Segmentation

def fix_segmentation_data():
    # Create default segmentation if it doesn't exist
    default_seg, created = Segmentation.objects.get_or_create(
        id=1,
        defaults={
            'name': 'Default',
            'segmentation_type': 'distribution'
        }
    )
    
    # Get all devices with invalid segmentation_id
    devices = Device.objects.filter(segmentation_id__isnull=False).exclude(
        segmentation_id__in=Segmentation.objects.values_list('id', flat=True)
    )
    
    # Update devices with invalid segmentation_id
    for device in devices:
        print(f"Fixing device {device.id} ({device.ip_address})")
        device.segmentation = default_seg
        device.save()
    
    print("Data fix completed!")

if __name__ == '__main__':
    fix_segmentation_data() 