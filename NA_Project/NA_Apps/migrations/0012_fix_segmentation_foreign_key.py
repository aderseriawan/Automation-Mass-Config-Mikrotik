from django.db import migrations, models
import django.db.models.deletion

def create_default_segmentation(apps, schema_editor):
    Segmentation = apps.get_model('segmentation', 'Segmentation')
    Device = apps.get_model('NA_Apps', 'Device')
    
    # Create default segmentation if it doesn't exist
    default_seg, created = Segmentation.objects.get_or_create(
        id=1,
        defaults={
            'name': 'Default',
            'segmentation_type': 'distribution'
        }
    )
    
    # Update devices with invalid segmentation_id
    Device.objects.filter(segmentation_id__isnull=False).exclude(
        segmentation_id__in=Segmentation.objects.values_list('id', flat=True)
    ).update(segmentation_id=default_seg.id)

class Migration(migrations.Migration):

    dependencies = [
        ('NA_Apps', '0011_segmentation_alter_device_segmentation'),
    ]

    operations = [
        migrations.RunPython(create_default_segmentation),
    ] 