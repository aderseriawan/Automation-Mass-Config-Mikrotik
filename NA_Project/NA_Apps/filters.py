import django_filters
from django.db.models import Q
from .models import Device, Log
from segmentation.models import Segmentation

class SegmentationFilter(django_filters.FilterSet):
    segmentation__segmentation_type = django_filters.ChoiceFilter(
        choices=[
            ('distribution', 'Distribution'),
            ('customer', 'Customer'),
        ],
        field_name='segmentation__segmentation_type',
        label='Segmentation Type',
        empty_label='All Types'
    )
    
    device_category = django_filters.ChoiceFilter(
        choices=Device.DEVICE_CATEGORY_CHOICES,
        label='Device Category',
        empty_label='All Categories'
    )
    
    class Meta:
        model = Device
        fields = ['segmentation__segmentation_type', 'device_category']
