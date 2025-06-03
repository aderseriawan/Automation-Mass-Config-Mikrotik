from django.contrib import admin
from .models import Segmentation

@admin.register(Segmentation)
class SegmentationAdmin(admin.ModelAdmin):
    list_display = ('name', 'segmentation_type')
    search_fields = ('name',)
    list_filter = ('segmentation_type',)
