from django.db import models

class Segmentation(models.Model):
    name = models.CharField(max_length=100)
    segmentation_type = models.CharField(
        max_length=20,
        choices=[
            ('distribution', 'Distribution'),
            ('customer', 'Customer'),
        ],
        default='distribution'
    )
    
    def __str__(self):
        return f"{self.name} ({self.get_segmentation_type_display()})"
    
    class Meta:
        verbose_name = 'Segmentation'
        verbose_name_plural = 'Segmentations'
