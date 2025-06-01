from django.db import models

class Submission(models.Model):
    TYPE_CHOICES = [
        ('file', 'File'),
        ('url', 'URL'),
    ]

    input_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    value = models.TextField(help_text='File path or URL')
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    vt_result = models.JSONField(blank=True, null=True)
    ip_reputation = models.JSONField(blank=True, null=True)
    whois_info = models.JSONField(blank=True, null=True)
    yara_result = models.TextField(blank=True, null=True)


    def __str__(self):
        return f"{self.input_type.upper()}: {self.value}"
