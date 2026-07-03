from django.db import models
from django.contrib.auth.models import User


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    attack_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="medium")
    source_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField(null=True, blank=True)
    confidence = models.FloatField(default=0.0)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.attack_type} from {self.source_ip}"


class TrafficLog(models.Model):
    source_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10, default="TCP")
    duration = models.FloatField(default=0.0)
    src_bytes = models.IntegerField(default=0)
    dst_bytes = models.IntegerField(default=0)
    prediction = models.CharField(max_length=50, default="normal")
    confidence = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.source_ip} -> {self.dest_ip} [{self.prediction}]"


class ModelMetrics(models.Model):
    accuracy = models.FloatField()
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    samples_trained = models.IntegerField(default=0)
    trained_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-trained_at"]

    def __str__(self):
        return f"Model {self.accuracy:.2%} @ {self.trained_at:%Y-%m-%d}"


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ("admin", "Administrator"),
        ("analyst", "Security Analyst"),
        ("viewer", "Viewer"),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="analyst")

    def __str__(self):
        return f"{self.user.username} ({self.role})"
