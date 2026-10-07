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


class PredictionRun(models.Model):
    CLASS_CHOICES = [
        ("malicious", "Malicious"),
        ("normal", "Normal"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="prediction_runs")
    input_filename = models.CharField(max_length=255)
    total_records = models.PositiveIntegerField(default=0)
    overall_class = models.CharField(max_length=20, choices=CLASS_CHOICES)
    confidence_score = models.FloatField(help_text="Dominant class percentage (0-100)")
    malicious_percent = models.FloatField(default=0.0)
    normal_percent = models.FloatField(default=0.0)
    model_name = models.CharField(max_length=64, default="Random Forest")
    feature_importance = models.JSONField(default=list)
    traffic_summary = models.JSONField(default=dict)
    results = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.input_filename} ({self.overall_class}) @ {self.created_at:%Y-%m-%d}"

    @property
    def is_malicious(self):
        return self.overall_class == "malicious"
