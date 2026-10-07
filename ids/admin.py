from django.contrib import admin
from .models import Alert, ModelMetrics, PredictionRun, TrafficLog, UserProfile


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("attack_type", "severity", "source_ip", "confidence", "is_resolved", "created_at")
    list_filter = ("severity", "attack_type", "is_resolved")


@admin.register(TrafficLog)
class TrafficLogAdmin(admin.ModelAdmin):
    list_display = ("source_ip", "dest_ip", "protocol", "prediction", "confidence", "created_at")
    list_filter = ("prediction", "protocol")


@admin.register(ModelMetrics)
class ModelMetricsAdmin(admin.ModelAdmin):
    list_display = ("accuracy", "precision", "recall", "f1_score", "samples_trained", "trained_at")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role")


@admin.register(PredictionRun)
class PredictionRunAdmin(admin.ModelAdmin):
    list_display = (
        "input_filename",
        "user",
        "overall_class",
        "confidence_score",
        "total_records",
        "created_at",
    )
    list_filter = ("overall_class", "created_at")
    search_fields = ("input_filename", "user__username")
