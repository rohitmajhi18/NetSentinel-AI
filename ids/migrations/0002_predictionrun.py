# Generated manually for PredictionRun model

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("ids", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="PredictionRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("input_filename", models.CharField(max_length=255)),
                ("total_records", models.PositiveIntegerField(default=0)),
                (
                    "overall_class",
                    models.CharField(
                        choices=[("malicious", "Malicious"), ("normal", "Normal")],
                        max_length=20,
                    ),
                ),
                ("confidence_score", models.FloatField(help_text="Dominant class percentage (0-100)")),
                ("malicious_percent", models.FloatField(default=0.0)),
                ("normal_percent", models.FloatField(default=0.0)),
                ("model_name", models.CharField(default="Random Forest", max_length=64)),
                ("feature_importance", models.JSONField(default=list)),
                ("traffic_summary", models.JSONField(default=dict)),
                ("results", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="prediction_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
