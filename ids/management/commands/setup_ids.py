from django.core.management.base import BaseCommand

from ids import ml
from ids.models import Alert, ModelMetrics, TrafficLog


class Command(BaseCommand):
    help = "Initialize NetSentinel: train model and seed sample data"

    def handle(self, *args, **options):
        self.stdout.write("Training ML model...")
        metrics = ml.train_model(n_samples=3000)
        ModelMetrics.objects.create(**metrics)
        self.stdout.write(self.style.SUCCESS(f"Model accuracy: {metrics['accuracy']:.1%}"))

        self.stdout.write("Seeding traffic logs and alerts...")
        for _ in range(50):
            features, src_ip, dst_ip = ml.random_traffic_sample()
            prediction, confidence = ml.predict_traffic(features)
            TrafficLog.objects.create(
                source_ip=src_ip,
                dest_ip=dst_ip,
                protocol=features.get("protocol_type", "tcp").upper(),
                duration=features.get("duration", 0),
                src_bytes=int(features.get("src_bytes", 0)),
                dst_bytes=int(features.get("dst_bytes", 0)),
                prediction=prediction,
                confidence=round(confidence * 100, 1),
            )
            if prediction != "normal":
                Alert.objects.create(
                    attack_type=prediction,
                    severity=ml.SEVERITY_MAP.get(prediction, "medium"),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=round(confidence * 100, 1),
                )

        self.stdout.write(self.style.SUCCESS("Setup complete. Run: python manage.py runserver"))
