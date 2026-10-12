from django.db import migrations, models


def normalize_roles(apps, schema_editor):
    UserProfile = apps.get_model("ids", "UserProfile")
    UserProfile.objects.exclude(role="admin").update(role="researcher")


class Migration(migrations.Migration):
    dependencies = [("ids", "0002_predictionrun")]

    operations = [
        migrations.RunPython(normalize_roles, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="userprofile",
            name="role",
            field=models.CharField(
                choices=[("admin", "Administrator"), ("researcher", "Researcher")],
                default="researcher",
                max_length=20,
            ),
        ),
    ]