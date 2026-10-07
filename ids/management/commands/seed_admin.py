import os

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from ids.models import UserProfile


class Command(BaseCommand):
    help = "Create or update the NetSentinel administrator (Django superuser + admin role)"

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin", help="Admin username (default: admin)")
        parser.add_argument(
            "--email",
            default="admin@netsentinel.local",
            help="Admin email (default: admin@netsentinel.local)",
        )
        parser.add_argument(
            "--password",
            default=None,
            help="Admin password (default: NETSENTINEL_ADMIN_PASSWORD env or admin123)",
        )

    def handle(self, *args, **options):
        username = options["username"]
        email = options["email"]
        password = options["password"] or os.environ.get("NETSENTINEL_ADMIN_PASSWORD", "admin123")

        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "is_staff": True,
                "is_superuser": True,
            },
        )
        if not created:
            user.email = email
            user.is_staff = True
            user.is_superuser = True

        user.set_password(password)
        user.save()

        profile, profile_created = UserProfile.objects.get_or_create(
            user=user,
            defaults={"role": "admin"},
        )
        if profile.role != "admin":
            profile.role = "admin"
            profile.save(update_fields=["role"])

        verb = "Created" if created else "Updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"{verb} administrator '{username}' (UserProfile role: admin). "
                "Log in at /admin/ or the app login page."
            )
        )
        if password == "admin123":
            self.stdout.write(
                self.style.WARNING(
                    "Using default password 'admin123'. Set --password or NETSENTINEL_ADMIN_PASSWORD for production."
                )
            )
