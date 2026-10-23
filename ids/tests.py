from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .models import Alert, TrafficLog, UserProfile


class RoleAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_user(username="admin", password="test-password")
        UserProfile.objects.create(user=cls.admin, role="admin")
        cls.user = User.objects.create_user(username="regularuser", password="test-password")
        UserProfile.objects.create(user=cls.user, role="user")

    def test_user_can_access_analysis_and_settings_but_not_admin_pages(self):
        self.client.force_login(self.user)

        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)
        self.assertEqual(self.client.get(reverse("settings")).status_code, 200)
        self.assertEqual(self.client.get(reverse("users")).status_code, 403)

    def test_admin_can_access_role_management(self):
        self.client.force_login(self.admin)

        self.assertEqual(self.client.get(reverse("users")).status_code, 200)
        self.assertEqual(self.client.get(reverse("settings")).status_code, 200)

    def test_admin_can_promote_user(self):
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("users"),
            {"user_id": self.user.pk, "role": "admin"},
        )

        self.assertRedirects(response, reverse("users"))
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.role, "admin")

    def test_last_admin_cannot_be_demoted(self):
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("users"),
            {"user_id": self.admin.pk, "role": "user"},
        )

        self.assertRedirects(response, reverse("users"))
        self.admin.profile.refresh_from_db()
        self.assertEqual(self.admin.profile.role, "admin")

    def test_user_sees_only_owned_alerts_and_logs(self):
        own_alert = Alert.objects.create(attack_type="dos", source_ip="192.0.2.1", user=self.user)
        Alert.objects.create(attack_type="probe", source_ip="192.0.2.2", user=self.admin)
        own_log = TrafficLog.objects.create(source_ip="192.0.2.1", dest_ip="192.0.2.10", user=self.user)
        TrafficLog.objects.create(source_ip="192.0.2.2", dest_ip="192.0.2.20", user=self.admin)
        self.client.force_login(self.user)

        alerts_response = self.client.get(reverse("alerts"))
        logs_response = self.client.get(reverse("logs"))
        chart_response = self.client.get(reverse("chart_api"))

        self.assertContains(alerts_response, str(own_alert.source_ip))
        self.assertNotContains(alerts_response, "192.0.2.2")
        self.assertContains(logs_response, str(own_log.source_ip))
        self.assertNotContains(logs_response, "192.0.2.2")
        self.assertEqual(chart_response.json()["total_logs"], 1)

    def test_admin_sees_global_records(self):
        Alert.objects.create(attack_type="dos", source_ip="192.0.2.1", user=self.user)
        Alert.objects.create(attack_type="probe", source_ip="192.0.2.2", user=self.admin)
        self.client.force_login(self.admin)

        response = self.client.get(reverse("alerts"))

        self.assertContains(response, "192.0.2.1")
        self.assertContains(response, "192.0.2.2")

    def test_user_cannot_trigger_model_training(self):
        self.client.force_login(self.user)

        response = self.client.post(reverse("train_model"))

        self.assertEqual(response.status_code, 403)

    def test_registration_creates_user(self):
        response = self.client.post(
            reverse("register"),
            {"username": "new-user", "password1": "VeryStrongPass!729", "password2": "VeryStrongPass!729"},
        )

        self.assertRedirects(response, reverse("dashboard"))
        user = User.objects.get(username="new-user")
        self.assertEqual(user.profile.role, "user")

    def test_csrf_trusted_origins_configured(self):
        from django.conf import settings
        self.assertIn("https://netsentinal.rohitmajhi.in", settings.CSRF_TRUSTED_ORIGINS)
        self.assertIn("https://*.rohitmajhi.in", settings.CSRF_TRUSTED_ORIGINS)
