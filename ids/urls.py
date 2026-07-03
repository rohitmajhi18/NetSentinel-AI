from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login/", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    path("logout/", views.logout_view, name="logout"),
    path("api/charts/", views.chart_api, name="chart_api"),
    path("alerts/", views.alerts_view, name="alerts"),
    path("alerts/<int:pk>/resolve/", views.resolve_alert, name="resolve_alert"),
    path("logs/", views.logs_view, name="logs"),
    path("monitor/", views.monitor_view, name="monitor"),
    path("api/capture/", views.capture_traffic, name="capture_traffic"),
    path("api/simulate/", views.simulate_traffic, name="simulate_traffic"),
    path("train/", views.train_view, name="train"),
    path("train/run/", views.train_model_view, name="train_model"),
    path("reports/", views.reports_view, name="reports"),
]
