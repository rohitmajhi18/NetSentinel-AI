import json
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import capture, ml
from .models import Alert, ModelMetrics, TrafficLog, UserProfile


def _chart_data():
    now = timezone.now()
    since = now - timedelta(hours=24)

    attack_counts = (
        Alert.objects.filter(created_at__gte=since)
        .values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    attack_labels = [a["attack_type"].upper() for a in attack_counts] or ["No Data"]
    attack_values = [a["count"] for a in attack_counts] or [0]

    hours = []
    normal_counts = []
    threat_counts = []
    for i in range(23, -1, -1):
        h_start = now - timedelta(hours=i + 1)
        h_end = now - timedelta(hours=i)
        logs = TrafficLog.objects.filter(created_at__gte=h_start, created_at__lt=h_end)
        hours.append(h_start.strftime("%H:00"))
        normal_counts.append(logs.filter(prediction="normal").count())
        threat_counts.append(logs.exclude(prediction="normal").count())

    severity_counts = (
        Alert.objects.filter(created_at__gte=since)
        .values("severity")
        .annotate(count=Count("id"))
    )
    sev_map = {s["severity"]: s["count"] for s in severity_counts}
    severity_labels = ["low", "medium", "high", "critical"]
    severity_values = [sev_map.get(s, 0) for s in severity_labels]

    traffic_by_protocol = (
        TrafficLog.objects.filter(created_at__gte=since)
        .values("protocol")
        .annotate(count=Count("id"))
    )
    proto_labels = [p["protocol"] for p in traffic_by_protocol] or ["TCP"]
    proto_values = [p["count"] for p in traffic_by_protocol] or [0]

    latest_metrics = ModelMetrics.objects.first()

    return {
        "attack_labels": attack_labels,
        "attack_values": attack_values,
        "hour_labels": hours,
        "normal_counts": normal_counts,
        "threat_counts": threat_counts,
        "severity_labels": [s.capitalize() for s in severity_labels],
        "severity_values": severity_values,
        "proto_labels": proto_labels,
        "proto_values": proto_values,
        "total_alerts": Alert.objects.filter(is_resolved=False).count(),
        "total_logs": TrafficLog.objects.count(),
        "threats_today": Alert.objects.filter(created_at__gte=since).count(),
        "model_accuracy": round(latest_metrics.accuracy * 100, 1) if latest_metrics else 0,
    }


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        login(request, form.get_user())
        return redirect("dashboard")
    return render(request, "ids/login.html", {"form": form})


def register_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    form = UserCreationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        UserProfile.objects.create(user=user, role="analyst")
        login(request, user)
        messages.success(request, "Account created. Welcome to NetSentinel AI.")
        return redirect("dashboard")
    return render(request, "ids/register.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("login")


@login_required
def dashboard(request):
    data = _chart_data()
    recent_alerts = Alert.objects.all()[:8]
    recent_logs = TrafficLog.objects.all()[:8]
    return render(
        request,
        "ids/dashboard.html",
        {"charts": json.dumps(data), "recent_alerts": recent_alerts, "recent_logs": recent_logs, **data},
    )


@login_required
def chart_api(request):
    return JsonResponse(_chart_data())


@login_required
def alerts_view(request):
    alerts = Alert.objects.all()
    severity = request.GET.get("severity")
    if severity:
        alerts = alerts.filter(severity=severity)
    return render(request, "ids/alerts.html", {"alerts": alerts})


@login_required
@require_POST
def resolve_alert(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    alert.is_resolved = True
    alert.save()
    messages.success(request, f"Alert #{pk} marked as resolved.")
    return redirect("alerts")


@login_required
def logs_view(request):
    logs = TrafficLog.objects.all()[:200]
    return render(request, "ids/logs.html", {"logs": logs})


@login_required
def monitor_view(request):
    tshark = capture.find_tshark()
    interfaces = capture.get_interfaces(tshark) if tshark else []
    return render(
        request,
        "ids/monitor.html",
        {
            "wireshark_ok": bool(tshark),
            "interfaces": interfaces,
            "tshark_path": tshark or "",
        },
    )


def _analyze_packet(source_ip, dest_ip, protocol, features):
    prediction, confidence = ml.predict_traffic(features)
    conf_pct = round(confidence * 100, 1)

    TrafficLog.objects.create(
        source_ip=source_ip,
        dest_ip=dest_ip,
        protocol=protocol,
        duration=features.get("duration", 0),
        src_bytes=int(features.get("src_bytes", 0)),
        dst_bytes=int(features.get("dst_bytes", 0)),
        prediction=prediction,
        confidence=conf_pct,
    )

    if prediction != "normal":
        Alert.objects.create(
            attack_type=prediction,
            severity=ml.SEVERITY_MAP.get(prediction, "medium"),
            source_ip=source_ip,
            dest_ip=dest_ip,
            confidence=conf_pct,
        )

    return {
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "prediction": prediction,
        "confidence": conf_pct,
        "is_threat": prediction != "normal",
    }


@login_required
def capture_traffic(request):
    interface = request.GET.get("interface") or request.POST.get("interface")
    result = capture.capture_packets(interface=interface or None)

    if not result["ok"]:
        return JsonResponse(
            {
                "ok": False,
                "message": result["message"],
                "packets": [],
                "count": 0,
            }
        )

    analyzed = []
    for pkt in result["packets"]:
        features = capture.packet_to_features(pkt)
        analyzed.append(
            _analyze_packet(
                pkt["source_ip"],
                pkt["dest_ip"],
                pkt.get("protocol", "TCP"),
                features,
            )
        )

    return JsonResponse(
        {
            "ok": True,
            "packets": analyzed,
            "count": len(analyzed),
            "interface": result.get("interface"),
            "interface_name": result.get("interface_name"),
            "message": result.get("message"),
        }
    )


@login_required
@require_POST
def simulate_traffic(request):
    """Fallback simulator when Wireshark capture is unavailable."""
    features, src_ip, dst_ip = ml.random_traffic_sample()
    protocol = features.get("protocol_type", "tcp").upper()
    item = _analyze_packet(src_ip, dst_ip, protocol, features)
    return JsonResponse(item)


@login_required
def train_view(request):
    metrics = ModelMetrics.objects.first()
    return render(request, "ids/train.html", {"metrics": metrics})


@login_required
@require_POST
def train_model_view(request):
    try:
        result = ml.train_model(n_samples=3000)
        ModelMetrics.objects.create(**result)
        messages.success(
            request,
            f"Model trained — Accuracy: {result['accuracy']:.1%}, F1: {result['f1_score']:.1%}",
        )
    except Exception as e:
        messages.error(request, f"Training failed: {e}")
    return redirect("train")


@login_required
def reports_view(request):
    since = timezone.now() - timedelta(days=7)
    alerts_by_type = (
        Alert.objects.filter(created_at__gte=since)
        .values("attack_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    resolved = Alert.objects.filter(is_resolved=True).count()
    unresolved = Alert.objects.filter(is_resolved=False).count()
    metrics = ModelMetrics.objects.first()
    return render(
        request,
        "ids/reports.html",
        {
            "alerts_by_type": alerts_by_type,
            "resolved": resolved,
            "unresolved": unresolved,
            "metrics": metrics,
            "total_logs": TrafficLog.objects.count(),
        },
    )
