import csv
import json
from datetime import timedelta
from io import StringIO

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import capture, ml
from . import ml_predict
from .models import Alert, ModelMetrics, PredictionRun, TrafficLog, UserProfile


def landing_view(request):
    return render(request, "ids/landing.html")

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


import threading

def _run_training_in_background():
    try:
        result = ml.train_model(n_samples=3000)
        ModelMetrics.objects.create(**result)
    except Exception as e:
        print(f"Background training failed: {e}")

@login_required
@require_POST
def train_model_view(request):
    thread = threading.Thread(target=_run_training_in_background)
    thread.daemon = True
    thread.start()
    messages.success(request, "Training started in the background. It will use both synthetic data and recorded network logs from the database.")
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


def _user_prediction_runs(user):
    return PredictionRun.objects.filter(user=user)


def _prediction_run_or_redirect(request, pk=None):
    if pk is not None:
        return get_object_or_404(_user_prediction_runs(request.user), pk=pk)
    run = _user_prediction_runs(request.user).first()
    if run is None:
        messages.info(request, "Upload a dataset to run your first prediction.")
        return redirect("predict_upload")
    return run


@login_required
def predict_upload_view(request):
    if request.method == "POST":
        is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.headers.get('accept') == 'application/json' or request.content_type == 'application/json' or 'axios' in request.META.get('HTTP_USER_AGENT', '').lower()
        # Axios might not set X-Requested-With by default unless configured.
        
        uploaded = request.FILES.get("dataset")
        if not uploaded:
            if is_ajax: return JsonResponse({"error": "Please select a CSV file to upload."}, status=400)
            messages.error(request, "Please select a CSV file to upload.")
            return redirect("predict_upload")
            
        if not uploaded.name.lower().endswith(".csv"):
            if is_ajax: return JsonResponse({"error": "Only CSV files are supported."}, status=400)
            messages.error(request, "Only CSV files are supported.")
            return redirect("predict_upload")
            
        try:
            analysis = ml_predict.predict_dataset(uploaded)
        except Exception as exc:
            if is_ajax: return JsonResponse({"error": f"Could not analyze dataset: {exc}"}, status=400)
            messages.error(request, f"Could not analyze dataset: {exc}")
            return redirect("predict_upload")

        run = PredictionRun.objects.create(
            user=request.user,
            input_filename=uploaded.name,
            total_records=analysis["total_records"],
            overall_class=analysis["overall_class"],
            confidence_score=analysis["confidence_score"],
            malicious_percent=analysis["malicious_percent"],
            normal_percent=analysis["normal_percent"],
            model_name=analysis["model_name"],
            feature_importance=analysis["feature_importance"],
            traffic_summary=analysis["traffic_summary"],
            results=analysis["results"],
        )
        
        # Store network logs in DB
        traffic_logs = []
        alerts = []
        for row in analysis["results"]:
            traffic_logs.append(TrafficLog(
                source_ip=row["source_ip"],
                dest_ip=row["dest_ip"],
                protocol=row["protocol"],
                duration=row["flow_duration"],
                src_bytes=row["packet_length"],
                prediction=row["prediction_raw"],
                confidence=row["confidence"],
            ))
            
            if row["prediction_raw"] != "normal":
                alerts.append(Alert(
                    attack_type=row["prediction_raw"],
                    severity=ml.SEVERITY_MAP.get(row["prediction_raw"], "medium"),
                    source_ip=row["source_ip"],
                    dest_ip=row["dest_ip"],
                    confidence=row["confidence"],
                ))
                
        TrafficLog.objects.bulk_create(traffic_logs)
        if alerts:
            Alert.objects.bulk_create(alerts)
        
        if is_ajax:
            return JsonResponse({"redirect_url": redirect("predict_result", pk=run.pk).url})
            
        messages.success(request, "Prediction completed successfully.")
        return redirect("predict_result", pk=run.pk)

    return render(request, "ids/predict_upload.html")


@login_required
def predict_result_view(request, pk=None):
    run = _prediction_run_or_redirect(request, pk)
    if not isinstance(run, PredictionRun):
        return run

    sample_rows = run.results[:10]
    chart_payload = {
        "malicious_percent": run.malicious_percent,
        "normal_percent": run.normal_percent,
        "confidence_score": run.confidence_score,
        "feature_labels": [f["label"] for f in run.feature_importance],
        "feature_values": [f["value"] for f in run.feature_importance],
    }
    return render(
        request,
        "ids/predict_result.html",
        {
            "run": run,
            "sample_rows": sample_rows,
            "charts": json.dumps(chart_payload),
            "traffic": run.traffic_summary,
        },
    )


@login_required
def predict_download_view(request, pk):
    run = get_object_or_404(_user_prediction_runs(request.user), pk=pk)
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "source_ip",
            "destination_ip",
            "protocol",
            "packet_length",
            "flow_duration",
            "prediction",
            "confidence",
        ]
    )
    for row in run.results:
        writer.writerow(
            [
                row["source_ip"],
                row["dest_ip"],
                row["protocol"],
                row["packet_length"],
                row["flow_duration"],
                row["prediction"],
                row["confidence"],
            ]
        )

    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    safe_name = run.input_filename.rsplit(".", 1)[0]
    response["Content-Disposition"] = f'attachment; filename="{safe_name}_predictions.csv"'
    return response


@login_required
def dataset_history_view(request):
    runs = _user_prediction_runs(request.user)
    return render(request, "ids/dataset_history.html", {"runs": runs})


@login_required
def users_view(request):
    profile = getattr(request.user, "profile", None)
    if profile is None or profile.role != "admin":
        messages.error(request, "Administrator access required.")
        return redirect("dashboard")
    users = User.objects.select_related("profile").order_by("username")
    return render(request, "ids/users.html", {"users": users})


@login_required
def settings_view(request):
    return render(request, "ids/settings.html")
