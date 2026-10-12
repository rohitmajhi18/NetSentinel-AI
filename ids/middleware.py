from django.http import HttpResponseForbidden


class RoleAccessMiddleware:
    ADMIN_ONLY = {"users", "settings", "train_model"}
    RESEARCHER_ACCESS = {
        "dashboard",
        "chart_api",
        "alerts",
        "resolve_alert",
        "logs",
        "monitor",
        "capture_traffic",
        "simulate_traffic",
        "train",
        "reports",
        "predict_upload",
        "predict_result",
        "predict_download",
        "dataset_history",
    }
    PUBLIC = {"landing", "login", "register", "logout"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.user.is_authenticated:
            return None

        match = request.resolver_match
        if match is None or match.namespace:
            return None

        route_name = match.url_name
        if route_name in self.PUBLIC:
            return None

        profile = getattr(request.user, "profile", None)
        role = "admin" if request.user.is_superuser else getattr(profile, "role", "researcher")
        if role == "admin":
            return None
        if role == "researcher" and route_name in self.RESEARCHER_ACCESS and route_name not in self.ADMIN_ONLY:
            return None
        return HttpResponseForbidden("You do not have permission to access this page.")