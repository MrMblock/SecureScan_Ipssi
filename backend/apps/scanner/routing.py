from django.urls import re_path

from .consumers import ScanProgressConsumer

websocket_urlpatterns = [
    re_path(r"ws/scan/(?P<scan_id>[0-9a-f-]+)/$", ScanProgressConsumer.as_asgi()),
]
