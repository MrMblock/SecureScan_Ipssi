"""WebSocket consumer for real-time scan progress updates."""

import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """Push scan progress events to connected clients.

    Group name: ``scan_{scan_id}``

    Incoming messages from the channel layer:
      - ``scan.progress`` — intermediate progress update
      - ``scan.completed`` — scan finished successfully
      - ``scan.failed`` — scan errored out
    """

    async def connect(self):
        self.scan_id = self.scope["url_route"]["kwargs"]["scan_id"]
        self.group_name = f"scan_{self.scan_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # ── Event handlers (called by channel_layer.group_send) ──

    async def scan_progress(self, event):
        """Forward a progress update to the WebSocket client."""
        await self.send(text_data=json.dumps({
            "type": "progress",
            "percent": event.get("percent", 0),
            "phase": event.get("phase", ""),
            "phase_label": event.get("phase_label", ""),
            "message": event.get("message", ""),
            "findings_so_far": event.get("findings_so_far", 0),
        }))

    async def scan_completed(self, event):
        """Notify the client that the scan completed."""
        await self.send(text_data=json.dumps({
            "type": "completed",
            "total_findings": event.get("total_findings", 0),
            "scan_id": self.scan_id,
        }))

    async def scan_failed(self, event):
        """Notify the client that the scan failed."""
        await self.send(text_data=json.dumps({
            "type": "failed",
            "error": event.get("error", "Unknown error"),
        }))
