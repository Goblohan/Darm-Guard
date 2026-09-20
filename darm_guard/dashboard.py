import http.server
import json
import os
import threading
import webbrowser
from typing import Optional
from .guard import DARMGuard


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    guard: Optional[DARMGuard] = None
    dashboard_dir: str = ""

    def do_GET(self):
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            state = {
                "mode": self.guard.mode.name if self.guard else "UNKNOWN",
                "scope": self.guard.scope() if self.guard else {},
                "audit": self.guard.audit() if self.guard else [],
                "policy_tools": sorted(self.guard.policy.authorized_tools) if self.guard else [],
            }
            self.wfile.write(json.dumps(state).encode())
            return
        if self.path == "/" or self.path == "/index.html":
            self.path = "/index.html"
        self.directory = self.dashboard_dir
        super().do_GET()

    def log_message(self, format, *args):
        pass


def serve_dashboard(guard: DARMGuard, port: int = 7832, open_browser: bool = True):
    dashboard_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard")
    dashboard_dir = os.path.abspath(dashboard_dir)
    DashboardHandler.guard = guard
    DashboardHandler.dashboard_dir = dashboard_dir
    server = http.server.HTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"DARM Guard dashboard: http://127.0.0.1:{port}")
    if open_browser:
        webbrowser.open(f"http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()


def serve_dashboard_background(guard: DARMGuard, port: int = 7832):
    t = threading.Thread(target=serve_dashboard, args=(guard, port, False), daemon=True)
    t.start()
    print(f"DARM Guard dashboard (background): http://127.0.0.1:{port}")
    return t
