# app/main.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from model import predict, load_model, FEATURE_COLS

class SecureFlowHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[SecureFlow] {self.address_string()} - {format % args}")

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/health":
            self._respond(200, {
                "status"  : "healthy",
                "service" : "SecureFlow-IDS",
                "version" : "1.0.0",
                "model"   : "Random Forest — NSL-KDD"
            })
        elif self.path == "/features":
            self._respond(200, {
                "required_features" : FEATURE_COLS,
                "count"             : len(FEATURE_COLS)
            })
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        """Prediction endpoint."""
        if self.path == "/predict":
            try:
                length  = int(self.headers['Content-Length'])
                body    = self.rfile.read(length)
                data    = json.loads(body)
                result  = predict(data)

                if "error" in result:
                    self._respond(400, result)
                else:
                    self._respond(200, result)

            except json.JSONDecodeError:
                self._respond(400, {"error": "Invalid JSON"})
            except Exception as e:
                self._respond(500, {"error": str(e)})
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body, indent=2).encode())

if __name__ == "__main__":
    print("="*50)
    print("  SecureFlow IDS — starting up")
    print("  Loading model...")
    load_model()
    print("  Model ready.")
    print("  Listening on http://0.0.0.0:8000")
    print("="*50)
    server = HTTPServer(('0.0.0.0', 8000), SecureFlowHandler)
    server.serve_forever()