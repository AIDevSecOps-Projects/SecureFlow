from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from model import predict, load_model, FEATURE_COLS
from security import (check_rate_limit, validate_input,
                      safe_error, apply_agency_controls,
                      log_and_detect_theft)


class SecureFlowHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[SecureFlow] {self.address_string()} - {format % args}")

    def do_GET(self):
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
        if self.path == "/predict":
            try:
                client_ip = self.client_address[0]

                if not check_rate_limit(client_ip):
                    self._respond(429, {
                        "error"  : "Rate limit exceeded",
                        "limit"  : "100 requests per minute",
                        "action" : "REJECT"
                    })
                    return

                length = int(self.headers['Content-Length'])
                body   = self.rfile.read(length)
                data   = json.loads(body)

                theft = log_and_detect_theft(client_ip, data)
                if theft:
                    self._respond(429, safe_error(
                        "Model theft detected", "THEFT_DETECTED"
                    ))
                    return

                valid, error_msg = validate_input(data)
                if not valid:
                    self._respond(400, safe_error(
                        error_msg, "INVALID_INPUT"
                    ))
                    return

                result = predict(data)

                if "error" in result:
                    self._respond(400, safe_error(
                        result["error"], "PREDICTION_ERROR"
                    ))
                    return

                result = apply_agency_controls(result)
                self._respond(200, result)

            except json.JSONDecodeError:
                self._respond(400, safe_error(
                    "Invalid JSON", "JSON_ERROR"
                ))
            except Exception as e:
                self._respond(500, safe_error(
                    str(e), "INTERNAL_ERROR"
                ))
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
    server = HTTPServer(('0.0.0.0', 8000), SecureFlowHandler)  # nosec B104 - intentional, required for Docker container networking
    server.serve_forever()
