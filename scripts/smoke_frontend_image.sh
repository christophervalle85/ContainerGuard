#!/usr/bin/env bash
# Check the built Nginx runtime without publishing an image or starting the API.
set -euo pipefail
image="${1:?usage: smoke_frontend_image.sh IMAGE}"
container=""
cleanup() {
  if [[ -n "$container" ]]; then
    docker logs "$container" || true
    docker rm -f "$container" >/dev/null
  fi
}
trap cleanup EXIT
container="$(docker run --detach --publish 127.0.0.1::8080 "$image")"
test "$(docker exec "$container" id -u)" = 101
port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$container")"
FRONTEND_SMOKE_PORT="$port" python3 - <<'PY'
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

base = "http://127.0.0.1:" + os.environ["FRONTEND_SMOKE_PORT"]

def fetch(path):
    with urlopen(base + path, timeout=3) as response:
        assert response.status == 200, path
        return response.read()

for attempt in range(30):
    try:
        assert fetch("/healthz").strip() == b"ok"
        break
    except (URLError, TimeoutError):
        if attempt == 29:
            raise
        time.sleep(1)

index = fetch("/index.html")
assert b"<html" in index.lower()
assert fetch("/") == index
assert fetch("/scans") == index
assets = re.findall(rb'(?:src|href)="(/assets/[^"\s]+\.(?:js|css))"', index)
assert assets, "Built index has no JavaScript or CSS assets"
for asset in assets:
    assert fetch(asset.decode()), asset
try:
    fetch("/assets/containerguard-missing-smoke-asset.js")
except HTTPError as error:
    assert error.code == 404
else:
    raise AssertionError("Missing assets must return 404")
print("Frontend runtime smoke passed: non-root, health, SPA routes, assets and 404")
PY
