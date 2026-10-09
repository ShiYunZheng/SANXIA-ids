"""Run SANXIA and sanxia-ids-standalone against the same input concurrently."""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def _request(url: str, path: Path, token: str | None) -> dict:
    boundary = uuid.uuid4().hex
    payload = path.read_bytes()
    filename = path.name
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: {content_type}\r\n\r\n".encode()
        + payload
        + f"\r\n--{boundary}--\r\n".encode()
    )
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            data = json.loads(response.read().decode("utf-8"))
            return {"ok": True, "status": response.status, "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "data": data}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as error:
        status = getattr(error, "code", None)
        return {"ok": False, "status": status, "elapsedMs": round((time.perf_counter() - started) * 1000, 2), "error": str(error)}


def _labels(result: dict) -> list:
    data = result.get("data", {}) if isinstance(result, dict) else {}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    return data.get("labels", []) if isinstance(data, dict) else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--sanxia", default="http://127.0.0.1:5000/api/v1/detections")
    parser.add_argument("--standalone", default="http://127.0.0.1:8000/api/v1/detections")
    parser.add_argument("--sanxia-token")
    parser.add_argument("--standalone-token")
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"input does not exist: {args.input}")

    results: dict[str, dict] = {}
    threads = [
        threading.Thread(target=lambda: results.__setitem__("sanxia", _request(args.sanxia, args.input, args.sanxia_token))),
        threading.Thread(target=lambda: results.__setitem__("standalone", _request(args.standalone, args.input, args.standalone_token))),
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    left, right = _labels(results.get("sanxia", {})), _labels(results.get("standalone", {}))
    differences = [{"index": i, "sanxia": left[i] if i < len(left) else None, "standalone": right[i] if i < len(right) else None}
                   for i in range(max(len(left), len(right))) if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    report = {"input": str(args.input), "elapsedMs": round((time.perf_counter() - started) * 1000, 2),
              "systems": results, "counts": {"sanxia": len(left), "standalone": len(right)},
              "differences": differences}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if all(item.get("ok") for item in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())