#!/usr/bin/env python3
"""Update only openhoo/hootway metadata through the namespace Docker Hub API."""

import json
from http.client import HTTPException
import os
from pathlib import Path
import posixpath
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


AUTH_URL = "https://hub.docker.com/v2/auth/token"
REPOSITORY_URL = "https://hub.docker.com/v2/namespaces/openhoo/repositories/hootway"
SHORT_DESCRIPTION = "Scoped virtual keys for agent sandboxes, with API credential injection and access controls."
MAX_AUTH_BYTES = 64 * 1024
MAX_README_BYTES = 25_000
LINK_OR_CODE = re.compile(
    r"`[^`]*`|(?P<prefix>!?\[[^\]\n]*\]\()"
    r"(?P<target><[^>\n]+>|[^)\s]+)(?P<suffix>[^)\n]*\))"
)


class MetadataError(Exception):
    """Only fixed, credential-independent messages may reach this exception."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def truncate_utf8(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def complete_readme_links(readme, commit):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise MetadataError("Docker Hub metadata requires a valid GitHub revision.")
    commit = commit.lower()

    def replace(match):
        prefix = match.group("prefix")
        if prefix is None:
            return match.group(0)  # inline code
        target = match.group("target")
        angled = target.startswith("<")
        parts = urlsplit(target[1:-1] if angled else target)
        if parts.scheme or parts.netloc or not parts.path:
            return match.group(0)  # external links and local anchors
        path = posixpath.normpath(parts.path.lstrip("/"))
        if path == ".." or path.startswith("../"):
            return match.group(0)
        if prefix.startswith("!"):
            base = "https://raw.githubusercontent.com/openhoo/hootway/" + commit
        else:
            base = "https://github.com/openhoo/hootway/blob/" + commit
        absolute = urlunsplit(urlsplit(base + "/" + path)._replace(query=parts.query, fragment=parts.fragment))
        if angled:
            absolute = "<" + absolute + ">"
        return prefix + absolute + match.group("suffix")

    lines = []
    fence = None
    for line in readme.splitlines(keepends=True):
        opening = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if opening:
            marker = opening.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append(line)
        else:
            lines.append(line if fence else LINK_OR_CODE.sub(replace, line))
    return "".join(lines)


def metadata_body(readme, commit, description=SHORT_DESCRIPTION):
    completed = complete_readme_links(readme, commit)
    if len(completed.encode("utf-8")) > MAX_README_BYTES:
        raise MetadataError("Docker Hub metadata README exceeds the supported size.")
    return {"description": truncate_utf8(description, 100), "full_description": completed}


def send_json(open_request, url, method, body, phase, token=None, read_body=False):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token is not None:
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
            raise MetadataError("Docker Hub returned an invalid authentication response.")
        headers["Authorization"] = "Bearer " + token
    request = Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method=method)
    try:
        with open_request(request, timeout=30) as response:
            if not 200 <= response.status < 300:
                raise MetadataError("Docker Hub " + phase + " failed (HTTP " + str(response.status) + ").")
            if read_body:
                data = response.read(MAX_AUTH_BYTES + 1)
                if len(data) > MAX_AUTH_BYTES:
                    raise MetadataError("Docker Hub returned an invalid authentication response.")
                try:
                    result = json.loads(data)
                except (ValueError, UnicodeError):
                    raise MetadataError("Docker Hub returned an invalid authentication response.") from None
                if not isinstance(result, dict):
                    raise MetadataError("Docker Hub returned an invalid authentication response.")
                return result
    except HTTPError as error:
        status = error.code
        error.close()
        raise MetadataError("Docker Hub " + phase + " failed (HTTP " + str(status) + ").") from None
    except (URLError, HTTPException, OSError, ValueError, UnicodeError):
        raise MetadataError("Docker Hub API could not be reached.") from None


def main(environ=None, open_request=None, stdout=None, stderr=None):
    environ = os.environ if environ is None else environ
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        username = environ.get("DOCKERHUB_USERNAME", "")
        secret = environ.get("DOCKERHUB_TOKEN", "")
        if not username or not secret:
            raise MetadataError("Docker Hub metadata credentials are missing.")
        body = metadata_body(Path("README.md").read_text(encoding="utf-8"), environ.get("GITHUB_SHA", ""))
        open_request = build_opener(NoRedirect()).open if open_request is None else open_request
        auth = send_json(open_request, AUTH_URL, "POST", {"identifier": username, "secret": secret}, "authentication", read_body=True)
        token = auth.get("access_token")
        if not isinstance(token, str) or not token:
            raise MetadataError("Docker Hub returned an invalid authentication response.")
        send_json(open_request, REPOSITORY_URL, "PATCH", body, "metadata update", token=token)
    except MetadataError as error:
        print(str(error), file=stderr)
        return 1
    except (OSError, ValueError, UnicodeError):
        print("Docker Hub metadata input could not be read.", file=stderr)
        return 1
    print("Docker Hub repository metadata updated.", file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
