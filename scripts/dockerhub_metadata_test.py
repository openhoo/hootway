import importlib.util
from http.client import BadStatusLine
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


spec = importlib.util.spec_from_file_location("dockerhub_metadata", Path(__file__).with_name("dockerhub-metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)
COMMIT = "0123456789abcdef0123456789abcdef01234567"
ENV = {"DOCKERHUB_USERNAME": "synthetic-user", "DOCKERHUB_TOKEN": "synthetic-private-password", "GITHUB_SHA": COMMIT}


class Response(io.BytesIO):
    status = 200


class DockerHubMetadataTests(unittest.TestCase):
    def invoke(self, open_request, environ=ENV, readme="![Keys](docs/screenshots/keys.png)\n[License](LICENSE)\n"):
        out, errors = io.StringIO(), io.StringIO()
        with patch.object(Path, "read_text", return_value=readme):
            result = metadata.main(environ, open_request, out, errors)
        return result, out.getvalue(), errors.getvalue()

    def test_exact_auth_and_namespace_patch(self):
        calls = []

        def request(req, timeout):
            calls.append(req)
            self.assertEqual(timeout, 30)
            return Response(b'{"access_token":"synthetic-api-token"}' if len(calls) == 1 else b"")

        code, out, errors = self.invoke(request)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(len(calls), 2)
        self.assertEqual((calls[0].get_method(), calls[0].full_url), ("POST", metadata.AUTH_URL))
        self.assertEqual(json.loads(calls[0].data), {"identifier": ENV["DOCKERHUB_USERNAME"], "secret": ENV["DOCKERHUB_TOKEN"]})
        self.assertIsNone(calls[0].get_header("Authorization"))
        self.assertEqual((calls[1].get_method(), calls[1].full_url), ("PATCH", "https://hub.docker.com/v2/namespaces/openhoo/repositories/hootway"))
        self.assertEqual(calls[1].get_header("Authorization"), "Bearer synthetic-api-token")
        body = json.loads(calls[1].data)
        self.assertEqual(set(body), {"description", "full_description"})
        self.assertLessEqual(len(body["description"].encode("utf-8")), 100)
        self.assertIn("https://raw.githubusercontent.com/openhoo/hootway/" + COMMIT + "/docs/screenshots/keys.png", body["full_description"])
        self.assertIn("https://github.com/openhoo/hootway/blob/" + COMMIT + "/LICENSE", body["full_description"])
        self.assertNotIn(ENV["DOCKERHUB_TOKEN"], out + errors)
        self.assertNotIn("synthetic-api-token", out + errors)

    def test_forbidden_and_network_errors_do_not_reflect_credentials(self):
        for failure in [
            HTTPError(metadata.REPOSITORY_URL, 403, "synthetic-private-password", {}, io.BytesIO(b"synthetic-api-token")),
            URLError("synthetic-private-password synthetic-api-token"),
            ValueError("invalid header: synthetic-api-token"),
            BadStatusLine("synthetic-private-password synthetic-api-token"),
        ]:
            with self.subTest(failure=type(failure).__name__):
                calls = []

                def request(req, timeout):
                    calls.append(req)
                    if len(calls) == 1:
                        return Response(b'{"access_token":"synthetic-api-token"}')
                    raise failure

                code, out, errors = self.invoke(request)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertNotIn("synthetic-private-password", errors)
                self.assertNotIn("synthetic-api-token", errors)
                self.assertIn("Docker Hub", errors)
                if isinstance(failure, HTTPError):
                    self.assertIn("HTTP 403", errors)

    def test_missing_credentials_and_bad_revision_make_no_requests(self):
        for environ in [{}, {**ENV, "DOCKERHUB_TOKEN": ""}, {**ENV, "GITHUB_SHA": "synthetic-private-password"}]:
            with self.subTest(fields=sorted(environ)):
                def unexpected(*args, **kwargs):
                    self.fail("invalid input reached Docker Hub")

                code, out, errors = self.invoke(unexpected, environ)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertNotIn("synthetic-private-password", errors)

    def test_short_description_bound_keeps_utf8_valid(self):
        description = metadata.metadata_body("README", COMMIT, "🐉" * 40)["description"]
        self.assertEqual(description, "🐉" * 25)
        self.assertEqual(len(description.encode("utf-8")), 100)

    def test_external_anchors_and_code_stay_unchanged(self):
        source = '[External](https://example.com) [Anchor](#setup) `[Example](LICENSE)`\n```md\n[Example](LICENSE)\n```\n[License](LICENSE "License")\n'
        result = metadata.complete_readme_links(source, COMMIT)
        self.assertIn('[External](https://example.com) [Anchor](#setup) `[Example](LICENSE)`', result)
        self.assertIn('```md\n[Example](LICENSE)\n```', result)
        self.assertIn('[License](https://github.com/openhoo/hootway/blob/' + COMMIT + '/LICENSE "License")', result)

    def test_auth_response_controls_and_oversize_are_rejected(self):
        for response in [b'{"access_token":"synthetic-api-token\\r\\nForged: value"}', b'{"access_token":null}', b"[]", b"synthetic-private-password", b" " * (metadata.MAX_AUTH_BYTES + 1)]:
            with self.subTest(kind=len(response)):
                calls = []

                def request(req, timeout):
                    calls.append(req)
                    return Response(response)

                code, out, errors = self.invoke(request)
                self.assertEqual(code, 1)
                self.assertEqual(len(calls), 1)
                self.assertNotIn("synthetic-api-token", out + errors)
                self.assertNotIn("synthetic-private-password", out + errors)

    def test_redirects_are_disabled(self):
        handler = metadata.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://other.example"))

    def test_readme_bound_rejects_without_network(self):
        def unexpected(*args, **kwargs):
            self.fail("oversized metadata reached Docker Hub")

        code, _, errors = self.invoke(unexpected, readme="x" * (metadata.MAX_README_BYTES + 1))
        self.assertEqual(code, 1)
        self.assertIn("supported size", errors)


if __name__ == "__main__":
    unittest.main()
