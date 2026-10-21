import hashlib
import hmac
import json
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("VERIFY_TOKEN", "test-verify-token")
os.environ.setdefault("WHATSAPP_TOKEN", "test-whatsapp-token")
os.environ.setdefault("PHONE_NUMBER_ID", "12345")
os.environ.setdefault("DATABASE_URL", "postgresql://127.0.0.1:1/unused")
os.environ.setdefault("META_APP_SECRET", "test-only-app-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import webhook  # noqa: E402


class WebhookSignatureTests(unittest.TestCase):
    def setUp(self):
        self.client = webhook.app.test_client()
        self.user_patch = patch.object(
            webhook, "get_user", return_value={"id": 1, "blocked": False}
        )
        self.handle_patch = patch.object(webhook, "handle_text")
        self.user_patch.start()
        self.handle_mock = self.handle_patch.start()
        self.addCleanup(self.user_patch.stop)
        self.addCleanup(self.handle_patch.stop)
        self.body = json.dumps({
            "object": "whatsapp_business_account",
            "entry": [{"changes": [{"value": {
                "metadata": {"phone_number_id": "12345"},
                "messages": [{
                    "type": "text", "from": "233551234567",
                    "text": {"body": "MENU"},
                }],
            }}]}],
        }).encode("utf-8")

    def post(self, signature=None):
        headers = {"Content-Type": "application/json"}
        if signature is not None:
            headers["X-Hub-Signature-256"] = signature
        return self.client.post("/webhook", data=self.body, headers=headers)

    def test_unsigned_event_is_rejected_before_processing(self):
        response = self.post()
        self.assertEqual(response.status_code, 403)
        self.handle_mock.assert_not_called()

    def test_invalid_signature_is_rejected_before_processing(self):
        response = self.post("sha256=" + "0" * 64)
        self.assertEqual(response.status_code, 403)
        self.handle_mock.assert_not_called()

    def test_valid_signature_processes_event(self):
        digest = hmac.new(
            b"test-only-app-secret", self.body, hashlib.sha256
        ).hexdigest()
        response = self.post("sha256=" + digest)
        self.assertEqual(response.status_code, 200)
        self.handle_mock.assert_called_once()

    def test_missing_app_secret_fails_closed(self):
        with patch.object(webhook, "META_APP_SECRET", ""):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        self.handle_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
