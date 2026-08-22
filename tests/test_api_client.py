import unittest
from unittest.mock import patch, MagicMock

import requests

import api_client


class FakeResponse:
    def __init__(self, status_code, json_data=None, raise_json_error=False):
        self.status_code = status_code
        self._json_data = json_data
        self._raise_json_error = raise_json_error

    def json(self):
        if self._raise_json_error:
            raise ValueError("not json")
        return self._json_data


class TestApiClientErrorHandling(unittest.TestCase):
    def setUp(self):
        api_client._cache.clear()

    def test_not_configured_when_no_key(self):
        result = api_client.virustotal_ip("1.2.3.4", None)
        self.assertEqual(result.status, api_client.STATUS_NOT_CONFIGURED)

    @patch("requests.get")
    def test_timeout_becomes_network_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        result = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(result.status, api_client.STATUS_NETWORK_ERROR)

    @patch("requests.get")
    def test_connection_error_becomes_network_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError()
        result = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(result.status, api_client.STATUS_NETWORK_ERROR)

    @patch("requests.get")
    def test_401_becomes_invalid_key(self, mock_get):
        mock_get.return_value = FakeResponse(401)
        result = api_client.virustotal_ip("1.2.3.4", "bad-key")
        self.assertEqual(result.status, api_client.STATUS_INVALID_KEY)

    @patch("requests.get")
    def test_429_becomes_rate_limited(self, mock_get):
        mock_get.return_value = FakeResponse(429)
        result = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(result.status, api_client.STATUS_RATE_LIMITED)

    @patch("requests.get")
    def test_404_becomes_not_found(self, mock_get):
        mock_get.return_value = FakeResponse(404)
        result = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(result.status, api_client.STATUS_NOT_FOUND)

    @patch("requests.get")
    def test_malformed_json_becomes_network_error(self, mock_get):
        mock_get.return_value = FakeResponse(200, raise_json_error=True)
        result = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(result.status, api_client.STATUS_NETWORK_ERROR)

    @patch("requests.get")
    def test_200_becomes_ok_and_is_cached(self, mock_get):
        mock_get.return_value = FakeResponse(200, json_data={"ok": True})
        r1 = api_client.virustotal_ip("1.2.3.4", "fake-key")
        r2 = api_client.virustotal_ip("1.2.3.4", "fake-key")
        self.assertEqual(r1.status, api_client.STATUS_OK)
        self.assertEqual(r2.status, api_client.STATUS_OK)
        mock_get.assert_called_once()  # second call served from cache

    @patch("requests.get")
    def test_errors_are_never_cached(self, mock_get):
        mock_get.return_value = FakeResponse(500)
        api_client.virustotal_ip("9.9.9.9", "fake-key")
        api_client.virustotal_ip("9.9.9.9", "fake-key")
        self.assertEqual(mock_get.call_count, 2)  # not cached -> called twice

    @patch("requests.get")
    def test_timeout_kwarg_always_passed(self, mock_get):
        mock_get.return_value = FakeResponse(200, json_data={})
        api_client.virustotal_ip("1.2.3.4", "fake-key")
        _, kwargs = mock_get.call_args
        self.assertIn("timeout", kwargs)
        self.assertIsNotNone(kwargs["timeout"])


if __name__ == "__main__":
    unittest.main()
