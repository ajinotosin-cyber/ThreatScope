import unittest
from unittest.mock import patch

import api_client
import ioc_analysis
from config import ProviderConfig


NO_KEYS = ProviderConfig(virustotal_key=None, abuseipdb_key=None, otx_key=None)
WITH_KEYS = ProviderConfig(virustotal_key="fake-vt-key", abuseipdb_key="fake-abuse-key", otx_key=None)


class TestIocTypeDetection(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("8.8.8.8"), ioc_analysis.IOC_TYPE_IPV4)

    def test_domain(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("example.com"), ioc_analysis.IOC_TYPE_DOMAIN)

    def test_url(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("https://example.com/path"), ioc_analysis.IOC_TYPE_URL)

    def test_md5(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), ioc_analysis.IOC_TYPE_HASH_MD5)

    def test_sha256(self):
        self.assertEqual(
            ioc_analysis.detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]),
            ioc_analysis.IOC_TYPE_HASH_SHA256,
        )

    def test_invalid(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("not a valid ioc!!"), ioc_analysis.IOC_TYPE_INVALID)

    def test_invalid_ip_out_of_range(self):
        self.assertEqual(ioc_analysis.detect_ioc_type("999.999.999.999"), ioc_analysis.IOC_TYPE_INVALID)

    def test_empty(self):
        self.assertEqual(ioc_analysis.detect_ioc_type(""), ioc_analysis.IOC_TYPE_INVALID)


class TestInvestigatePipeline(unittest.TestCase):
    def test_invalid_ioc_never_calls_providers(self):
        with patch("api_client.virustotal_ip") as vt, patch("api_client.abuseipdb_check") as abuse:
            result = ioc_analysis.investigate("!!not-valid!!", WITH_KEYS)
        vt.assert_not_called()
        abuse.assert_not_called()
        self.assertEqual(result.result_status, ioc_analysis.RESULT_INVALID_IOC)

    def test_missing_keys_never_reports_safe(self):
        result = ioc_analysis.investigate("8.8.8.8", NO_KEYS)
        self.assertEqual(result.result_status, ioc_analysis.RESULT_PROVIDERS_UNAVAILABLE)
        self.assertNotEqual(result.classification, "Clean")
        self.assertNotEqual(result.classification, "Safe")

    def test_domain_never_calls_abuseipdb(self):
        """Regression test for the original bug: AbuseIPDB (IP-only API) must
        never be called with a domain."""
        with patch("api_client.virustotal_domain") as vt_domain, \
             patch("api_client.abuseipdb_check") as abuse, \
             patch("api_client.otx_domain") as otx:
            vt_domain.return_value = api_client.ProviderResult("VirusTotal", api_client.STATUS_NOT_FOUND)
            otx.return_value = api_client.ProviderResult("OTX", api_client.STATUS_NOT_CONFIGURED)
            ioc_analysis.investigate("example.com", WITH_KEYS)
        abuse.assert_not_called()
        vt_domain.assert_called_once()

    def test_provider_error_does_not_produce_safe_verdict(self):
        with patch("api_client.virustotal_ip") as vt, patch("api_client.abuseipdb_check") as abuse, \
             patch("api_client.otx_ip") as otx:
            vt.return_value = api_client.ProviderResult("VirusTotal", api_client.STATUS_NETWORK_ERROR, message="timeout")
            abuse.return_value = api_client.ProviderResult("AbuseIPDB", api_client.STATUS_INVALID_KEY, message="bad key")
            otx.return_value = api_client.ProviderResult("OTX", api_client.STATUS_NOT_CONFIGURED)
            result = ioc_analysis.investigate("1.2.3.4", WITH_KEYS)
        self.assertEqual(result.result_status, ioc_analysis.RESULT_PROVIDERS_UNAVAILABLE)
        self.assertEqual(result.classification, "Unknown")

    def test_clean_verdict_requires_actual_ok_data(self):
        with patch("api_client.virustotal_ip") as vt, patch("api_client.abuseipdb_check") as abuse, \
             patch("api_client.otx_ip") as otx:
            vt.return_value = api_client.ProviderResult(
                "VirusTotal", api_client.STATUS_OK,
                data={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "country": "US"}}},
            )
            abuse.return_value = api_client.ProviderResult(
                "AbuseIPDB", api_client.STATUS_OK,
                data={"data": {"abuseConfidenceScore": 0, "countryCode": "US"}},
            )
            otx.return_value = api_client.ProviderResult("OTX", api_client.STATUS_NOT_CONFIGURED)
            result = ioc_analysis.investigate("1.1.1.1", WITH_KEYS)
        self.assertEqual(result.result_status, ioc_analysis.RESULT_VALID)
        self.assertEqual(result.classification, "Clean")
        self.assertEqual(result.confidence, "High")

    def test_malicious_verdict_gets_mitre_mapping(self):
        with patch("api_client.virustotal_ip") as vt, patch("api_client.abuseipdb_check") as abuse, \
             patch("api_client.otx_ip") as otx:
            vt.return_value = api_client.ProviderResult(
                "VirusTotal", api_client.STATUS_OK,
                data={"data": {"attributes": {"last_analysis_stats": {"malicious": 10}, "country": "RU"}}},
            )
            abuse.return_value = api_client.ProviderResult(
                "AbuseIPDB", api_client.STATUS_OK,
                data={"data": {"abuseConfidenceScore": 95, "countryCode": "RU"}},
            )
            otx.return_value = api_client.ProviderResult("OTX", api_client.STATUS_NOT_CONFIGURED)
            result = ioc_analysis.investigate("6.6.6.6", WITH_KEYS)
        self.assertEqual(result.classification, "Malicious")
        self.assertEqual(result.severity, "Critical")
        self.assertTrue(len(result.mitre) >= 1)
        self.assertEqual(result.mitre[0].technique_id, "T1071")


if __name__ == "__main__":
    unittest.main()
