#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8"))
VERSION = BASELINE["version"]
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{VERSION}"

SSL_VERIFICATION = FIREFOX / "security/manager/ssl/SSLServerCertVerification.cpp"
SOCKET_CONTROL = FIREFOX / "security/manager/ssl/NSSSocketControl.cpp"
COMMON_SOCKET_CONTROL = FIREFOX / "security/manager/ssl/CommonSocketControl.cpp"
TRANSPORT_SECURITY_INFO = FIREFOX / "security/manager/ssl/TransportSecurityInfo.h"
VERIFY_PARENT = FIREFOX / "security/manager/ssl/VerifySSLServerCertParent.cpp"
VERIFY_CHILD = FIREFOX / "security/manager/ssl/VerifySSLServerCertChild.cpp"
CERT_VERIFIER = FIREFOX / "security/certverifier/CertVerifier.cpp"
TRUST_DOMAIN = FIREFOX / "security/certverifier/NSSCertDBTrustDomain.cpp"
PKIX_RESULTS = FIREFOX / "security/nss/lib/mozpkix/include/pkix/Result.h"
PSM_TEST_MANIFEST = FIREFOX / "security/manager/ssl/tests/unit/xpcshell.toml"
PSM_TEST_HELPER = FIREFOX / "security/manager/ssl/tests/unit/head_psm.js"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    """Return one C++ function body, including its outer braces."""
    signature_start = source.index(signature)
    body_start = source.index("{", signature_start)
    depth = 0
    for index in range(body_start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : index + 1]
    raise AssertionError(f"unterminated C++ function: {signature}")


def assert_in_order(test: unittest.TestCase, source: str, *needles: str) -> None:
    positions = [source.index(needle) for needle in needles]
    test.assertEqual(positions, sorted(positions), needles)


class M201VerificationContractTest(unittest.TestCase):
    def test_targeted_firefox_owners_and_upstream_probes_are_pinned(self) -> None:
        for owner in (
            SSL_VERIFICATION,
            SOCKET_CONTROL,
            COMMON_SOCKET_CONTROL,
            TRANSPORT_SECURITY_INFO,
            VERIFY_PARENT,
            VERIFY_CHILD,
            CERT_VERIFIER,
            TRUST_DOMAIN,
            PKIX_RESULTS,
            PSM_TEST_HELPER,
        ):
            self.assertTrue(owner.is_file(), owner)

        manifest = read(PSM_TEST_MANIFEST)
        self.assertIn('["test_cert_overrides.js"]', manifest)
        self.assertIn('["test_self_signed_certs.js"]', manifest)
        helper = read(PSM_TEST_HELPER)
        self.assertIn("function add_connection_test(", helper)
        self.assertIn("Actual and expected connection result should match", helper)

    def test_socket_process_uses_the_same_verification_job_and_barrier(self) -> None:
        parent_dispatch = function_body(
            read(VERIFY_PARENT), "VerifySSLServerCertParent::Dispatch("
        )
        self.assertIn("SSLServerCertVerificationJob::Dispatch(", parent_dispatch)
        self.assertIn("status != SECWouldBlock", parent_dispatch)

        remote = function_body(read(VERIFY_CHILD), "RemoteProcessCertVerification(")
        assert_in_order(
            self,
            remote,
            "SendInitVerifySSLServerCert(",
            "PR_SetError(PR_WOULD_BLOCK_ERROR, 0);",
            "return SECWouldBlock;",
        )
        child_result = function_body(
            read(VERIFY_CHILD),
            "VerifySSLServerCertChild::RecvOnVerifySSLServerCertFinished(",
        )
        self.assertIn("mResultTask->Dispatch(", child_result)

    def test_standard_verification_returns_one_exact_pkix_result(self) -> None:
        ssl_source = read(SSL_VERIFICATION)
        auth_certificate = function_body(ssl_source, "Result AuthCertificate(")
        assert_in_order(
            self,
            auth_certificate,
            "Result rv = certVerifier.VerifySSLServerCert(",
            "CollectCertTelemetry(rv,",
            "return rv;",
        )

        verifier_source = read(CERT_VERIFIER)
        verify_server = function_body(
            verifier_source, "Result CertVerifier::VerifySSLServerCert("
        )
        verify_cert = verify_server.index("rv = VerifyCert(")
        early_hostname = verify_server.index("CheckCertHostnameHelper(")
        tls_features = verify_server.index("CheckTLSFeaturesAreSatisfied(")
        final_hostname = verify_server.rindex("CheckCertHostnameHelper(")
        success = verify_server.rindex("return Success;")
        self.assertLess(verify_cert, early_hostname)
        self.assertLess(early_hostname, tls_features)
        self.assertLess(tls_features, final_hostname)
        self.assertLess(final_hostname, success)

    def test_standard_anchor_selection_is_byte_or_nss_trust_based(self) -> None:
        verifier = function_body(read(CERT_VERIFIER), "Result CertVerifier::VerifyCert(")
        tls_server_case = verifier[verifier.index("case VerifyUsage::TLSServer:") :]
        self.assertIn("NSSCertDBTrustDomain trustDomain(\n            trustSSL,", tls_server_case)
        self.assertIn("BuildCertChainForOneKeyUsage(", tls_server_case)

        get_trust = function_body(
            read(TRUST_DOMAIN), "Result NSSCertDBTrustDomain::GetCertTrust("
        )
        assert_in_order(
            self,
            get_trust,
            "InputsAreEqual(candidateCertDER, thirdPartyRootInput)",
            "trustLevel = TrustLevel::TrustAnchor;",
        )
        assert_in_order(
            self,
            get_trust,
            "InputsAreEqual(candidateCertDER, thirdPartyIntermediateInput)",
            "trustLevel = TrustLevel::InheritsTrust;",
        )
        self.assertIn("CERT_GetCertTrust(candidateCert.get(), &trust)", get_trust)
        self.assertIn("if (flags & CERTDB_TRUSTED_CA)", get_trust)

    def test_selected_hook_sees_security_relevant_failure_taxonomy(self) -> None:
        result_map = read(PKIX_RESULTS)
        normalized_result_map = result_map.replace("\\\n", " ")
        expected_mappings = {
            "ERROR_UNKNOWN_ISSUER": "SEC_ERROR_UNKNOWN_ISSUER",
            "ERROR_BAD_CERT_DOMAIN": "SSL_ERROR_BAD_CERT_DOMAIN",
            "ERROR_EXPIRED_CERTIFICATE": "SEC_ERROR_EXPIRED_CERTIFICATE",
            "ERROR_NOT_YET_VALID_CERTIFICATE":
                "MOZILLA_PKIX_ERROR_NOT_YET_VALID_CERTIFICATE",
            "ERROR_BAD_SIGNATURE": "SEC_ERROR_BAD_SIGNATURE",
            "ERROR_INADEQUATE_KEY_USAGE": "SEC_ERROR_INADEQUATE_KEY_USAGE",
            "ERROR_CA_CERT_INVALID": "SEC_ERROR_CA_CERT_INVALID",
            "ERROR_CERT_NOT_IN_NAME_SPACE": "SEC_ERROR_CERT_NOT_IN_NAME_SPACE",
            "ERROR_PATH_LEN_CONSTRAINT_INVALID":
                "SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID",
            "ERROR_REVOKED_CERTIFICATE": "SEC_ERROR_REVOKED_CERTIFICATE",
        }
        for result, nss_error in expected_mappings.items():
            pattern = re.compile(
                rf"MOZILLA_PKIX_MAP\(\s*{result},\s*[^,]+,\s*{nss_error}\s*\)",
                re.MULTILINE,
            )
            self.assertRegex(normalized_result_map, pattern, result)

        run = function_body(
            read(SSL_VERIFICATION), "SSLServerCertVerificationJob::Run()"
        )
        assert_in_order(
            self,
            run,
            "Result result = AuthCertificate(",
            "if (result == Success)",
            "PRErrorCode error = MapResultToPRErrorCode(result);",
            "PRErrorCode finalError = ResolveGoodBearCertificateOverride(",
            "goodBearOrdinaryClassification, startedInGoodBearManagedContainer, result,",
            "return AuthCertificateParseResults(",
        )
        policy = function_body(
            read(FIREFOX / "security/manager/ssl/GoodBearRussianPKIContainerScope.h"),
            "ResolveGoodBearCertificateOverride(",
        )
        self.assertIn("GoodBearOrdinaryClassificationAllowsCertificateOverrides(", policy)
        self.assertIn("aStartedInManagedContainer", policy)
        self.assertIn("IsGoodBearRussianPKISecondaryVerificationEligible(", policy)

    def test_selected_hook_is_before_tls_application_data_release(self) -> None:
        ssl_source = read(SSL_VERIFICATION)
        auth_hook = function_body(ssl_source, "SECStatus AuthCertificateHook(")
        assert_in_order(
            self,
            auth_hook,
            "socketInfo->SetCertVerificationWaiting();",
            "rv = AuthCertificateHookInternal(",
            "return rv;",
        )

        dispatch = function_body(
            ssl_source, "SECStatus SSLServerCertVerificationJob::Dispatch("
        )
        assert_in_order(
            self,
            dispatch,
            "gCertVerificationThreadPool->Dispatch(job, NS_DISPATCH_NORMAL)",
            "PR_SetError(PR_WOULD_BLOCK_ERROR, 0);",
            "return SECWouldBlock;",
        )

        verification_run = function_body(
            ssl_source, "SSLServerCertVerificationJob::Run()"
        )
        self.assertNotIn("SSL_AuthCertificateComplete", verification_run)
        result_run = function_body(
            ssl_source, "SSLServerCertVerificationResult::Run()"
        )
        assert_in_order(
            self,
            result_run,
            "mSocketControl->SetHandshakeCertificates(",
            "mSocketControl->SetCertVerificationResult(mFinalError);",
        )

        completion = function_body(
            read(SOCKET_CONTROL), "NSSSocketControl::SetCertVerificationResult("
        )
        self.assertIn("mCertVerificationState == WaitingForCertVerification", completion)
        self.assertIn("SSL_AuthCertificateComplete(mFd, errorCode)", completion)
        self.assertIn("SetCanceled(errorCode);", completion)

    def test_transport_security_result_has_one_immutable_owner(self) -> None:
        getter = function_body(
            read(COMMON_SOCKET_CONTROL), "CommonSocketControl::GetSecurityInfo("
        )
        self.assertIn("new psm::TransportSecurityInfo(", getter)
        self.assertIn("mSecurityState, mErrorCode, mHandshakeCertificates.Clone()", getter)
        self.assertIn("mServerCert, mSucceededCertChain.Clone()", getter)

        transport_header = read(TRANSPORT_SECURITY_INFO)
        self.assertIn("const uint32_t mSecurityState;", transport_header)
        self.assertIn("const PRErrorCode mErrorCode;", transport_header)
        self.assertIn("const nsTArray<RefPtr<nsIX509Cert>> mHandshakeCertificates;", transport_header)
        self.assertIn("const nsTArray<RefPtr<nsIX509Cert>> mSucceededCertChain;", transport_header)


if __name__ == "__main__":
    unittest.main()
