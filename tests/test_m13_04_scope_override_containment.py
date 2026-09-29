#!/usr/bin/env python3
"""Execute the actual Good Bear policy headers without claiming Gecko runtime.

The compatibility headers below provide types only. Classification, scope
checks and the final-error policy come from the materialized Firefox owners.
Native gtests and whole-channel tests remain separate acceptance requirements.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE, TOOLCHAIN


TYPE_HEADERS = {
    "mozilla/FunctionRef.h": """
#pragma once
#include <functional>
namespace mozilla {
template <class Signature> using FunctionRef = std::function<Signature>;
}
""",
    "mozilla/Maybe.h": """
#pragma once
#include <optional>
namespace mozilla {
template <class T> class Maybe {
  std::optional<T> value;
 public:
  Maybe() = default;
  Maybe(T initial) : value(initial) {}
  bool isSome() const { return value.has_value(); }
  const T& ref() const { return value.value(); }
};
}
""",
    "mozilla/OriginAttributes.h": """
#pragma once
#include <cstdint>
namespace mozilla {
struct OriginAttributes {
  uint32_t mUserContextId = 0;
  uint32_t mPrivateBrowsingId = 0;
};
}
""",
    "mozpkix/Result.h": """
#pragma once
namespace mozilla::pkix {
enum class Result {
  SUCCESS, ERROR_UNKNOWN_ISSUER, ERROR_BAD_SIGNATURE,
  ERROR_EXPIRED_CERTIFICATE, FATAL_ERROR_INVALID_STATE
};
constexpr Result Success = Result::SUCCESS;
}
""",
    "nsIScriptSecurityManager.h": """
#pragma once
struct nsIScriptSecurityManager {
  static constexpr unsigned DEFAULT_USER_CONTEXT_ID = 0;
};
""",
    "nsITransportSecurityInfo.h": """
#pragma once
#include <cstdint>
struct nsITransportSecurityInfo {
  enum class GoodBearTrustDomain : uint8_t { Invalid, Standard, RussianPKI };
};
""",
    "prerror.h": """
#pragma once
#include <cstdint>
using PRErrorCode = int32_t;
""",
}

HARNESS = r"""
#include "GoodBearRussianPKIContainerScope.h"
#include <cassert>
#include <iostream>
#include <string>

using namespace mozilla;
using namespace mozilla::pkix;
using namespace mozilla::psm;

int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string scenario = argv[1];
  constexpr PRErrorCode originalError = -8179;
  bool overrideCalled = false;
  auto savedOverride = [&]() -> PRErrorCode {
    overrideCalled = true;
    return 0;
  };

  if (scenario == "scope_disable" || scenario == "scope_recreate" ||
      scenario == "before_alternate" || scenario == "alternate_failure") {
    GoodBearRussianPKIContainerScope scope{true, Maybe<uint32_t>(17U)};
    OriginAttributes attributes;
    attributes.mUserContextId = 17;
    const bool startedInManaged = scope.Allows(attributes);
    assert(startedInManaged);
    if (scenario == "before_alternate") {
      scope.mEnabled = false;
    }
    bool alternateCalled = false;
    auto result = ClassifyGoodBearContainerServerCertificate(
        Result::ERROR_UNKNOWN_ISSUER, attributes,
        [&](const OriginAttributes& candidate) { return scope.Allows(candidate); },
        [&]() {
          alternateCalled = true;
          if (scenario == "scope_recreate") {
            scope.mDedicatedUserContextId = Maybe<uint32_t>(23U);
          } else if (scenario == "scope_disable") {
            scope.mEnabled = false;
          }
          return scenario == "alternate_failure" ? Result::ERROR_BAD_SIGNATURE
                                                 : Success;
        });
    assert(alternateCalled == (scenario != "before_alternate"));
    assert(!result.ChannelUsable());
    assert(result.mResult == Result::ERROR_UNKNOWN_ISSUER);
    const PRErrorCode finalError = ResolveGoodBearCertificateOverride(
        GoodBearOrdinaryTrustClassification::Invalid, startedInManaged,
        result.mResult, originalError, savedOverride);
    assert(finalError == originalError);
    assert(!overrideCalled);
  } else if (scenario == "ordinary_saved" || scenario == "ordinary_unmatched") {
    auto ordinary = ClassifyGoodBearOrdinaryServerCertificate(
        Result::ERROR_UNKNOWN_ISSUER,
        []() { return Result::ERROR_BAD_SIGNATURE; });
    const PRErrorCode finalError = ResolveGoodBearCertificateOverride(
        ordinary.mClassification, false, ordinary.mOriginalResult,
        originalError, [&]() -> PRErrorCode {
          overrideCalled = true;
          return scenario == "ordinary_saved" ? 0 : originalError;
        });
    assert(overrideCalled);
    assert(finalError == (scenario == "ordinary_saved" ? 0 : originalError));
  } else if (scenario == "standard_success") {
    assert(ResolveGoodBearCertificateOverride(
               GoodBearOrdinaryTrustClassification::Standard, false, Success,
               0, savedOverride) == 0);
    assert(!overrideCalled);
  } else if (scenario == "russian_routing") {
    auto ordinary = ClassifyGoodBearOrdinaryServerCertificate(
        Result::ERROR_UNKNOWN_ISSUER, []() { return Success; });
    assert(ResolveGoodBearCertificateOverride(
               ordinary.mClassification, false, ordinary.mOriginalResult,
               originalError, savedOverride) == originalError);
    assert(!overrideCalled);
  } else if (scenario == "noneligible_standard") {
    for (bool managed : {false, true}) {
      overrideCalled = false;
      assert(ResolveGoodBearCertificateOverride(
                 GoodBearOrdinaryTrustClassification::Invalid, managed,
                 Result::ERROR_EXPIRED_CERTIFICATE, originalError,
                 savedOverride) == 0);
      assert(overrideCalled);
    }
  } else {
    return 2;
  }
  std::cout << scenario << ": actual-header policy assertions passed\n";
}
"""


class M1304ScopeOverrideContainmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        work = Path(cls.temporary.name)
        types = work / "types"
        for name, content in TYPE_HEADERS.items():
            path = types / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        harness = work / "policy.cpp"
        harness.write_text(HARNESS, encoding="utf-8")
        cls.executable = work / "policy"
        compiler = TOOLCHAIN / "llvm/bin/clang++"
        if not compiler.is_file():
            raise AssertionError("locked clang++ is required for the policy unit test")
        compiled = subprocess.run(
            [
                str(compiler), "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-I", str(SOURCE / "security/manager/ssl"), "-I", str(types),
                str(harness), "-o", str(cls.executable),
            ],
            check=False, capture_output=True, text=True, timeout=60,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def test_actual_policy_rejects_scope_override_escape_and_preserves_controls(self) -> None:
        for scenario in (
            "scope_disable", "scope_recreate", "before_alternate",
            "alternate_failure", "ordinary_saved", "ordinary_unmatched",
            "standard_success", "russian_routing", "noneligible_standard",
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [str(self.executable), scenario], check=False,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(scenario + ": actual-header policy assertions passed", result.stdout)

    def test_native_job_uses_the_same_policy_and_initial_scope_snapshot(self) -> None:
        source = (SOURCE / "security/manager/ssl/SSLServerCertVerification.cpp").read_text(
            encoding="utf-8"
        )
        snapshot = source.index("const uint64_t goodBearScopeLease =")
        ordinary_branch = source.index("!startedInGoodBearManagedContainer", snapshot)
        final_policy = source.index("PRErrorCode finalError = ResolveGoodBearCertificateOverride(")
        self.assertLess(snapshot, ordinary_branch)
        self.assertLess(ordinary_branch, final_policy)
        compact = "".join(source[snapshot:ordinary_branch].split())
        self.assertIn(
            "result!=Success?GetGoodBearRussianPKIScopeAuthority().CaptureLease(mOriginAttributes):0;",
            compact,
        )
        self.assertIn("startedInGoodBearManagedContainer = goodBearScopeLease != 0", source)
        resolution = source[final_policy : source.index("// NB: finalError may be 0", final_policy)]
        self.assertIn(
            "goodBearOrdinaryClassification, startedInGoodBearManagedContainer, result,",
            resolution,
        )
        self.assertIn("return AuthCertificateParseResults(", resolution)


if __name__ == "__main__":
    unittest.main()
