#!/usr/bin/env python3
"""Execute the production TLS-cache record parser with small storage adapters.

This checks the actual serializer, parser and metadata clone, not NSS, Gecko
socket lifecycle, Brotli, persistence or TLS acceptance. Native cache gtests
and the real resumed-channel xpcshell fixture remain separate requirements.
"""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE, TOOLCHAIN


def definition(text, signature):
    """Extract a complete, balanced production definition without rewriting it."""
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 1
    position = opening + 1
    while depth:
        depth += (text[position] == "{") - (text[position] == "}")
        position += 1
    return text[start:position]


ADAPTERS = r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// Container/enum adapters only. All byte layout and acceptance decisions below
// are extracted unchanged from the pinned production source.
template <class T> class nsTArray : public std::vector<T> {
 public:
  using std::vector<T>::vector;
  size_t Length() const { return this->size(); }
  bool IsEmpty() const { return this->empty(); }
  T* Elements() { return this->data(); }
  const T* Elements() const { return this->data(); }
  nsTArray Clone() const { return *this; }
  void AppendElement(T value) { this->push_back(std::move(value)); }
  void AppendElements(const T* values, size_t count) {
    if (count) this->insert(this->end(), values, values + count);
  }
  bool SetLength(size_t length, int) { this->resize(length); return true; }
};
template <class T> class Maybe : public std::optional<T> {
 public:
  using std::optional<T>::optional;
  using std::optional<T>::operator=;
  bool isNothing() const { return !this->has_value(); }
  bool isSome() const { return this->has_value(); }
  template<class F> auto map(F function) const {
    using U = decltype(function(**this));
    return this->has_value() ? Maybe<U>(function(**this)) : Maybe<U>();
  }
};
template<class T> Maybe<std::decay_t<T>> Some(T&& value) {
  return Maybe<std::decay_t<T>>(std::forward<T>(value));
}
inline std::nullopt_t Nothing() { return std::nullopt; }
template<class T> class Span {
  T* data;
  size_t size;
 public:
  Span(T* values, size_t length) : data(values), size(length) {}
  size_t Length() const { return size; }
  T* Elements() const { return data; }
  T& operator[](size_t index) const { return data[index]; }
};
template<class T, class F> auto TransformIntoNewArray(const nsTArray<T>& in, F f) {
  nsTArray<decltype(f(std::declval<T>()))> out;
  for (const auto& value : in) out.AppendElement(f(value));
  return out;
}
template<class T, class U> T AssertedCast(U value) {
  assert(static_cast<U>(static_cast<T>(value)) == value);
  return static_cast<T>(value);
}
namespace mozilla {
struct NativeEndian {
  template<class T> static T swapToLittleEndian(T value) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
    return value;
  }
  template<class T> static T swapFromLittleEndian(T value) {
    return swapToLittleEndian(value);
  }
};
}
namespace psm { enum class EVStatus { NotEV, EV }; }
struct nsITransportSecurityInfo {
  static constexpr uint16_t CERTIFICATE_TRANSPARENCY_NOT_APPLICABLE = 0;
  enum class GoodBearTrustDomain : uint8_t { Invalid = 0, Standard = 1, RussianPKI = 2 };
  enum class OverridableErrorCategory : uint8_t { ERROR_UNSET, ERROR_TRUST };
};
constexpr int fallible = 0;
#define MOZ_RELEASE_ASSERT(condition) assert(condition)
"""


HARNESS = r"""
using TrustDomain = nsITransportSecurityInfo::GoodBearTrustDomain;

static bool Decode(const nsTArray<uint8_t>& bytes, SessionCacheInfo& output) {
  nsTArray<uint8_t> token;
  return DeserializeRecord({bytes.Elements(), bytes.Length()}, token, output);
}

int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string scenario = argv[1];
  const uint8_t token[] = {1, 2, 3, 4};
  SessionCacheInfo original;
  original.mGoodBearTrustDomain = Some(TrustDomain::Standard);
  original.mServerCertBytes = {0x30, 0x81, 0x42};
  original.mSucceededCertChainBytes = Some(nsTArray<nsTArray<uint8_t>>{
      original.mServerCertBytes, {0x30, 0x10, 0x11}});
  original.mHandshakeCertificatesBytes = original.mSucceededCertChainBytes;
  original.mIsBuiltCertChainRootBuiltInRoot = Some(true);
  original.mEVStatus = psm::EVStatus::EV;
  original.mCertificateTransparencyStatus = 2;

  if (scenario == "roundtrip") {
    for (auto domain : {TrustDomain::Standard, TrustDomain::Invalid}) {
      original.mGoodBearTrustDomain = Some(domain);
      original.mOverridableErrorCategory = domain == TrustDomain::Invalid
          ? nsITransportSecurityInfo::OverridableErrorCategory::ERROR_TRUST
          : nsITransportSecurityInfo::OverridableErrorCategory::ERROR_UNSET;
      auto clone = original.Clone();
      assert(clone.mGoodBearTrustDomain && *clone.mGoodBearTrustDomain == domain);
      auto encoded = SerializeRecord({token, sizeof(token)}, clone);
      SessionCacheInfo decoded;
      nsTArray<uint8_t> decodedToken;
      assert(DeserializeRecord({encoded.Elements(), encoded.Length()},
                               decodedToken, decoded));
      assert(decodedToken == nsTArray<uint8_t>({1, 2, 3, 4}));
      assert(decoded.mGoodBearTrustDomain && *decoded.mGoodBearTrustDomain == domain);
      assert(decoded.mOverridableErrorCategory == original.mOverridableErrorCategory);
      assert(decoded.mEVStatus == original.mEVStatus);
      assert(decoded.mCertificateTransparencyStatus == original.mCertificateTransparencyStatus);
      assert(decoded.mServerCertBytes == original.mServerCertBytes);
      assert(*decoded.mSucceededCertChainBytes == *original.mSucceededCertChainBytes);
      assert(*decoded.mHandshakeCertificatesBytes == *original.mHandshakeCertificatesBytes);
      assert(*decoded.mIsBuiltCertChainRootBuiltInRoot);
    }
  } else if (scenario == "unusable_types") {
    for (auto domain : {TrustDomain::RussianPKI, static_cast<TrustDomain>(0xff)}) {
      original.mGoodBearTrustDomain = Some(domain);
      auto encoded = SerializeRecord({token, sizeof(token)}, original);
      SessionCacheInfo decoded;
      assert(!Decode(encoded, decoded));
    }
    original.mGoodBearTrustDomain = Nothing();
    assert(!original.Clone().mGoodBearTrustDomain);
    auto encoded = SerializeRecord({token, sizeof(token)}, original);
    SessionCacheInfo decoded;
    assert(!Decode(encoded, decoded));
  } else if (scenario == "legacy_and_corruption") {
    const auto valid = SerializeRecord({token, sizeof(token)}, original);
    SessionCacheInfo decoded;
    assert(Decode(valid, decoded));
    // This includes the exact legacy record without the five-byte trailer,
    // and a versioned record whose domain byte is missing.
    for (size_t length = 0; length < valid.Length(); ++length) {
      auto truncated = valid.Clone();
      truncated.resize(length);
      assert(!Decode(truncated, decoded));
    }
    auto future = valid.Clone();
    future[future.Length() - 5] = 0xff;
    assert(!Decode(future, decoded));
    auto extra = valid.Clone();
    extra.AppendElement(0);
    assert(!Decode(extra, decoded));
  } else {
    return 2;
  }
  std::cout << scenario << ": production record parser assertions passed\n";
}
"""


class M1304TypedCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        header = (SOURCE / "netwerk/base/SSLTokensCache.h").read_text()
        implementation = (SOURCE / "netwerk/base/SSLTokensCache.cpp").read_text()
        declarations = definition(header, "struct SessionCacheInfo {") + ";\n"
        for name in ("kGoodBearCacheMetadataVersion", "kMaxTokenSize", "kMaxCertSize"):
            match = re.search(rf"^static constexpr uint32_t {name} = [^;]+;", implementation, re.M)
            if not match:
                raise AssertionError(f"production typed-cache constant absent: {name}")
            declarations += match[0] + "\n"
        for signature in (
            "static nsTArray<nsTArray<uint8_t>> CloneCertChain(",
            "SessionCacheInfo SessionCacheInfo::Clone() const",
            "template <typename T>\nstatic void AppendLE(",
            "static nsTArray<uint8_t> SerializeRecord(",
            "struct PayloadReader {",
            "static bool DeserializeRecord(",
        ):
            declarations += definition(implementation, signature)
            declarations += ";\n" if signature.startswith("struct ") else "\n"
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        harness = directory / "typed_cache.cpp"
        harness.write_text(ADAPTERS + declarations + HARNESS)
        cls.binary = directory / "typed_cache"
        result = subprocess.run(
            [str(TOOLCHAIN / "llvm/bin/clang++"), "-std=c++17", "-O2",
             "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_standard_and_invalid_roundtrip_and_clone(self):
        self.run_scenario("roundtrip")

    def test_untyped_unknown_and_russian_metadata_are_rejected(self):
        self.run_scenario("unusable_types")

    def test_legacy_truncated_future_version_and_trailing_bytes_are_rejected(self):
        self.run_scenario("legacy_and_corruption")


if __name__ == "__main__":
    unittest.main()
