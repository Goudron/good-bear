#!/usr/bin/env python3
"""Execute the actual scope-lease header; this is not a Gecko packet test.

The cross-process case uses Linux mmap to exercise the production atomic
policy. Firefox's frozen shared-memory handle is covered by native gtests,
which must be executed separately in the freshly built browser.
"""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE, TOOLCHAIN


HARNESS = r"""
#include "GoodBearRussianPKIScopeLease.h"
#include <cassert>
#include <iostream>
#include <new>
#include <string>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

using State = mozilla::psm::GoodBearRussianPKIScopeLeaseState;

int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string scenario = argv[1];
  if (scenario == "policy") {
    State state;
    assert(state.Capture(17, false) == 0);
    assert(!state.Matches(0, 17, false));
    assert(state.Publish(17));
    const uint64_t lease = state.Capture(17, false);
    assert(lease && state.Matches(lease, 17, false));
    assert(!state.Matches(lease, 0, false));
    assert(!state.Matches(lease, 18, false));
    assert(!state.Matches(lease, 17, true));
    assert(state.Publish(17));
    assert(state.Matches(lease, 17, false));
    assert(!state.Publish(0));
    assert(!state.Matches(lease, 17, false));
    assert(state.Publish(17));
    assert(!state.Matches(lease, 17, false));
    const uint64_t recreated = state.Capture(17, false);
    assert(recreated && state.Matches(recreated, 17, false));
    assert(state.Publish(23));
    assert(!state.Matches(recreated, 17, false));
    assert(!state.Matches(recreated, 23, false));
    const uint64_t last = (uint64_t{UINT32_MAX - 1} << 32) | 17;
    assert(State::NextWord(last, 0) == State::kExhausted);
    assert(State::NextWord(last, 17) == State::kExhausted);
    assert(State::NextWord(State::kExhausted, 17) == State::kExhausted);
    assert(State::NextWord(State::kExhausted, 0) == State::kExhausted);
  } else if (scenario == "shared_reader") {
    const long pageSize = sysconf(_SC_PAGESIZE);
    assert(pageSize > 0);
    void* memory = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    assert(memory != MAP_FAILED);
    auto* writer = new (memory) State();
    assert(writer->Publish(17));
    const uint64_t oldLease = writer->Capture(17, false);
    int ready[2], resume[2];
    assert(pipe(ready) == 0 && pipe(resume) == 0);
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
      assert(mprotect(memory, pageSize, PROT_READ) == 0);
      const auto* reader = static_cast<const State*>(memory);
      assert(reader->Matches(oldLease, 17, false));
      char byte = 'r';
      assert(write(ready[1], &byte, 1) == 1);
      assert(read(resume[0], &byte, 1) == 1);
      // Parent has revoked, then recreated the SAME contextual identity.
      assert(!reader->Matches(oldLease, 17, false));
      const uint64_t current = reader->Capture(17, false);
      assert(current && current != oldLease);
      assert(reader->Matches(current, 17, false));
      assert(!reader->Matches(current, 17, true));
      _exit(0);
    }
    char byte;
    assert(read(ready[0], &byte, 1) == 1);
    assert(!writer->Publish(0));
    assert(writer->Publish(17));
    assert(write(resume[1], &byte, 1) == 1);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(munmap(memory, pageSize) == 0);
    for (int fd : {ready[0], ready[1], resume[0], resume[1]}) {
      close(fd);
    }
  } else {
    return 2;
  }
  std::cout << scenario << ": actual-header lease assertions passed\n";
}
"""


class M1304ScopeLeaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        owner = SOURCE / "security/manager/ssl/GoodBearRussianPKIScopeLease.h"
        if not owner.is_file():
            raise AssertionError(f"materialized scope lease owner is missing: {owner}")
        harness = directory / "scope_lease.cpp"
        harness.write_text(HARNESS, encoding="utf-8")
        cls.binary = directory / "scope_lease"
        result = subprocess.run(
            [str(TOOLCHAIN / "llvm/bin/clang++"), "-std=c++17", "-O2",
             "-Wall", "-Wextra", "-Werror", "-I", str(owner.parent),
             str(harness), "-o", str(cls.binary)],
            text=True, capture_output=True, timeout=60,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def test_actual_lease_policy_rejects_recreation_private_and_overflow(self):
        result = subprocess.run(
            [str(self.binary), "policy"], text=True, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_read_only_process_observes_revocation_before_recreated_scope(self):
        result = subprocess.run(
            [str(self.binary), "shared_reader"], text=True, capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
