#!/usr/bin/env bash
# Exercise incremental C builds without changing the working tree's artifacts.
set -euo pipefail

# Each case starts from the Makefile defaults, independent of caller overrides.
unset CC CPPFLAGS CFLAGS AR ARFLAGS DEBUG CROSS_COMPILE MAKEFLAGS MFLAGS MAKEOVERRIDES

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf -- "$test_dir"' EXIT
cp -- "$repo_dir/Makefile" "$repo_dir/"*.c "$repo_dir/"*.h "$test_dir/"
cd -- "$test_dir"

# Compare the old-header fallback with the build host's actual syscall ABI.
gcc -I. -x c -fsyntax-only - <<'EOF'
#include <sys/syscall.h>
#ifdef SYS_clone3
enum { native_clone3 = SYS_clone3 };
#undef SYS_clone3
#undef __NR_clone3
#include "graftcp.h"
_Static_assert(SYS_clone3 == native_clone3, "incorrect clone3 fallback");
#endif
EOF

artifacts=(graftcp.o util.o ptrace-ops.o cidr-trie.o cidr-trie_test.o
           libgraftcp.a cidr-trie_test)

build() {
    if ! make --no-print-directory -j2 VERSION=build-config-test \
        "$@" libgraftcp.a test-c > build.log 2>&1; then
        cat build.log >&2
        exit 1
    fi
}

check_build() {
    local expected="$1"
    shift
    local artifact before after should_change
    local -A timestamps
    for artifact in "${artifacts[@]}"; do
        timestamps["$artifact"]="$(stat -c '%y' "$artifact")"
    done
    build "$@"
    for artifact in "${artifacts[@]}"; do
        before="${timestamps[$artifact]}"
        after="$(stat -c '%y' "$artifact")"
        should_change=false
        if [[ "$expected" == all ||
              ( "$expected" == archive && "$artifact" == libgraftcp.a ) ]]; then
            should_change=true
        fi
        if { "$should_change" && [[ "$before" == "$after" ]]; } ||
           { ! "$should_change" && [[ "$before" != "$after" ]]; }; then
            echo "Unexpected rebuild state for $artifact: expected $expected ($*)" >&2
            cat build.log >&2
            exit 1
        fi
    done
}

build
check_build none
check_build all DEBUG=1
check_build none DEBUG=1
check_build all
check_build all 'CFLAGS=-Wall -MMD -MP -O1'
check_build none 'CFLAGS=-Wall -MMD -MP -O1'
check_build all
# Include literal quotes to exercise stamp serialization as well as rebuilding.
check_build all "CPPFLAGS=-DBUILD_CONFIG_TEST='1'"
check_build none "CPPFLAGS=-DBUILD_CONFIG_TEST='1'"
check_build all
check_build all "CC=$(command -v gcc)"
check_build none "CC=$(command -v gcc)"
check_build all
check_build archive "AR=$(command -v ar)"
check_build none "AR=$(command -v ar)"
check_build archive
check_build archive ARFLAGS=crs
check_build none ARFLAGS=crs
check_build archive
touch Makefile
check_build all
check_build none
make --no-print-directory clean > /dev/null
build
check_build none

# Independent Make processes check the same stamps even on a no-op build.
for round in {1..15}; do
    pids=()
    for job in {1..4}; do
        make --no-print-directory VERSION=build-config-test libgraftcp.a \
            > "concurrent-$job.log" 2>&1 &
        pids+=("$!")
    done
    failed=false
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed=true
        fi
    done
    if "$failed"; then
        echo "Concurrent Make failed in round $round" >&2
        cat concurrent-*.log >&2
        exit 1
    fi
done

# Use a dependency-free cgo package to exercise the actual Go test recipe.
unset GOFLAGS CGO_CPPFLAGS
mkdir -p local/cmd/mgraftcp 'graftcp review'
printf 'module build-config-test\n\ngo 1.25.0\n' > local/go.mod
printf '#define REVIEW_VALUE 42\n' > 'graftcp review/review.h'
cat > local/cmd/mgraftcp/main.go <<'GO'
package main

// #cgo LDFLAGS: -L${SRCDIR}/../../.. -lgraftcp
// #include <review.h>
import "C"

func reviewValue() int { return C.REVIEW_VALUE }
GO
cat > local/cmd/mgraftcp/main_test.go <<'GO'
package main

import (
	"os/exec"
	"testing"
)

func TestReviewValue(t *testing.T) {
	if got := reviewValue(); got != 42 {
		t.Fatalf("reviewValue() = %d, want 42", got)
	}
}

func TestCompileProbe(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "gcc", "-fsyntax-only", "testdata/probe.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile probe: %v\n%s", err, out)
	}
}
GO

mkdir -p local/cmd/mgraftcp/testdata
probe=local/cmd/mgraftcp/testdata/probe.c
printf 'int probe(void) { return 0; }\n' > "$probe"

export CGO_CPPFLAGS="\"-I$test_dir/graftcp review\""
make --no-print-directory VERSION=build-config-test test-go

printf '#error probe source changed\n' >> "$probe"
if make --no-print-directory VERSION=build-config-test test-go > build.log 2>&1 ||
   ! rg -q 'error: #error probe source changed' build.log; then
    echo 'Expected the changed C probe to fail compilation' >&2
    cat build.log >&2
    exit 1
fi
sed -i '/^#error/d' "$probe"

# Repeat with the same quoted flag stored only in GOENV.
export GOENV="$test_dir/goenv"
printf "CGO_CPPFLAGS=%s\n" "$CGO_CPPFLAGS" > "$GOENV"
unset CGO_CPPFLAGS
make --no-print-directory VERSION=build-config-test test-go

# Thin archives refer to external objects. Keep the member and symbol names
# fixed while changing the value that the Go test binary reads from C.
cat >> cidr-trie.c <<'C'

int review_value(void)
{
	return 42;
}
C
sed -i 's/#define REVIEW_VALUE 42/int review_value(void);/' 'graftcp review/review.h'
sed -i 's/C.REVIEW_VALUE/int(C.review_value())/' local/cmd/mgraftcp/main.go

make --no-print-directory VERSION=build-config-test ARFLAGS=rcsT test-go
cp libgraftcp.a thin-before.a
cp cidr-trie.o object-before.o
sed -i 's/return 42;/return 43;/' cidr-trie.c

if make --no-print-directory VERSION=build-config-test ARFLAGS=rcsT test-go > build.log 2>&1; then
    echo 'Go test reused the old C value after changing a thin archive member' >&2
    cat build.log >&2
    exit 1
fi
if ! cmp -s thin-before.a libgraftcp.a || cmp -s object-before.o cidr-trie.o ||
   ! rg -q 'reviewValue\(\) = 43, want 42' build.log; then
    echo 'Expected the updated object to change the test result with an identical thin archive' >&2
    cat build.log >&2
    exit 1
fi

echo 'Build configuration tests passed'
