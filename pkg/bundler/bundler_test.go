package bundler

import (
	"reflect"
	"strings"
	"testing"
)

// TestMergeEnv_OverridesDefault verifies that a user-supplied override
// for a default key replaces the default in place — not appended as a
// second instance that would shadow it nondeterministically at the
// runtime level.
func TestMergeEnv_OverridesDefault(t *testing.T) {
	got := mergeEnv(
		[]string{"PATH=/usr/bin", "TERM=xterm"},
		map[string]string{"PATH": "/opt/bin"},
	)
	want := []string{"PATH=/opt/bin", "TERM=xterm"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("override-in-place\n got=%v\nwant=%v", got, want)
	}
}

// TestMergeEnv_AppendsNewKeysSorted confirms that overrides that don't
// shadow a default land at the tail in sorted order, so two callers
// passing the same map (even with different Go-internal hash seeds)
// produce identical config.json bytes.
func TestMergeEnv_AppendsNewKeysSorted(t *testing.T) {
	got := mergeEnv(
		[]string{"PATH=/usr/bin"},
		map[string]string{"ZETA": "z", "ALPHA": "a", "MIDDLE": "m"},
	)
	want := []string{"PATH=/usr/bin", "ALPHA=a", "MIDDLE=m", "ZETA=z"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sorted append\n got=%v\nwant=%v", got, want)
	}
}

// TestMergeEnv_Deterministic spot-checks that mergeEnv produces the
// same output for two calls with the same inputs — the property the
// previous append-on-map-range code did NOT have. Reseed-resistant
// because mergeEnv sorts.
func TestMergeEnv_Deterministic(t *testing.T) {
	defaults := []string{"PATH=/usr/bin", "TERM=xterm"}
	overrides := map[string]string{
		"A": "1", "B": "2", "C": "3", "D": "4", "E": "5",
		"F": "6", "G": "7", "H": "8", "I": "9", "J": "10",
	}
	first := mergeEnv(defaults, overrides)
	for i := 0; i < 20; i++ {
		again := mergeEnv(defaults, overrides)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("non-deterministic on attempt %d :\n %v\nvs\n %v", i, first, again)
		}
	}
}

// TestMergeEnv_PreservesMalformedDefault keeps the contract that an
// entry without an `=` in defaults survives unchanged — defensive in
// case a future caller adds a malformed default that the merge
// shouldn't silently swallow.
func TestMergeEnv_PreservesMalformedDefault(t *testing.T) {
	got := mergeEnv(
		[]string{"bareword", "PATH=/usr/bin"},
		map[string]string{"PATH": "/x"},
	)
	want := []string{"bareword", "PATH=/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("malformed-default preservation\n got=%v\nwant=%v", got, want)
	}
}

// TestMergeEnv_EmptyOverridesIsIdentity guards the obvious base case :
// passing a nil/empty override map returns the defaults unchanged.
func TestMergeEnv_EmptyOverridesIsIdentity(t *testing.T) {
	defaults := []string{"PATH=/usr/bin", "TERM=xterm"}
	if got := mergeEnv(defaults, nil); !reflect.DeepEqual(got, defaults) {
		t.Errorf("nil overrides\n got=%v\nwant=%v", got, defaults)
	}
	if got := mergeEnv(defaults, map[string]string{}); !reflect.DeepEqual(got, defaults) {
		t.Errorf("empty overrides\n got=%v\nwant=%v", got, defaults)
	}
}

// TestMergeEnv_OverridesAreDeterministicVsNaiveAppend is the
// regression proof : a deliberately-pathological input (many keys
// that all shadow nothing, exercising the worst case of the old
// for-range append code) still produces sorted output.
func TestMergeEnv_OverridesAreDeterministicVsNaiveAppend(t *testing.T) {
	overrides := map[string]string{}
	for c := 'a'; c <= 'z'; c++ {
		overrides[string(c)] = string(c)
	}
	got := mergeEnv(nil, overrides)
	// Last 26 entries must be a-z in order.
	prev := ""
	for _, kv := range got {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed entry %q", kv)
		}
		if k <= prev {
			t.Fatalf("non-sorted: %q after %q", k, prev)
		}
		prev = k
	}
}
