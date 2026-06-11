package server

import (
	"testing"

	"natcat/internal/core"
)

func TestChangedKeepAliveAgesOnlyReturnsChangedSeconds(t *testing.T) {
	last := map[string]int64{}
	first := changedKeepAliveAges(last, []core.KeepAliveAgeEvent{{ID: "a", ConnectedSeconds: 0}})
	if len(first) != 1 || first[0].ConnectedSeconds != 0 {
		t.Fatalf("first update = %#v, want initial zero", first)
	}

	repeated := changedKeepAliveAges(last, []core.KeepAliveAgeEvent{{ID: "a", ConnectedSeconds: 0}})
	if len(repeated) != 0 {
		t.Fatalf("repeated update = %#v, want none", repeated)
	}

	changed := changedKeepAliveAges(last, []core.KeepAliveAgeEvent{{ID: "a", ConnectedSeconds: 1}})
	if len(changed) != 1 || changed[0].ConnectedSeconds != 1 {
		t.Fatalf("changed update = %#v, want second 1", changed)
	}
}

func TestChangedKeepAliveAgesDropsMissingInstances(t *testing.T) {
	last := map[string]int64{"a": 3}

	changed := changedKeepAliveAges(last, nil)
	if len(changed) != 0 {
		t.Fatalf("missing update = %#v, want none", changed)
	}
	if _, ok := last["a"]; ok {
		t.Fatalf("last still contains dropped instance: %#v", last)
	}
}
