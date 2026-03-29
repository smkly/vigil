package main

import "testing"

func TestClampedCursor(t *testing.T) {
	m := model{cursor: 10}
	if got := m.clampedCursor(3); got != 2 {
		t.Fatalf("expected cursor to clamp to last item, got %d", got)
	}

	m.cursor = -1
	if got := m.clampedCursor(3); got != 0 {
		t.Fatalf("expected negative cursor to clamp to zero, got %d", got)
	}

	if got := m.clampedCursor(0); got != 0 {
		t.Fatalf("expected empty list cursor to be zero, got %d", got)
	}
}

func TestVisibleRange(t *testing.T) {
	tests := []struct {
		name      string
		cursor    int
		length    int
		maxShow   int
		wantStart int
		wantEnd   int
	}{
		{name: "empty", cursor: 0, length: 0, maxShow: 5, wantStart: 0, wantEnd: 0},
		{name: "fits on screen", cursor: 1, length: 3, maxShow: 5, wantStart: 0, wantEnd: 3},
		{name: "scrolls down", cursor: 6, length: 10, maxShow: 5, wantStart: 2, wantEnd: 7},
		{name: "clamps near end", cursor: 9, length: 10, maxShow: 5, wantStart: 5, wantEnd: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end := visibleRange(tt.cursor, tt.length, tt.maxShow)
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("visibleRange(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tt.cursor, tt.length, tt.maxShow, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}
