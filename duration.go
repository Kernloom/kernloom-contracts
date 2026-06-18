// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package contracts

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration serializes as a Go duration string, for example "30s" or "10m".
type Duration struct {
	time.Duration
}

func NewDuration(d time.Duration) Duration {
	return Duration{Duration: d}
}

func (d Duration) IsZero() bool {
	return d.Duration == 0
}

func (d Duration) MarshalJSON() ([]byte, error) {
	if d.Duration == 0 {
		return []byte(`"0s"`), nil
	}
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}
