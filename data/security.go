package data

import _ "embed"

//go:embed security_event_families.json
var securityEventFamiliesJSON string

// SecurityEventFamiliesJSON returns the embedded mappings for portable Linux
// Audit security event families outside the CIS rule-oriented classifier.
func SecurityEventFamiliesJSON() string {
	return securityEventFamiliesJSON
}
