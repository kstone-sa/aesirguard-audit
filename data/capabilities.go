package data

import _ "embed"

//go:embed capabilities.json
var linuxCapabilityNamesJSON string

// LinuxCapabilityNamesJSON returns the embedded ordered Linux capability
// names. Array indexes are capability bit numbers.
func LinuxCapabilityNamesJSON() string {
	return linuxCapabilityNamesJSON
}
