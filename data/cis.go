package data

import _ "embed"

//go:embed cis_audit_families.json
var cisAuditFamiliesJSON string

// CISAuditFamiliesJSON returns the embedded ordered classifier rules for the
// Linux Audit event families covered by CIS server audit recommendations.
func CISAuditFamiliesJSON() string {
	return cisAuditFamiliesJSON
}
