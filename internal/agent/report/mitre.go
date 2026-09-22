package report

// mitreTechniqueNames maps the ATT&CK technique IDs the swarm commonly emits to
// their names, so the report reads as a real ATT&CK mapping. Unknown IDs render
// as the bare ID.
var mitreTechniqueNames = map[string]string{
	"T1190": "Exploit Public-Facing Application",
	"T1210": "Exploitation of Remote Services",
	"T1212": "Exploitation for Credential Access",
	"T1068": "Exploitation for Privilege Escalation",
	"T1078": "Valid Accounts",
	"T1552": "Unsecured Credentials",
	"T1550": "Use Alternate Authentication Material",
	"T1539": "Steal Web Session Cookie",
	"T1548": "Abuse Elevation Control Mechanism",
	"T1213": "Data from Information Repositories",
	"T1071": "Application Layer Protocol",
	"T1567": "Exfiltration Over Web Service",
	"T1005": "Data from Local System",
	"T1580": "Cloud Infrastructure Discovery",
	"T1528": "Steal Application Access Token",
	"T1098": "Account Manipulation",
}

// mitreLabel returns "T1190 — Exploit Public-Facing Application" when the ID is
// known, otherwise just the ID.
func mitreLabel(id string) string {
	if name, ok := mitreTechniqueNames[id]; ok {
		return id + " — " + name
	}
	return id
}
