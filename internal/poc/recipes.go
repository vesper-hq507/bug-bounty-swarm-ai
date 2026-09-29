package poc

import "strings"

// Recipe is the class-specific knowledge that makes a proof-of-concept actually
// trigger while staying safe. A generic "write a PoC" prompt produces
// plausible-looking code; a recipe tells the model exactly what benign signal
// proves THIS class of bug and what a successful run should look like.
type Recipe struct {
	Class     string // canonical attack class
	SafeProof string // the benign demonstration technique for this class
	Indicator string // what a successful, safe proof looks like in the output
	Hints     string // structural guidance for the generated script
}

// recipeFor picks the proof recipe for a finding from its attack category,
// title and description. Falls back to a generic-but-safe recipe.
func recipeFor(attackCategory, title, description string) Recipe {
	t := strings.ToLower(attackCategory + " " + title + " " + description)
	switch {
	case has(t, "bola", "idor", "object-level", "object level", "broken object"):
		return Recipe{
			Class:     "bola",
			SafeProof: "Authenticate as user A, note an object id A owns, then request the SAME endpoint with a DIFFERENT id belonging to user B. Prove access by showing B's object is returned to A. Fetch exactly ONE other object — never enumerate or bulk-pull.",
			Indicator: "A 200 response for an object the authenticated user does not own, with a field (email/owner/id) that clearly belongs to a different user.",
			Hints:     "Two identities may be needed; if only one is available, show that an id you do not own still returns data. Print the mismatched owner field as the proof.",
		}
	case has(t, "sqli", "sql injection"):
		return Recipe{
			Class:     "sqli",
			SafeProof: "Prove injectability with a BENIGN, read-only signal only: a boolean-based true/false differential, or extract a single harmless value like the DB version or current_user. NEVER read application/user tables, NEVER write, NEVER stack destructive statements.",
			Indicator: "A response difference between a true and false condition, or a printed DB version / current-user string.",
			Hints:     "Prefer a boolean/time-independent differential. If extracting, limit to version()/current_user. No UNION dumps of real tables.",
		}
	case has(t, "xss", "cross-site scripting", "cross site scripting"):
		return Recipe{
			Class:     "xss",
			SafeProof: "Inject a UNIQUE, HARMLESS marker (e.g. a random string inside a benign tag) and show it is reflected UNSANITIZED in the response HTML/JS context. Do NOT use alert()/cookie theft/keyloggers — a reflected inert marker in an executable context is sufficient proof.",
			Indicator: "The unique marker appears unencoded inside an HTML/JS execution context in the response.",
			Hints:     "Generate a random marker per run. Check the marker is present AND not HTML-entity-encoded.",
		}
	case has(t, "ssrf", "server-side request", "server side request", "metadata"):
		return Recipe{
			Class:     "ssrf",
			SafeProof: "Show the server makes a request to an attacker-controlled or internal address it should not. Prove with a BENIGN internal fetch (e.g. a metadata endpoint's top-level index, or a callback to a listener you print) — do NOT retrieve cloud credentials or secrets; stopping at proof of the outbound request is enough.",
			Indicator: "Evidence the server fetched an internal/attacker URL (a distinctive internal response body, or a logged callback).",
			Hints:     "If demonstrating cloud metadata reachability, fetch only the non-sensitive index path, never credential paths.",
		}
	case has(t, "rce", "remote code", "command injection", "deserial"):
		return Recipe{
			Class:     "rce",
			SafeProof: "Prove code execution with a HARMLESS command only: `id`, `whoami`, or echo of a unique token. NEVER read sensitive files, write files, open shells, install anything, or run destructive commands.",
			Indicator: "The output of `id`/`whoami` or the unique echoed token appears in the response.",
			Hints:     "Echo a random token and confirm it round-trips, or capture the `id` output. Nothing beyond a benign command.",
		}
	case has(t, "auth", "jwt", "token", "session", "login", "bypass"):
		return Recipe{
			Class:     "auth-bypass",
			SafeProof: "Demonstrate the auth weakness with a benign forged/altered credential (e.g. an alg:none JWT, or a tampered claim) and show it grants access to a protected endpoint that should reject it. Access ONE protected resource as proof — do not act on it.",
			Indicator: "A protected endpoint returns 200 / authorized data for a request that should have been rejected.",
			Hints:     "Construct the minimal forged token in-script (stdlib base64/json). Prove access, then stop.",
		}
	case has(t, "traversal", "lfi", "path traversal", "directory traversal"):
		return Recipe{
			Class:     "path-traversal",
			SafeProof: "Prove traversal by reading a WELL-KNOWN, NON-SENSITIVE file (e.g. /etc/hostname or a public static file outside the intended dir). NEVER read secrets, keys, /etc/shadow, or app config with credentials.",
			Indicator: "Content of a benign out-of-scope-directory file appears in the response.",
			Hints:     "Target the most harmless file that still proves traversal.",
		}
	case has(t, "secret", "leak", "exposure", "exposed", "disclosure", "api key"):
		return Recipe{
			Class:     "secret-leak",
			SafeProof: "Show the secret/token is reachable at the exposed location, but prove it by its SHAPE (a redacted prefix + length + entropy), NOT by exfiltrating or using it. Print only enough to prove it is a live secret.",
			Indicator: "A response contains a value matching a secret pattern (key/token) at an endpoint that should not expose it.",
			Hints:     "Redact the secret in output: show first 4 chars + length. Do not use the secret against any service.",
		}
	default:
		return Recipe{
			Class:     "generic",
			SafeProof: "Demonstrate the vulnerability with the most benign signal that proves it exists, without destroying or modifying data, exfiltrating at scale, or disrupting the service.",
			Indicator: "A response or behavior that unambiguously proves the described vulnerability, safely.",
			Hints:     "Keep it minimal, read-only, and reproducible.",
		}
	}
}
