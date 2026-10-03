package mobile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/evidence"
)

const (
	MaxCaptureBytes    = 32 << 20
	MaxTransactions    = 1000
	MaxTransactionBody = 256 << 10
)

type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
)

type Metadata struct {
	Platform      Platform
	AppID         string
	IdentityAlias string
	ActorRole     string
	SessionRef    string
}

type Capture struct {
	ID             string
	Platform       Platform
	AppID          string
	IdentityAlias  string
	ActorRole      string
	SessionRef     string
	Transactions   []Transaction
	Truncated      bool
	RedactionCount int
}

type Transaction struct {
	Sequence        int
	Method          string
	URL             string
	StatusCode      int
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
	RequestBody     []byte
	ResponseBody    []byte
}

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request struct {
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers []harHeader `json:"headers"`
		PostData struct {
			Text string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int         `json:"status"`
		Headers []harHeader `json:"headers"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func ParseHAR(data []byte, meta Metadata) (Capture, error) {
	if len(data) == 0 {
		return Capture{}, fmt.Errorf("HAR capture is empty")
	}
	if len(data) > MaxCaptureBytes {
		return Capture{}, fmt.Errorf("HAR capture exceeds %d bytes", MaxCaptureBytes)
	}
	if meta.Platform != PlatformAndroid && meta.Platform != PlatformIOS {
		return Capture{}, fmt.Errorf("mobile platform must be %q or %q", PlatformAndroid, PlatformIOS)
	}
	if strings.TrimSpace(meta.AppID) == "" {
		return Capture{}, fmt.Errorf("mobile app id is required")
	}
	if strings.TrimSpace(meta.IdentityAlias) == "" {
		return Capture{}, fmt.Errorf("mobile identity alias is required")
	}

	var raw harFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return Capture{}, fmt.Errorf("parse HAR: %w", err)
	}
	if len(raw.Log.Entries) == 0 {
		return Capture{}, fmt.Errorf("HAR contains no entries")
	}

	sum := sha256.Sum256(append(append([]byte(nil), data...), []byte("\x00"+meta.IdentityAlias)...))
	capture := Capture{
		ID: hex.EncodeToString(sum[:8]),
		Platform: meta.Platform,
		AppID: strings.TrimSpace(meta.AppID),
		IdentityAlias: strings.TrimSpace(meta.IdentityAlias),
		ActorRole: strings.TrimSpace(meta.ActorRole),
		SessionRef: strings.TrimSpace(meta.SessionRef),
	}

	limit := len(raw.Log.Entries)
	if limit > MaxTransactions {
		limit = MaxTransactions
		capture.Truncated = true
	}
	capture.Transactions = make([]Transaction, 0, limit)
	for i := 0; i < limit; i++ {
		entry := &raw.Log.Entries[i]
		method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		rawURL := strings.TrimSpace(entry.Request.URL)
		if rawURL == "" {
			continue
		}
		requestHeaders, requestRedactions := sanitizeHARHeaders(entry.Request.Headers)
		responseHeaders, responseRedactions := sanitizeHARHeaders(entry.Response.Headers)
		capture.RedactionCount += len(requestRedactions) + len(responseRedactions)

		responseBody, err := decodeHARBody(entry.Response.Content.Text, entry.Response.Content.Encoding)
		if err != nil {
			return Capture{}, fmt.Errorf("HAR entry %d response body: %w", i+1, err)
		}
		capture.Transactions = append(capture.Transactions, Transaction{
			Sequence: i + 1,
			Method: method,
			URL: rawURL,
			StatusCode: entry.Response.Status,
			RequestHeaders: requestHeaders,
			ResponseHeaders: responseHeaders,
			RequestBody: boundedBytes([]byte(entry.Request.PostData.Text)),
			ResponseBody: boundedBytes(responseBody),
		})
	}
	if len(capture.Transactions) == 0 {
		return Capture{}, fmt.Errorf("HAR contains no usable request entries")
	}
	return capture, nil
}

func sanitizeHARHeaders(headers []harHeader) (map[string]string, []evidence.Redaction) {
	h := make(http.Header)
	for i := range headers {
		if strings.TrimSpace(headers[i].Name) == "" {
			continue
		}
		h.Add(headers[i].Name, headers[i].Value)
	}
	return evidence.SanitizeHeaders(h)
}

func decodeHARBody(text, encoding string) ([]byte, error) {
	if !strings.EqualFold(strings.TrimSpace(encoding), "base64") {
		return boundedBytes([]byte(text)), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return boundedBytes(decoded), nil
}

func boundedBytes(in []byte) []byte {
	if len(in) > MaxTransactionBody {
		in = in[:MaxTransactionBody]
	}
	return append([]byte(nil), in...)
}
