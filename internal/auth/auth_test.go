package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		wantKey   string
		wantErr   error  // for sentinel errors
		errSubstr string // for non-sentinel errors (like "malformed ...")
	}{
		{
			name:      "missing header returns ErrNoAuthHeaderIncluded",
			headerVal: "",
			wantKey:   "",
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong scheme returns malformed error",
			headerVal: "Bearer abc123",
			wantKey:   "",
			errSubstr: "malformed authorization header",
		},
		{
			name:      "no key part returns malformed error",
			headerVal: "ApiKey",
			wantKey:   "",
			errSubstr: "malformed authorization header",
		},
		{
			name:      "api key extracted",
			headerVal: "ApiKey abc123",
			wantKey:   "abc123",
		},
		{
			name:      "extra parts still returns second token as key",
			headerVal: "ApiKey abc123 ignored",
			wantKey:   "abc123",
		},
		{
			name:      "case sensitive scheme check fails",
			headerVal: "apikey abc123",
			wantKey:   "",
			errSubstr: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range var
		t.Run(tt.name, func(t *testing.T) {
			h := make(http.Header)
			if tt.headerVal != "" {
				h.Set("Authorization", tt.headerVal)
			}

			gotKey, err := GetAPIKey(h)

			if gotKey != tt.wantKey {
				t.Fatalf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			// Sentinel error check (your exported ErrNoAuthHeaderIncluded)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("GetAPIKey() err = %v, want %v", err, tt.wantErr)
				}
				return
			}

			// Substring check for the non-sentinel malformed error
			if tt.errSubstr != "" {
				if err == nil {
					t.Fatalf("GetAPIKey() err = nil, want error containing %q", tt.errSubstr)
				}
				if err.Error() != tt.errSubstr {
					t.Fatalf("GetAPIKey() err = %q, want %q", err.Error(), tt.errSubstr)
				}
				return
			}

			// Success case: expect nil error
			if err != nil {
				t.Fatalf("GetAPIKey() err = %v, want nil", err)
			}
		})
	}
}
