package proxy

import "testing"

func TestParseListMailbox(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"* LIST (\\HasNoChildren) \"/\" INBOX\r\n", "INBOX", true},
		{"* LIST () \".\" \"Sent Items\"\r\n", "Sent Items", true},
		{"* LSUB () NIL Drafts\r\n", "Drafts", true},
		{"* LIST () \"\\\\\" \"a\\\"b\"\r\n", "a\"b", true},
		{"* LIST () \"/\" {6}\r\nSecret\r\n", "Secret", true},
		{"* LIST () \"/\" \"Secret\" (\"CHILDINFO\" (\"SUBSCRIBED\"))\r\n", "", false},
		{"* LIST \"/\" Secret\r\n", "", false},
		{"* LIST () \"/\" \"unterminated\r\n", "", false},
	}
	for _, tt := range tests {
		got, ok := parseListMailbox([]byte(tt.in))
		if ok != tt.ok || got != tt.want {
			t.Errorf("%q: got (%q,%v) want (%q,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
