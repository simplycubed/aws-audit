package report

import (
	"strings"
	"testing"
)

func TestExporters(t *testing.T) {
	r := New("123456789012", "arn:aws:iam::123456789012:role/audit", "/tmp/dump")
	r.Add("HIGH", "Root account MFA disabled", "Enable hardware MFA on the root user.", "")
	r.Note("Regions scanned (1): eu-west-1")
	r.Errors = 2

	md := r.Markdown()
	for _, n := range []string{"Account 123456789012", "HIGH: Root account MFA disabled", "Permission / API Errors"} {
		if !strings.Contains(md, n) {
			t.Fatalf("markdown missing %q\n%s", n, md)
		}
	}
	csv, err := r.CSV()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csv, "aws,123456789012,HIGH,Root account MFA disabled") {
		t.Fatalf("csv: %s", csv)
	}
	js, err := r.JSONBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"cloud": "aws"`) {
		t.Fatalf("json: %s", js)
	}
	if !strings.Contains(string(js), `"account": "123456789012"`) {
		t.Fatalf("json account: %s", js)
	}
}
