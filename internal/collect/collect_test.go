package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simplycubed/aws-audit/internal/awsapi"
)

func testOpts(t *testing.T, fake *awsapi.Fake) Options {
	t.Helper()
	if fake.Identity.Account == "" {
		fake.Identity = awsapi.Identity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:role/audit"}
	}
	if fake.Regions == nil {
		fake.Regions = []awsapi.RegionStatus{
			{Name: "eu-west-1", Status: "ENABLED_BY_DEFAULT"},
			{Name: "us-east-1", Status: "ENABLED_BY_DEFAULT"},
			{Name: "af-south-1", Status: "DISABLED"},
		}
	}
	return Options{
		Profile:  "audit",
		OutDir:   t.TempDir(),
		Parallel: 2,
		Client:   fake,
	}
}

func TestUnknownRegionRejectedWithoutDump(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "us-east-3"
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "us-east-3") {
		t.Fatalf("got %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("must not call AWS before rejecting unknown codes: %+v", fake.Calls)
	}
}

func TestWritesMetaAndRestrictsMode(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(opts.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dump dir should not be group/world accessible: %o", st.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["account_id"] != "123456789012" {
		t.Fatalf("meta: %s", raw)
	}
	if meta["partition"] != "aws" {
		t.Fatalf("partition %v", meta["partition"])
	}
	scanned, _ := meta["regions_scanned"].([]any)
	if len(scanned) != 1 || scanned[0] != "eu-west-1" {
		t.Fatalf("scanned %v", scanned)
	}
}

func TestRedactsVPNPreSharedKey(t *testing.T) {
	fake := &awsapi.Fake{
		Bodies: map[string]json.RawMessage{
			"eu-west-1|ec2|DescribeVpnConnections": json.RawMessage(`{"VpnConnections":[{"Options":{"TunnelOptions":[{"PreSharedKey":"supersecret"}]}}]}`),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "regions", "eu-west-1", "vpc", "vpn-connections.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "supersecret") {
		t.Fatalf("PSK written to disk: %s", raw)
	}
}

func TestDumpFailureWritesEmptyObjectAndErrorLog(t *testing.T) {
	fake := &awsapi.Fake{
		Errs: map[string]error{
			"|iam|ListUsers": fmtErr("AccessDenied"),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "global", "iam", "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "{}" {
		t.Fatalf("want {} got %s", raw)
	}
	elog, _ := os.ReadFile(filepath.Join(opts.OutDir, "errors.log"))
	if !strings.Contains(string(elog), "AccessDenied") {
		t.Fatalf("errors.log: %s", elog)
	}
}

func TestSummaryReportsGenerated(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	opts.Formats = []string{"md", "csv", "json"}
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"summary.md", "summary.csv", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(opts.OutDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s empty", name)
		}
	}
	md, err := os.ReadFile(filepath.Join(opts.OutDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Account 123456789012") {
		t.Fatalf("summary: %s", md)
	}
}

func TestPerResourceReadsFollowListIds(t *testing.T) {
	const region = "eu-west-1"
	fake := &awsapi.Fake{
		Bodies: map[string]json.RawMessage{
			region + "|ec2|DescribeSnapshots":      json.RawMessage(`{"Snapshots":[{"SnapshotId":"snap-1"},{"SnapshotId":""}]}`),
			region + "|rds|DescribeDBSnapshots":    json.RawMessage(`{"DBSnapshots":[{"DBSnapshotIdentifier":"db-snap"}]}`),
			region + "|eks|ListClusters":           json.RawMessage(`{"Clusters":["prod"]}`),
			region + "|lambda|ListFunctions":       json.RawMessage(`{"Functions":[{"FunctionName":"fn"}]}`),
			region + "|sqs|ListQueues":             json.RawMessage(`{"QueueUrls":["https://sqs.eu-west-1.amazonaws.com/123/q"]}`),
			region + "|sns|ListTopics":             json.RawMessage(`{"Topics":[{"TopicArn":"arn:aws:sns:eu-west-1:123:t"}]}`),
			region + "|ecr|DescribeRepositories":   json.RawMessage(`{"Repositories":[{"RepositoryName":"app"}]}`),
			region + "|dynamodb|ListTables":        json.RawMessage(`{"TableNames":["orders"]}`),
			region + "|opensearch|ListDomainNames": json.RawMessage(`{"DomainNames":[{"DomainName":"logs"}]}`),
			region + "|guardduty|ListDetectors":    json.RawMessage(`{"DetectorIds":["det-1"]}`),
			region + "|ec2|DescribeInstances":      json.RawMessage(`{}`),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = region
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"ec2|DescribeSnapshotAttribute":         {"SnapshotId": "snap-1"},
		"ec2|GetSnapshotBlockPublicAccessState": nil,
		"ec2|GetImageBlockPublicAccessState":    nil,
		"rds|DescribeDBSnapshotAttributes":      {"DBSnapshotIdentifier": "db-snap"},
		"eks|DescribeCluster":                   {"Name": "prod"},
		"lambda|ListFunctionUrlConfigs":         {"FunctionName": "fn"},
		"lambda|GetPolicy":                      {"FunctionName": "fn"},
		"sqs|GetQueueAttributes":                {"QueueUrl": "https://sqs.eu-west-1.amazonaws.com/123/q"},
		"sns|GetTopicAttributes":                {"TopicArn": "arn:aws:sns:eu-west-1:123:t"},
		"ecr|GetRepositoryPolicy":               {"RepositoryName": "app"},
		"dynamodb|DescribeTable":                {"TableName": "orders"},
		"dynamodb|DescribeContinuousBackups":    {"TableName": "orders"},
		"opensearch|DescribeDomain":             {"DomainName": "logs"},
		"guardduty|GetDetector":                 {"DetectorId": "det-1"},
	}
	got := map[string]int{}
	for _, c := range fake.Calls {
		if c.Region != region {
			continue
		}
		k := c.Service + "|" + c.Operation
		if _, ok := want[k]; !ok {
			continue
		}
		got[k]++
		for key, val := range want[k] {
			if c.Input[key] != val {
				t.Errorf("%s input %s=%q want %q", k, key, c.Input[key], val)
			}
		}
	}
	for k := range want {
		if got[k] != 1 {
			t.Errorf("%s calls=%d", k, got[k])
		}
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, "regions", region, "ec2", "snapshots", "snap-1-attributes.json")); err != nil {
		t.Fatal(err)
	}
}

type fmtErr string

func (e fmtErr) Error() string { return string(e) }
