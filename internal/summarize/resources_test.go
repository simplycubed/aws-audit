package summarize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResourceFindings(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	star := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"*","Resource":"*"}]}`
	specific := `{"Version":"2012-10-17","Statement":[{"Sid":"star-in-resource","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}]}`
	denyStar := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}]}`

	write("meta.json", `{"account_id":"123456789012"}`)
	write("regions/eu-west-1/kms/keys/key-open-policy.json", `{"Policy":`+jsonQuote(star)+`}`)
	write("regions/eu-west-1/kms/keys/key-ok-policy.json", `{"Policy":`+jsonQuote(specific)+`}`)
	write("regions/eu-west-1/kms/keys/key-err-policy.json", `{}`)
	write("regions/eu-west-1/ec2/snapshot-block-public-access.json", `{"State":"block-new-sharing"}`)
	write("regions/eu-west-1/ec2/image-block-public-access.json", `{"ImageBlockPublicAccessState":"unblocked"}`)
	write("regions/us-east-1/ec2/snapshot-block-public-access.json", `{"State":"block-all-sharing"}`)
	write("regions/us-east-1/ec2/image-block-public-access.json", `{"ImageBlockPublicAccessState":"block-new-sharing"}`)
	write("regions/eu-west-1/ec2/snapshots/snap-pub-attributes.json", `{"SnapshotId":"snap-pub","CreateVolumePermissions":[{"Group":"all"}]}`)
	write("regions/eu-west-1/ec2/snapshots/snap-priv-attributes.json", `{"SnapshotId":"snap-priv","CreateVolumePermissions":[{"UserId":"123456789012"}]}`)
	write("regions/eu-west-1/ec2/snapshots/snap-err-attributes.json", `{}`)
	write("regions/eu-west-1/rds/snapshots/db-pub-attributes.json", `{"DBSnapshotAttributesResult":{"DBSnapshotIdentifier":"db-pub","DBSnapshotAttributes":[{"AttributeName":"restore","AttributeValues":["all"]}]}}`)
	write("regions/eu-west-1/rds/snapshots/db-priv-attributes.json", `{"DBSnapshotAttributesResult":{"DBSnapshotIdentifier":"db-priv","DBSnapshotAttributes":[{"AttributeName":"restore","AttributeValues":["123456789012"]}]}}`)
	write("regions/eu-west-1/eks/clusters/pub.json", `{"Cluster":{"Name":"pub","EncryptionConfig":[],"ResourcesVpcConfig":{"EndpointPublicAccess":true,"PublicAccessCidrs":["0.0.0.0/0"]}}}`)
	write("regions/eu-west-1/eks/clusters/ok.json", `{"Cluster":{"Name":"ok","EncryptionConfig":[{"Resources":["secrets"]}],"ResourcesVpcConfig":{"EndpointPublicAccess":true,"PublicAccessCidrs":["10.0.0.0/16"]}}}`)
	write("regions/eu-west-1/eks/clusters/err.json", `{}`)
	write("regions/eu-west-1/lambda/functions/open-url-configs.json", `{"FunctionUrlConfigs":[{"AuthType":"NONE"},{"AuthType":"AWS_IAM"}]}`)
	write("regions/eu-west-1/lambda/functions/iam-url-configs.json", `{"FunctionUrlConfigs":[{"AuthType":"AWS_IAM"}]}`)
	write("regions/eu-west-1/lambda/functions/open-policy.json", `{"Policy":`+jsonQuote(star)+`}`)
	write("regions/eu-west-1/lambda/functions/ok-policy.json", `{"Policy":`+jsonQuote(denyStar)+`}`)
	write("regions/eu-west-1/lambda/functions/err-policy.json", `{}`)
	write("regions/eu-west-1/sqs/queues/q-attributes.json", `{"Attributes":{"Policy":`+jsonQuote(star)+`}}`)
	write("regions/eu-west-1/sns/topics/t-attributes.json", `{"Attributes":{"TopicArn":"arn:aws:sns:eu-west-1:123:t","Policy":`+jsonQuote(specific)+`}}`)
	write("regions/eu-west-1/ecr/repositories/app-policy.json", `{"RepositoryName":"app","PolicyText":`+jsonQuote(star)+`}`)
	write("regions/eu-west-1/dynamodb/tables/orders.json", `{"Table":{"TableName":"orders","DeletionProtectionEnabled":false,"SSEDescription":{"Status":"DISABLED"}}}`)
	write("regions/eu-west-1/dynamodb/tables/orders-continuous-backups.json", `{"ContinuousBackupsDescription":{"PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"DISABLED"}}}`)
	write("regions/eu-west-1/dynamodb/tables/safe.json", `{"Table":{"TableName":"safe","DeletionProtectionEnabled":true}}`)
	write("regions/eu-west-1/dynamodb/tables/safe-continuous-backups.json", `{"ContinuousBackupsDescription":{"PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"ENABLED"}}}`)
	write("regions/eu-west-1/dynamodb/tables/err.json", `{}`)
	write("regions/eu-west-1/opensearch/domains/pub.json", `{"DomainStatus":{"DomainName":"pub","AccessPolicies":`+jsonQuote(star)+`,"EncryptionAtRestOptions":{"Enabled":false},"NodeToNodeEncryptionOptions":{"Enabled":false}}}`)
	write("regions/eu-west-1/opensearch/domains/vpc.json", `{"DomainStatus":{"DomainName":"vpc","VPCOptions":{"VPCId":"vpc-1"},"AccessPolicies":`+jsonQuote(specific)+`,"EncryptionAtRestOptions":{"Enabled":true},"NodeToNodeEncryptionOptions":{"Enabled":true}}}`)
	write("regions/eu-west-1/opensearch/domains/err.json", `{}`)
	write("regions/eu-west-1/security/guardduty-detectors.json", `{"DetectorIds":["det-on","det-off"]}`)
	write("regions/eu-west-1/security/guardduty/det-on.json", `{"Status":"ENABLED"}`)
	write("regions/eu-west-1/security/guardduty/det-off.json", `{"Status":"DISABLED"}`)
	write("regions/eu-west-1/security/guardduty/det-err.json", `{}`)

	rep, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()
	needles := []string{
		"KMS key policy allows any principal",
		"eu-west-1/key-open",
		"EBS snapshot public sharing is not fully blocked",
		"block-new-sharing",
		"AMI public sharing is not fully blocked",
		"EBS snapshot is public",
		"eu-west-1/snap-pub",
		"RDS snapshot is public",
		"eu-west-1/db-pub",
		"EKS API is public",
		"eu-west-1/pub",
		"EKS secrets are not encrypted with a customer key",
		"Lambda function URL allows unauthenticated calls",
		"eu-west-1/open",
		"Resource policy allows any principal",
		"eu-west-1/lambda/open",
		"eu-west-1/ecr/app",
		"DynamoDB table deletion protection is disabled",
		"eu-west-1/orders",
		"DynamoDB point-in-time recovery is disabled",
		"DynamoDB table is not encrypted with a customer key",
		"OpenSearch domain has a public endpoint",
		"OpenSearch domain endpoint policy allows any principal",
		"OpenSearch domain is not encrypted at rest",
		"OpenSearch node-to-node encryption is disabled",
		"GuardDuty detector is not enabled",
		"eu-west-1/det-off",
	}
	for _, n := range needles {
		if !strings.Contains(md, n) {
			t.Errorf("missing %q\n%s", n, md)
		}
	}
	for _, n := range []string{
		"key-ok",
		"snap-priv",
		"db-priv",
		"eu-west-1/ok",
		"eu-west-1/iam",
		"eu-west-1/safe",
		"eu-west-1/vpc",
		"det-on",
		"det-err",
		"GuardDuty disabled in regions",
	} {
		if strings.Contains(md, n) {
			t.Errorf("negative case %q was flagged\n%s", n, md)
		}
	}
	if strings.Contains(md, "us-east-1 (") || strings.Contains(md, "— us-east-1") {
		t.Fatalf("fully blocked public-access state was flagged\n%s", md)
	}
}

func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
