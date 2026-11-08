package summarize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingOnlyChecks(t *testing.T) {
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
	write("meta.json", `{"account_id":"123456789012"}`)
	write("global/iam/roles/admin/attached-policies.json", `{
		"AttachedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]
	}`)
	write("global/iam/roles/ci/role.json", `{
		"Role":{"RoleName":"ci","AssumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Aoidc-provider%2Ftoken.actions.githubusercontent.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRoleWithWebIdentity%22%7D%5D%7D"}
	}`)
	write("global/s3/buckets/open/acl.json", `{
		"Grants":[{"Grantee":{"URI":"http://acs.amazonaws.com/groups/global/AllUsers"}}]
	}`)
	write("regions/eu-west-1/ec2/security-groups.json", `{
		"SecurityGroups":[{"GroupId":"sg-1","GroupName":"v6","IpPermissions":[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]}]
	}`)
	write("regions/eu-west-1/ec2/images-owned.json", `{"Images":[{"ImageId":"ami-1","Name":"pub","Public":true},{"ImageId":"ami-2","Name":"priv","Public":false}]}`)
	write("regions/eu-west-1/redshift/clusters.json", `{"Clusters":[{"ClusterIdentifier":"wh","PubliclyAccessible":true,"Encrypted":false}]}`)
	write("regions/eu-west-1/elasticache/replication-groups.json", `{"ReplicationGroups":[{"ReplicationGroupId":"cache","AtRestEncryptionEnabled":false,"TransitEncryptionEnabled":true,"AuthTokenEnabled":false}]}`)
	write("regions/eu-west-1/efs/file-systems.json", `{"FileSystems":[{"FileSystemId":"fs-1","Encrypted":false}]}`)
	write("regions/eu-west-1/rds/instances.json", `{"DBInstances":[{"DBInstanceIdentifier":"db","StorageEncrypted":true,"BackupRetentionPeriod":7,"DeletionProtection":false}]}`)
	write("regions/eu-west-1/rds/clusters.json", `{"DBClusters":[{"DBClusterIdentifier":"aurora","DeletionProtection":true}]}`)
	write("regions/eu-west-1/secretsmanager/secrets.json", `{"SecretList":[{"Name":"app","RotationEnabled":false}]}`)
	write("regions/eu-west-1/ssm/parameters.json", `{"Parameters":[{"Name":"/app/token","Type":"String"},{"Name":"/app/ok","Type":"SecureString"}]}`)
	write("regions/eu-west-1/security/config-recorder-status.json", `{"ConfigurationRecordersStatus":[{"Name":"default","Recording":false}]}`)
	write("global/s3/public-access-block.json", `{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true}}`)

	rep, err := Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := rep.Markdown()
	needles := []string{
		"IAM principals with broad managed policies",
		"OIDC trust has no sub condition",
		"S3 bucket ACLs grant access to everyone",
		"Security groups expose ports to the public internet",
		"Owned AMIs are public",
		"Publicly accessible Redshift clusters",
		"Unencrypted Redshift clusters",
		"ElastiCache replication groups without encryption or an auth token",
		"Unencrypted EFS file systems",
		"RDS instances without deletion protection",
		"Secrets Manager secrets without rotation",
		"SSM parameters stored as String",
		"AWS Config recorder is not recording",
	}
	for _, n := range needles {
		if !strings.Contains(md, n) {
			t.Errorf("missing %q\n%s", n, md)
		}
	}
	if strings.Contains(md, "Aurora clusters without deletion protection") {
		t.Fatal("protected Aurora cluster was flagged")
	}
	if strings.Contains(md, "/app/ok") {
		t.Fatal("SecureString parameter was flagged")
	}
}

func TestCrossAccountTrustRequiresExternalID(t *testing.T) {
	raw := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}}`
	got := trustProblems(raw, "123456789012")
	if len(got) != 1 || !strings.Contains(got[0], "ExternalId") {
		t.Fatalf("got %v", got)
	}
	safe := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"abc"}}}}`
	if got := trustProblems(safe, "123456789012"); len(got) != 0 {
		t.Fatalf("external id should pass, got %v", got)
	}
}
