package summarize

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/simplycubed/aws-audit/internal/report"
)

var adminPolicyNames = map[string]bool{
	"AdministratorAccess": true,
	"IAMFullAccess":       true,
	"PowerUserAccess":     true,
}

func iamPrivileges(g string, r *report.Report) {
	var admins []string
	for _, kind := range []string{"users", "roles"} {
		matches, _ := filepath.Glob(filepath.Join(g, "iam", kind, "*", "attached-policies.json"))
		for _, f := range matches {
			var doc struct {
				AttachedPolicies []struct {
					PolicyName string `json:"PolicyName"`
					PolicyArn  string `json:"PolicyArn"`
				} `json:"AttachedPolicies"`
			}
			if readJSON(f, &doc) != nil {
				continue
			}
			name := filepath.Base(filepath.Dir(f))
			for _, p := range doc.AttachedPolicies {
				if adminPolicyNames[p.PolicyName] || adminPolicyNames[arnName(p.PolicyArn)] {
					admins = append(admins, kind+"/"+name+" ("+firstNonEmpty(p.PolicyName, arnName(p.PolicyArn))+")")
				}
			}
		}
	}
	if len(admins) > 0 {
		add(r, "HIGH: IAM principals with broad managed policies", strings.Join(admins, ", "))
	}

	account := sj(filepath.Join(filepath.Dir(g), "meta.json"), "account_id")
	var trusts []string
	matches, _ := filepath.Glob(filepath.Join(g, "iam", "roles", "*", "role.json"))
	for _, f := range matches {
		var doc struct {
			Role struct {
				RoleName                 string `json:"RoleName"`
				AssumeRolePolicyDocument string `json:"AssumeRolePolicyDocument"`
			} `json:"Role"`
		}
		if readJSON(f, &doc) != nil || doc.Role.AssumeRolePolicyDocument == "" {
			continue
		}
		raw, err := url.QueryUnescape(doc.Role.AssumeRolePolicyDocument)
		if err != nil {
			raw = doc.Role.AssumeRolePolicyDocument
		}
		name := firstNonEmpty(doc.Role.RoleName, filepath.Base(filepath.Dir(f)))
		for _, why := range trustProblems(raw, account) {
			trusts = append(trusts, name+": "+why)
		}
	}
	if len(trusts) > 0 {
		add(r, "HIGH: IAM role trust policy is overly broad", strings.Join(trusts, "; "))
	}
}

func aclPublic(path string) bool {
	var doc struct {
		Grants []struct {
			Grantee struct {
				URI string `json:"URI"`
			} `json:"Grantee"`
		} `json:"Grants"`
	}
	if readJSON(path, &doc) != nil {
		return false
	}
	for _, g := range doc.Grants {
		if strings.Contains(g.Grantee.URI, "AllUsers") || strings.Contains(g.Grantee.URI, "AuthenticatedUsers") {
			return true
		}
	}
	return false
}

func dataPlane(rgn string, r *report.Report) {
	var publicAMI, redshiftPub, redshiftUnenc, cacheWeak, efsUnenc []string
	var rdsNoDelete, auroraNoDelete, secretsNoRotate, ssmPlain, configOff []string

	for _, f := range glob(rgn, "*/ec2/images-owned.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Images []struct {
				ImageId string `json:"ImageId"`
				Name    string `json:"Name"`
				Public  bool   `json:"Public"`
			} `json:"Images"`
		}
		_ = readJSON(f, &doc)
		for _, img := range doc.Images {
			if img.Public && img.ImageId != "" {
				publicAMI = append(publicAMI, region+"/"+firstNonEmpty(img.Name, img.ImageId))
			}
		}
	}
	for _, f := range glob(rgn, "*/redshift/clusters.json") {
		region := regionFrom(f, "redshift")
		var doc struct {
			Clusters []struct {
				ClusterIdentifier  string `json:"ClusterIdentifier"`
				PubliclyAccessible bool   `json:"PubliclyAccessible"`
				Encrypted          bool   `json:"Encrypted"`
			} `json:"Clusters"`
		}
		_ = readJSON(f, &doc)
		for _, c := range doc.Clusters {
			if c.ClusterIdentifier == "" {
				continue
			}
			id := region + "/" + c.ClusterIdentifier
			if c.PubliclyAccessible {
				redshiftPub = append(redshiftPub, id)
			}
			if !c.Encrypted {
				redshiftUnenc = append(redshiftUnenc, id)
			}
		}
	}
	for _, f := range glob(rgn, "*/elasticache/replication-groups.json") {
		region := regionFrom(f, "elasticache")
		var doc struct {
			ReplicationGroups []struct {
				ReplicationGroupId       string `json:"ReplicationGroupId"`
				AtRestEncryptionEnabled  bool   `json:"AtRestEncryptionEnabled"`
				TransitEncryptionEnabled bool   `json:"TransitEncryptionEnabled"`
				AuthTokenEnabled         bool   `json:"AuthTokenEnabled"`
			} `json:"ReplicationGroups"`
		}
		_ = readJSON(f, &doc)
		for _, g := range doc.ReplicationGroups {
			if g.ReplicationGroupId == "" {
				continue
			}
			var why []string
			if !g.AtRestEncryptionEnabled {
				why = append(why, "at-rest")
			}
			if !g.TransitEncryptionEnabled {
				why = append(why, "transit")
			}
			if !g.AuthTokenEnabled {
				why = append(why, "auth-token")
			}
			if len(why) > 0 {
				cacheWeak = append(cacheWeak, region+"/"+g.ReplicationGroupId+" ("+strings.Join(why, ",")+")")
			}
		}
	}
	for _, f := range glob(rgn, "*/efs/file-systems.json") {
		region := regionFrom(f, "efs")
		var doc struct {
			FileSystems []struct {
				FileSystemId string `json:"FileSystemId"`
				Encrypted    bool   `json:"Encrypted"`
			} `json:"FileSystems"`
		}
		_ = readJSON(f, &doc)
		for _, fs := range doc.FileSystems {
			if fs.FileSystemId != "" && !fs.Encrypted {
				efsUnenc = append(efsUnenc, region+"/"+fs.FileSystemId)
			}
		}
	}
	for _, rel := range []string{"*/rds/instances.json", "*/rds/clusters.json"} {
		for _, f := range glob(rgn, rel) {
			kind := filepath.Base(f)
			region := regionFrom(f, "rds")
			var doc struct {
				DBInstances []struct {
					DBInstanceIdentifier string `json:"DBInstanceIdentifier"`
					DeletionProtection   bool   `json:"DeletionProtection"`
				} `json:"DBInstances"`
				DBClusters []struct {
					DBClusterIdentifier string `json:"DBClusterIdentifier"`
					DeletionProtection  bool   `json:"DeletionProtection"`
				} `json:"DBClusters"`
			}
			_ = readJSON(f, &doc)
			if kind == "instances.json" {
				for _, d := range doc.DBInstances {
					if d.DBInstanceIdentifier != "" && !d.DeletionProtection {
						rdsNoDelete = append(rdsNoDelete, region+"/"+d.DBInstanceIdentifier)
					}
				}
			} else {
				for _, d := range doc.DBClusters {
					if d.DBClusterIdentifier != "" && !d.DeletionProtection {
						auroraNoDelete = append(auroraNoDelete, region+"/"+d.DBClusterIdentifier)
					}
				}
			}
		}
	}
	for _, f := range glob(rgn, "*/secretsmanager/secrets.json") {
		region := regionFrom(f, "secretsmanager")
		var doc struct {
			SecretList []struct {
				Name            string `json:"Name"`
				RotationEnabled bool   `json:"RotationEnabled"`
			} `json:"SecretList"`
		}
		_ = readJSON(f, &doc)
		for _, s := range doc.SecretList {
			if s.Name != "" && !s.RotationEnabled {
				secretsNoRotate = append(secretsNoRotate, region+"/"+s.Name)
			}
		}
	}
	for _, f := range glob(rgn, "*/ssm/parameters.json") {
		region := regionFrom(f, "ssm")
		var doc struct {
			Parameters []struct {
				Name string `json:"Name"`
				Type string `json:"Type"`
			} `json:"Parameters"`
		}
		_ = readJSON(f, &doc)
		for _, p := range doc.Parameters {
			if p.Name != "" && p.Type == "String" {
				ssmPlain = append(ssmPlain, region+"/"+p.Name)
			}
		}
	}
	for _, f := range glob(rgn, "*/security/config-recorder-status.json") {
		region := regionFrom(f, "security")
		var doc struct {
			ConfigurationRecordersStatus []struct {
				Name      string `json:"Name"`
				Recording bool   `json:"Recording"`
			} `json:"ConfigurationRecordersStatus"`
		}
		_ = readJSON(f, &doc)
		for _, rec := range doc.ConfigurationRecordersStatus {
			if rec.Name != "" && !rec.Recording {
				configOff = append(configOff, region+"/"+rec.Name)
			}
		}
	}

	if len(publicAMI) > 0 {
		add(r, "HIGH: Owned AMIs are public", strings.Join(publicAMI, ","))
	}
	if len(redshiftPub) > 0 {
		add(r, "HIGH: Publicly accessible Redshift clusters", strings.Join(redshiftPub, ","))
	}
	if len(redshiftUnenc) > 0 {
		add(r, "HIGH: Unencrypted Redshift clusters", strings.Join(redshiftUnenc, ","))
	}
	if len(cacheWeak) > 0 {
		add(r, "MEDIUM: ElastiCache replication groups without encryption or an auth token", strings.Join(cacheWeak, ","))
	}
	if len(efsUnenc) > 0 {
		add(r, "MEDIUM: Unencrypted EFS file systems", strings.Join(efsUnenc, ","))
	}
	if len(rdsNoDelete) > 0 {
		add(r, "MEDIUM: RDS instances without deletion protection", strings.Join(rdsNoDelete, ","))
	}
	if len(auroraNoDelete) > 0 {
		add(r, "MEDIUM: Aurora clusters without deletion protection", strings.Join(auroraNoDelete, ","))
	}
	if len(secretsNoRotate) > 0 {
		add(r, "MEDIUM: Secrets Manager secrets without rotation", strings.Join(secretsNoRotate, ","))
	}
	if len(ssmPlain) > 0 {
		add(r, "MEDIUM: SSM parameters stored as String", strings.Join(ssmPlain, ",")+" — use SecureString.")
	}
	if len(configOff) > 0 {
		add(r, "MEDIUM: AWS Config recorder is not recording", strings.Join(configOff, ","))
	}
}

func trustProblems(raw, account string) []string {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || len(doc.Statement) == 0 {
		return nil
	}
	var stmts []struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
		Action    json.RawMessage `json:"Action"`
		Condition json.RawMessage `json:"Condition"`
	}
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var one struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Action    json.RawMessage `json:"Action"`
			Condition json.RawMessage `json:"Condition"`
		}
		if json.Unmarshal(doc.Statement, &one) != nil {
			return nil
		}
		stmts = append(stmts, one)
	}
	var out []string
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !assumeAction(st.Action) {
			continue
		}
		principals := jsonStrings(st.Principal)
		cond := string(st.Condition)
		if principalStar(principals) {
			out = append(out, "principal is *")
		}
		if account != "" && crossAccount(principals, account) && !strings.Contains(cond, "ExternalId") {
			out = append(out, "cross-account trust has no sts:ExternalId")
		}
		if oidc(principals) && !strings.Contains(cond, ":sub") {
			out = append(out, "OIDC trust has no sub condition")
		}
	}
	return out
}

func assumeAction(raw json.RawMessage) bool {
	for _, a := range jsonStrings(raw) {
		if a == "*" || strings.Contains(a, "AssumeRole") {
			return true
		}
	}
	return false
}

func principalStar(vals []string) bool {
	for _, v := range vals {
		if v == "*" {
			return true
		}
	}
	return false
}

func crossAccount(vals []string, account string) bool {
	for _, v := range vals {
		if !strings.HasPrefix(v, "arn:") {
			continue
		}
		parts := strings.Split(v, ":")
		if len(parts) < 5 || parts[4] == "" || parts[4] == account {
			continue
		}
		if strings.Contains(v, ":iam:") || strings.Contains(v, ":sts:") {
			return true
		}
	}
	return false
}

func oidc(vals []string) bool {
	for _, v := range vals {
		if strings.Contains(v, "oidc-provider/") {
			return true
		}
	}
	return false
}

func jsonStrings(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	var out []string
	for _, v := range obj {
		out = append(out, jsonStrings(v)...)
	}
	return out
}

func arnName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
