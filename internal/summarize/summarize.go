package summarize

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charlesgreen/aws-audit/internal/report"
)

// Build reads an aws-audit dump directory and returns a portable report.
func Build(dir string) (*report.Report, error) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("Usage: aws-audit-summarize <audit-output-dir>")
	}
	g := filepath.Join(dir, "global")
	rgn := filepath.Join(dir, "regions")

	account := sj(filepath.Join(dir, "meta.json"), "account_id")
	principal := sj(filepath.Join(dir, "meta.json"), "principal_arn")
	r := report.New(account, principal, dir)

	iam(g, r)
	securityServices(rgn, r)
	network(rgn, r)
	s3(g, r)
	compute(rgn, r)
	kms(rgn, r)
	acm(rgn, r)
	logging(rgn, r)
	cost(rgn, r)
	coverage(dir, rgn, r)
	inventory(dir, g, rgn, r)
	r.Errors = errorLines(filepath.Join(dir, "errors.log"))
	return r, nil
}

// add splits "SEVERITY: title" into report fields.
func add(r *report.Report, sevTitle, detail string) {
	addRes(r, sevTitle, detail, "")
}

func addRes(r *report.Report, sevTitle, detail, resource string) {
	sev, title, ok := strings.Cut(sevTitle, ": ")
	if !ok {
		r.Add("INFO", sevTitle, detail, resource)
		return
	}
	r.Add(sev, title, detail, resource)
}

func iam(g string, r *report.Report) {
	csvPath := filepath.Join(g, "iam", "credential-report.csv")
	if rows, err := readCSV(csvPath); err == nil && len(rows) > 1 {
		for _, row := range rows[1:] {
			if len(row) < 14 {
				continue
			}
			if row[0] == "<root_account>" {
				if row[7] == "false" {
					add(r, "HIGH: Root account MFA disabled", "Enable hardware MFA on the root user immediately.")
				}
				if row[8] == "true" {
					add(r, "HIGH: Root account has active access key #1", "Delete root access keys; the root user should never have programmatic credentials.")
				}
				if row[13] == "true" {
					add(r, "HIGH: Root account has active access key #2", "Delete root access keys.")
				}
			}
		}
		var noMFA []string
		now := time.Now().UTC()
		var oldKeys []string
		for _, row := range rows[1:] {
			if len(row) < 14 || row[0] == "<root_account>" || row[0] == "user" {
				continue
			}
			if row[3] == "true" && row[7] == "false" {
				noMFA = append(noMFA, row[0])
			}
			checkOld := func(label, active, rotated string) {
				if active != "true" || rotated == "N/A" || rotated == "" {
					return
				}
				t, err := time.Parse(time.RFC3339, strings.Replace(rotated, " ", "T", 1))
				if err != nil {
					t, err = time.Parse("2006-01-02T15:04:05+00:00", strings.Split(rotated, ".")[0]+"+00:00")
				}
				if err != nil {
					return
				}
				days := int(now.Sub(t).Hours() / 24)
				if days > 90 {
					oldKeys = append(oldKeys, fmt.Sprintf("%s (%s, %dd)", row[0], label, days))
				}
			}
			checkOld("ak1", row[8], row[9])
			if len(row) > 14 {
				checkOld("ak2", row[13], row[14])
			}
		}
		if len(noMFA) > 0 {
			add(r, "MEDIUM: IAM users with console password but no MFA", strings.Join(noMFA, ","))
		}
		if len(oldKeys) > 0 {
			add(r, "MEDIUM: Access keys older than 90 days", strings.Join(oldKeys, ", "))
		}
	} else {
		r.Note("Credential report not available (permission denied or not generated).")
	}

	pwp := filepath.Join(g, "iam", "account-password-policy.json")
	var pol struct {
		PasswordPolicy *struct {
			MinimumPasswordLength      int  `json:"MinimumPasswordLength"`
			RequireSymbols             bool `json:"RequireSymbols"`
			RequireNumbers             bool `json:"RequireNumbers"`
			RequireUppercaseCharacters bool `json:"RequireUppercaseCharacters"`
			RequireLowercaseCharacters bool `json:"RequireLowercaseCharacters"`
			MaxPasswordAge             int  `json:"MaxPasswordAge"`
			PasswordReusePrevention    int  `json:"PasswordReusePrevention"`
		} `json:"PasswordPolicy"`
	}
	_ = readJSON(pwp, &pol)
	if pol.PasswordPolicy == nil {
		add(r, "MEDIUM: No IAM password policy set", "Configure an account-wide IAM password policy.")
	} else {
		p := pol.PasswordPolicy
		if p.MinimumPasswordLength < 14 {
			add(r, fmt.Sprintf("MEDIUM: Password policy min length %d < 14", p.MinimumPasswordLength), "Raise minimum length to at least 14.")
		}
		if !p.RequireSymbols || !p.RequireNumbers || !p.RequireUppercaseCharacters || !p.RequireLowercaseCharacters {
			add(r, "LOW: Password policy missing character class requirements", "Require symbols, numbers, upper- and lower-case.")
		}
		if p.MaxPasswordAge == 0 || p.MaxPasswordAge > 90 {
			add(r, fmt.Sprintf("LOW: Password max age %d > 90 (or unset)", p.MaxPasswordAge), "Set max age to 90 days.")
		}
		if p.PasswordReusePrevention < 24 {
			add(r, fmt.Sprintf("LOW: Password reuse prevention %d < 24", p.PasswordReusePrevention), "Prevent reuse of last 24 passwords.")
		}
	}

	var inline []string
	_ = filepath.Walk(filepath.Join(g, "iam", "users"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "inline-policies.json" {
			return nil
		}
		var doc struct {
			PolicyNames []string `json:"PolicyNames"`
		}
		if readJSON(path, &doc) == nil && len(doc.PolicyNames) > 0 {
			inline = append(inline, filepath.Base(filepath.Dir(path)))
		}
		return nil
	})
	if len(inline) > 0 {
		add(r, "LOW: IAM users with inline policies", strings.Join(inline, ",")+" — prefer managed policies and groups.")
	}
}

func securityServices(rgn string, r *report.Report) {
	type trail struct {
		Name                     string `json:"Name"`
		IsMultiRegionTrail       bool   `json:"IsMultiRegionTrail"`
		LogFileValidationEnabled bool   `json:"LogFileValidationEnabled"`
		KmsKeyId                 string `json:"KmsKeyId"`
	}
	trails := map[string]trail{}
	for _, f := range glob(rgn, "*/security/cloudtrail-trails.json") {
		var doc struct {
			TrailList []trail `json:"trailList"`
		}
		_ = readJSON(f, &doc)
		for _, t := range doc.TrailList {
			trails[t.Name] = t
		}
	}
	loggingOn := map[string]bool{}
	for _, f := range glob(rgn, "*/security/trails/*-status.json") {
		name := strings.TrimSuffix(filepath.Base(f), "-status.json")
		var doc struct {
			IsLogging bool `json:"IsLogging"`
		}
		_ = readJSON(f, &doc)
		if doc.IsLogging {
			loggingOn[name] = true
		} else if _, ok := loggingOn[name]; !ok {
			loggingOn[name] = false
		}
	}
	if len(trails) == 0 {
		add(r, "HIGH: No CloudTrail trails found", "Enable at least one multi-region CloudTrail with log file validation.")
	} else {
		multi := 0
		var noVal, noKMS, notLog []string
		for _, t := range trails {
			if t.IsMultiRegionTrail {
				multi++
			}
			if !t.LogFileValidationEnabled {
				noVal = append(noVal, t.Name)
			}
			if t.KmsKeyId == "" {
				noKMS = append(noKMS, t.Name)
			}
		}
		for name, on := range loggingOn {
			if !on {
				notLog = append(notLog, name)
			}
		}
		if multi == 0 {
			add(r, "HIGH: No multi-region CloudTrail", "Convert (or create) a trail with IsMultiRegionTrail=true.")
		}
		if len(noVal) > 0 {
			add(r, "MEDIUM: CloudTrail without log file validation", strings.Join(noVal, ","))
		}
		if len(noKMS) > 0 {
			add(r, "LOW: CloudTrail without KMS encryption", strings.Join(noKMS, ","))
		}
		if len(notLog) > 0 {
			add(r, "HIGH: CloudTrail trails not actively logging", strings.Join(notLog, ","))
		}
	}

	off := regionsWhere(rgn, "security/guardduty-detectors.json", func(raw []byte) bool {
		var doc struct {
			DetectorIds []string `json:"DetectorIds"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.DetectorIds) == 0
	})
	if len(off) > 0 {
		add(r, "MEDIUM: GuardDuty disabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(rgn, "security/config-recorders.json", func(raw []byte) bool {
		var doc struct {
			ConfigurationRecorders []any `json:"ConfigurationRecorders"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.ConfigurationRecorders) == 0
	})
	if len(off) > 0 {
		add(r, "MEDIUM: AWS Config not enabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(rgn, "security/securityhub-hub.json", func(raw []byte) bool {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		_, ok := doc["HubArn"]
		return !ok
	})
	if len(off) > 0 {
		add(r, "LOW: Security Hub not enabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(rgn, "security/access-analyzer-analyzers.json", func(raw []byte) bool {
		var doc struct {
			Analyzers []any `json:"analyzers"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.Analyzers) == 0
	})
	if len(off) > 0 {
		add(r, "LOW: IAM Access Analyzer not configured in regions", strings.Join(off, ","))
	}
}

func network(rgn string, r *report.Report) {
	var open []string
	for _, f := range glob(rgn, "*/ec2/security-groups.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			SecurityGroups []struct {
				GroupId       string `json:"GroupId"`
				GroupName     string `json:"GroupName"`
				IpPermissions []struct {
					IpProtocol string `json:"IpProtocol"`
					FromPort   *int   `json:"FromPort"`
					ToPort     *int   `json:"ToPort"`
					IpRanges   []struct {
						CidrIp string `json:"CidrIp"`
					} `json:"IpRanges"`
				} `json:"IpPermissions"`
			} `json:"SecurityGroups"`
		}
		_ = readJSON(f, &doc)
		for _, sg := range doc.SecurityGroups {
			for _, p := range sg.IpPermissions {
				for _, ip := range p.IpRanges {
					if ip.CidrIp == "0.0.0.0/0" {
						from, to := "all", "all"
						if p.FromPort != nil {
							from = fmt.Sprintf("%d", *p.FromPort)
						}
						if p.ToPort != nil {
							to = fmt.Sprintf("%d", *p.ToPort)
						}
						open = append(open, fmt.Sprintf("%s  %s (%s)  %s %s-%s", region, sg.GroupId, sg.GroupName, p.IpProtocol, from, to))
					}
				}
			}
		}
	}
	if len(open) > 0 {
		for _, e := range open {
			r.Note("Security group 0.0.0.0/0 ingress: `" + e + "`")
		}
		add(r, "HIGH: Security groups expose ports to the public internet", "Restrict ingress to specific CIDRs; pay special attention to 22 (SSH), 3389 (RDP), 3306, 5432, 1433, 27017, 6379.")
	}

	var defVPC, noFlow []string
	for _, f := range glob(rgn, "*/vpc/vpcs.json") {
		region := regionFrom(f, "vpc")
		var doc struct {
			Vpcs []struct {
				VpcId     string `json:"VpcId"`
				IsDefault bool   `json:"IsDefault"`
			} `json:"Vpcs"`
		}
		_ = readJSON(f, &doc)
		var flow struct {
			FlowLogs []struct {
				ResourceId string `json:"ResourceId"`
			} `json:"FlowLogs"`
		}
		_ = readJSON(filepath.Join(filepath.Dir(f), "flow-logs.json"), &flow)
		have := map[string]bool{}
		for _, fl := range flow.FlowLogs {
			have[fl.ResourceId] = true
		}
		for _, v := range doc.Vpcs {
			if v.IsDefault {
				defVPC = append(defVPC, region+"/"+v.VpcId)
			}
			if !have[v.VpcId] {
				noFlow = append(noFlow, region+"/"+v.VpcId)
			}
		}
	}
	if len(defVPC) > 0 {
		add(r, "LOW: Default VPC present", strings.Join(defVPC, ",")+" — consider deleting unused default VPCs.")
	}
	if len(noFlow) > 0 {
		add(r, "MEDIUM: VPCs without flow logs", strings.Join(noFlow, ","))
	}
}

func s3(g string, r *report.Report) {
	if !fullPAB(filepath.Join(g, "s3", "public-access-block.json")) {
		add(r, "HIGH: Account-level S3 Public Access Block not fully enabled", "Enable all four block settings at the account level via s3control.")
	}
	var pub, noPAB, noEnc, noVer, noLog, web []string
	entries, _ := os.ReadDir(filepath.Join(g, "s3", "buckets"))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		bd := filepath.Join(g, "s3", "buckets", e.Name())
		name := e.Name()
		if !fullPAB(filepath.Join(bd, "public-access-block.json")) {
			noPAB = append(noPAB, name)
		}
		var ps struct {
			PolicyStatus struct {
				IsPublic bool `json:"IsPublic"`
			} `json:"PolicyStatus"`
		}
		_ = readJSON(filepath.Join(bd, "policy-status.json"), &ps)
		if ps.PolicyStatus.IsPublic {
			pub = append(pub, name)
		}
		var enc struct {
			ServerSideEncryptionConfiguration struct {
				Rules []any `json:"Rules"`
			} `json:"ServerSideEncryptionConfiguration"`
		}
		_ = readJSON(filepath.Join(bd, "encryption.json"), &enc)
		if len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			noEnc = append(noEnc, name)
		}
		if sj(filepath.Join(bd, "versioning.json"), "Status") != "Enabled" {
			noVer = append(noVer, name)
		}
		var log struct {
			LoggingEnabled any `json:"LoggingEnabled"`
		}
		_ = readJSON(filepath.Join(bd, "logging.json"), &log)
		if log.LoggingEnabled == nil {
			noLog = append(noLog, name)
		}
		var site map[string]any
		_ = readJSON(filepath.Join(bd, "website.json"), &site)
		if site["IndexDocument"] != nil || site["RedirectAllRequestsTo"] != nil {
			web = append(web, name)
		}
	}
	if len(pub) > 0 {
		add(r, "HIGH: S3 buckets resolved as public", strings.Join(pub, ","))
	}
	if len(noPAB) > 0 {
		add(r, "MEDIUM: S3 buckets without full public access block", strings.Join(noPAB, ","))
	}
	if len(noEnc) > 0 {
		add(r, "MEDIUM: S3 buckets without default encryption", strings.Join(noEnc, ","))
	}
	if len(noVer) > 0 {
		add(r, "LOW: S3 buckets without versioning", strings.Join(noVer, ","))
	}
	if len(noLog) > 0 {
		add(r, "LOW: S3 buckets without access logging", strings.Join(noLog, ","))
	}
	if len(web) > 0 {
		r.Note("Buckets configured for static website hosting: " + strings.Join(web, ","))
	}
}

func fullPAB(path string) bool {
	var doc struct {
		PublicAccessBlockConfiguration struct {
			BlockPublicAcls       bool `json:"BlockPublicAcls"`
			BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
			IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
			RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
		} `json:"PublicAccessBlockConfiguration"`
	}
	if readJSON(path, &doc) != nil {
		return false
	}
	c := doc.PublicAccessBlockConfiguration
	return c.BlockPublicAcls && c.BlockPublicPolicy && c.IgnorePublicAcls && c.RestrictPublicBuckets
}

func compute(rgn string, r *report.Report) {
	ebsOff := regionsWhere(rgn, "ec2/ebs-encryption-default.json", func(raw []byte) bool {
		var doc struct {
			EbsEncryptionByDefault bool `json:"EbsEncryptionByDefault"`
		}
		_ = json.Unmarshal(raw, &doc)
		return !doc.EbsEncryptionByDefault
	})
	if len(ebsOff) > 0 {
		add(r, "MEDIUM: EBS encryption by default disabled", strings.Join(ebsOff, ",")+" — enable EBS encryption-by-default per region.")
	}
	var unenc, rdsPub, rdsUnenc, rdsNoBackup, publicIP, imds []string
	for _, f := range glob(rgn, "*/ec2/volumes.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Volumes []struct {
				VolumeId  string `json:"VolumeId"`
				Encrypted bool   `json:"Encrypted"`
			} `json:"Volumes"`
		}
		_ = readJSON(f, &doc)
		for _, v := range doc.Volumes {
			if !v.Encrypted {
				unenc = append(unenc, region+"/"+v.VolumeId)
			}
		}
	}
	if len(unenc) > 0 {
		add(r, "MEDIUM: Unencrypted EBS volumes", strings.Join(unenc, ","))
	}
	for _, f := range glob(rgn, "*/rds/instances.json") {
		region := regionFrom(f, "rds")
		var doc struct {
			DBInstances []struct {
				DBInstanceIdentifier  string `json:"DBInstanceIdentifier"`
				PubliclyAccessible    bool   `json:"PubliclyAccessible"`
				StorageEncrypted      bool   `json:"StorageEncrypted"`
				BackupRetentionPeriod int    `json:"BackupRetentionPeriod"`
			} `json:"DBInstances"`
		}
		_ = readJSON(f, &doc)
		for _, d := range doc.DBInstances {
			if d.PubliclyAccessible {
				rdsPub = append(rdsPub, region+"/"+d.DBInstanceIdentifier)
			}
			if !d.StorageEncrypted {
				rdsUnenc = append(rdsUnenc, region+"/"+d.DBInstanceIdentifier)
			}
			if d.BackupRetentionPeriod == 0 {
				rdsNoBackup = append(rdsNoBackup, region+"/"+d.DBInstanceIdentifier)
			}
		}
	}
	if len(rdsPub) > 0 {
		add(r, "HIGH: Publicly accessible RDS instances", strings.Join(rdsPub, ","))
	}
	if len(rdsUnenc) > 0 {
		add(r, "HIGH: Unencrypted RDS storage", strings.Join(rdsUnenc, ","))
	}
	if len(rdsNoBackup) > 0 {
		add(r, "MEDIUM: RDS instances with 0-day backup retention", strings.Join(rdsNoBackup, ","))
	}
	for _, f := range glob(rgn, "*/ec2/instances.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Reservations []struct {
				Instances []struct {
					InstanceId      string `json:"InstanceId"`
					PublicIpAddress string `json:"PublicIpAddress"`
					State           struct {
						Name string `json:"Name"`
					} `json:"State"`
					MetadataOptions struct {
						HttpTokens string `json:"HttpTokens"`
					} `json:"MetadataOptions"`
				} `json:"Instances"`
			} `json:"Reservations"`
		}
		_ = readJSON(f, &doc)
		for _, res := range doc.Reservations {
			for _, inst := range res.Instances {
				if inst.PublicIpAddress != "" && (inst.State.Name == "running" || inst.State.Name == "pending") {
					publicIP = append(publicIP, fmt.Sprintf("%s/%s (%s)", region, inst.InstanceId, inst.PublicIpAddress))
				}
				if inst.MetadataOptions.HttpTokens != "required" && inst.InstanceId != "" {
					imds = append(imds, region+"/"+inst.InstanceId)
				}
			}
		}
	}
	if len(publicIP) > 0 {
		r.Note("Public-IP EC2 instances: " + strings.Join(publicIP, ",") + " — verify exposure is intentional.")
	}
	if len(imds) > 0 {
		add(r, "MEDIUM: EC2 instances not enforcing IMDSv2", strings.Join(imds, ","))
	}
}

func kms(rgn string, r *report.Report) {
	var no []string
	for _, f := range glob(rgn, "*/kms/keys/*-rotation.json") {
		region := regionFrom(filepath.Dir(filepath.Dir(f)), "kms")
		key := strings.TrimSuffix(filepath.Base(f), "-rotation.json")
		var doc struct {
			KeyRotationEnabled bool `json:"KeyRotationEnabled"`
		}
		_ = readJSON(f, &doc)
		if !doc.KeyRotationEnabled {
			no = append(no, region+"/"+key)
		}
	}
	if len(no) > 0 {
		add(r, "LOW: Customer-managed KMS keys without rotation", strings.Join(no, ","))
	}
}

func acm(rgn string, r *report.Report) {
	var exp []string
	now := time.Now().UTC()
	for _, f := range glob(rgn, "*/acm/cert-*.json") {
		region := regionFrom(f, "acm")
		var doc struct {
			Certificate struct {
				DomainName string `json:"DomainName"`
				NotAfter   string `json:"NotAfter"`
				Status     string `json:"Status"`
			} `json:"Certificate"`
		}
		_ = readJSON(f, &doc)
		if doc.Certificate.NotAfter == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, doc.Certificate.NotAfter)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", strings.Split(doc.Certificate.NotAfter, ".")[0])
		}
		if err != nil {
			continue
		}
		days := int(t.Sub(now).Hours() / 24)
		if days < 30 {
			exp = append(exp, fmt.Sprintf("%s %s expires in %dd (status: %s)", region, doc.Certificate.DomainName, days, doc.Certificate.Status))
		}
	}
	if len(exp) > 0 {
		add(r, "MEDIUM: ACM certificates expiring soon", strings.Join(exp, "; "))
	}
}

func logging(rgn string, r *report.Report) {
	var none []string
	for _, f := range glob(rgn, "*/logs/log-groups.json") {
		region := regionFrom(f, "logs")
		var doc struct {
			LogGroups []struct {
				LogGroupName    string `json:"logGroupName"`
				RetentionInDays *int   `json:"retentionInDays"`
			} `json:"logGroups"`
		}
		_ = readJSON(f, &doc)
		for _, lg := range doc.LogGroups {
			if lg.RetentionInDays == nil {
				none = append(none, region+"/"+lg.LogGroupName)
			}
		}
	}
	if len(none) > 50 {
		n := 10
		if n > len(none) {
			n = len(none)
		}
		add(r, fmt.Sprintf("LOW: %d CloudWatch log groups have no retention (never expire)", len(none)), "Set retention on log groups to control cost; sampling first 10: "+strings.Join(none[:n], ","))
	} else if len(none) > 0 {
		add(r, "LOW: CloudWatch log groups without retention", strings.Join(none, ","))
	}
}

func cost(rgn string, r *report.Report) {
	var unattached, eip []string
	for _, f := range glob(rgn, "*/ec2/volumes.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Volumes []struct {
				VolumeId   string `json:"VolumeId"`
				State      string `json:"State"`
				Size       int    `json:"Size"`
				VolumeType string `json:"VolumeType"`
			} `json:"Volumes"`
		}
		_ = readJSON(f, &doc)
		for _, v := range doc.Volumes {
			if v.State == "available" {
				unattached = append(unattached, fmt.Sprintf("%s/%s (%dGB %s)", region, v.VolumeId, v.Size, v.VolumeType))
			}
		}
	}
	if len(unattached) > 0 {
		add(r, "COST: Unattached EBS volumes", strings.Join(unattached, ",")+" — delete if unused.")
	}
	for _, f := range glob(rgn, "*/ec2/elastic-ips.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Addresses []struct {
				PublicIp      string `json:"PublicIp"`
				AssociationId string `json:"AssociationId"`
			} `json:"Addresses"`
		}
		_ = readJSON(f, &doc)
		for _, a := range doc.Addresses {
			if a.AssociationId == "" && a.PublicIp != "" {
				eip = append(eip, region+"/"+a.PublicIp)
			}
		}
	}
	if len(eip) > 0 {
		add(r, "COST: Unassociated Elastic IPs (charged hourly)", strings.Join(eip, ","))
	}
	untagged := 0
	for _, f := range glob(rgn, "*/tags/resources.json") {
		var doc struct {
			ResourceTagMappingList []struct {
				Tags []any `json:"Tags"`
			} `json:"ResourceTagMappingList"`
		}
		_ = readJSON(f, &doc)
		for _, m := range doc.ResourceTagMappingList {
			if len(m.Tags) == 0 {
				untagged++
			}
		}
	}
	if untagged > 0 {
		add(r, fmt.Sprintf("GOVERNANCE: %d resources with no tags", untagged), "Adopt a tagging standard (Owner, Environment, CostCenter) and enforce via SCP or Config rule.")
	}
}

func coverage(dir, rgn string, r *report.Report) {
	meta := filepath.Join(dir, "meta.json")
	part := sj(meta, "partition")
	home := sj(meta, "home_region")
	if part != "" {
		r.Note(fmt.Sprintf("Partition: %s (home Region %s)", part, home))
	}
	var scanned []string
	var raw struct {
		RegionsScanned    []string `json:"regions_scanned"`
		RegionsNotEnabled []string `json:"regions_not_enabled"`
	}
	_ = readJSON(meta, &raw)
	scanned = raw.RegionsScanned
	if len(scanned) == 0 {
		ents, _ := os.ReadDir(rgn)
		for _, e := range ents {
			if e.IsDir() {
				scanned = append(scanned, e.Name())
			}
		}
		sort.Strings(scanned)
	}
	if len(scanned) > 0 {
		r.Note(fmt.Sprintf("Regions scanned (%d): %s", len(scanned), strings.Join(scanned, ",")))
	}
	if len(raw.RegionsNotEnabled) > 0 {
		r.Note("Opt-in Regions not enabled (skipped; IAM is not replicated until enabled): " + strings.Join(raw.RegionsNotEnabled, ","))
	}
}

func inventory(dir, g, rgn string, r *report.Report) {
	inst, lambda, rdsN := 0, 0, 0
	for _, f := range glob(rgn, "*/ec2/instances.json") {
		var doc struct {
			Reservations []struct {
				Instances []any `json:"Instances"`
			} `json:"Reservations"`
		}
		_ = readJSON(f, &doc)
		for _, res := range doc.Reservations {
			inst += len(res.Instances)
		}
	}
	for _, f := range glob(rgn, "*/lambda/functions.json") {
		var doc struct {
			Functions []any `json:"Functions"`
		}
		_ = readJSON(f, &doc)
		lambda += len(doc.Functions)
	}
	for _, f := range glob(rgn, "*/rds/instances.json") {
		var doc struct {
			DBInstances []any `json:"DBInstances"`
		}
		_ = readJSON(f, &doc)
		rdsN += len(doc.DBInstances)
	}
	var buckets struct {
		Buckets []any `json:"Buckets"`
	}
	_ = readJSON(filepath.Join(g, "s3", "list-buckets.json"), &buckets)
	var users struct {
		Users []any `json:"Users"`
	}
	_ = readJSON(filepath.Join(g, "iam", "users.json"), &users)
	var roles struct {
		Roles []any `json:"Roles"`
	}
	_ = readJSON(filepath.Join(g, "iam", "roles.json"), &roles)
	r.Note(fmt.Sprintf("Inventory: EC2 instances=%d, Lambda=%d, RDS=%d, S3 buckets=%d, IAM users=%d, IAM roles=%d",
		inst, lambda, rdsN, len(buckets.Buckets), len(users.Users), len(roles.Roles)))
}

func errorLines(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func sj(path, key string) string {
	var m map[string]any
	if readJSON(path, &m) != nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func readCSV(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var rows [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rows = append(rows, rec)
	}
	return rows, nil
}

func glob(root, pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(root, pattern))
	sort.Strings(m)
	return m
}

func regionFrom(path, svc string) string {
	// .../regions/<region>/<svc>/file.json
	dir := filepath.Dir(path)
	if filepath.Base(dir) == svc {
		return filepath.Base(filepath.Dir(dir))
	}
	return filepath.Base(filepath.Dir(filepath.Dir(path)))
}

func regionsWhere(r, rel string, pred func([]byte) bool) []string {
	var out []string
	for _, f := range glob(r, "*/"+rel) {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if pred(raw) {
			out = append(out, regionFrom(f, filepath.Base(filepath.Dir(f))))
		}
	}
	sort.Strings(out)
	return out
}
