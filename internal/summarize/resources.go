package summarize

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simplycubed/aws-audit/internal/report"
)

func resourceFindings(rgn string, r *report.Report) {
	kmsKeyPolicies(rgn, r)
	blockPublicAccess(rgn, r)
	publicSnapshots(rgn, r)
	eksClusters(rgn, r)
	lambdaExposure(rgn, r)
	resourcePolicies(rgn, r)
	dynamoTables(rgn, r)
	openSearchDomains(rgn, r)
	guardDutyDetectors(rgn, r)
}

func kmsKeyPolicies(rgn string, r *report.Report) {
	var hit []string
	for _, f := range glob(rgn, "*/kms/keys/*-policy.json") {
		var doc struct {
			Policy string `json:"Policy"`
		}
		if readJSON(f, &doc) != nil || strings.TrimSpace(doc.Policy) == "" {
			continue
		}
		id := strings.TrimSuffix(filepath.Base(f), "-policy.json")
		if id == "" || !allowsAnyPrincipal(doc.Policy) {
			continue
		}
		hit = append(hit, regionOf(f)+"/"+id)
	}
	if len(hit) > 0 {
		add(r, "HIGH: KMS key policy allows any principal", strings.Join(hit, ","))
	}
}

func blockPublicAccess(rgn string, r *report.Report) {
	var snap, ami []string
	for _, f := range glob(rgn, "*/ec2/snapshot-block-public-access.json") {
		var doc struct {
			State string `json:"State"`
		}
		if readJSON(f, &doc) != nil || doc.State == "" || doc.State == "block-all-sharing" {
			continue
		}
		region := regionOf(f)
		if region == "" {
			continue
		}
		snap = append(snap, region+" ("+doc.State+")")
	}
	for _, f := range glob(rgn, "*/ec2/image-block-public-access.json") {
		var doc struct {
			State string `json:"ImageBlockPublicAccessState"`
		}
		if readJSON(f, &doc) != nil || doc.State != "unblocked" {
			continue
		}
		region := regionOf(f)
		if region == "" {
			continue
		}
		ami = append(ami, region)
	}
	if len(snap) > 0 {
		add(r, "HIGH: EBS snapshot public sharing is not fully blocked", strings.Join(snap, ","))
	}
	if len(ami) > 0 {
		add(r, "HIGH: AMI public sharing is not fully blocked", strings.Join(ami, ","))
	}
}

func publicSnapshots(rgn string, r *report.Report) {
	var ebs, rds []string
	for _, f := range glob(rgn, "*/ec2/snapshots/*-attributes.json") {
		var doc struct {
			SnapshotId string `json:"SnapshotId"`
			Perms      []struct {
				Group string `json:"Group"`
			} `json:"CreateVolumePermissions"`
		}
		if readJSON(f, &doc) != nil {
			continue
		}
		public := false
		for _, p := range doc.Perms {
			if p.Group == "all" {
				public = true
			}
		}
		id := firstNonEmpty(doc.SnapshotId, strings.TrimSuffix(filepath.Base(f), "-attributes.json"))
		if public && id != "" {
			ebs = append(ebs, regionOf(f)+"/"+id)
		}
	}
	for _, f := range glob(rgn, "*/rds/snapshots/*-attributes.json") {
		var doc struct {
			Result *struct {
				ID    string `json:"DBSnapshotIdentifier"`
				Attrs []struct {
					Name   string   `json:"AttributeName"`
					Values []string `json:"AttributeValues"`
				} `json:"DBSnapshotAttributes"`
			} `json:"DBSnapshotAttributesResult"`
		}
		if readJSON(f, &doc) != nil || doc.Result == nil {
			continue
		}
		public := false
		for _, a := range doc.Result.Attrs {
			if a.Name != "restore" {
				continue
			}
			for _, v := range a.Values {
				if v == "all" {
					public = true
				}
			}
		}
		id := firstNonEmpty(doc.Result.ID, strings.TrimSuffix(filepath.Base(f), "-attributes.json"))
		if public && id != "" {
			rds = append(rds, regionOf(f)+"/"+id)
		}
	}
	if len(ebs) > 0 {
		add(r, "HIGH: EBS snapshot is public", strings.Join(ebs, ","))
	}
	if len(rds) > 0 {
		add(r, "HIGH: RDS snapshot is public", strings.Join(rds, ","))
	}
}

func eksClusters(rgn string, r *report.Report) {
	var public, plain []string
	for _, f := range glob(rgn, "*/eks/clusters/*.json") {
		if filepath.Base(f) == "clusters.json" {
			continue
		}
		var doc struct {
			Cluster *struct {
				Name             string            `json:"Name"`
				EncryptionConfig []json.RawMessage `json:"EncryptionConfig"`
				VPC              *struct {
					EndpointPublicAccess *bool    `json:"EndpointPublicAccess"`
					PublicAccessCidrs    []string `json:"PublicAccessCidrs"`
				} `json:"ResourcesVpcConfig"`
			} `json:"Cluster"`
		}
		if readJSON(f, &doc) != nil || doc.Cluster == nil || doc.Cluster.Name == "" {
			continue
		}
		id := regionOf(f) + "/" + doc.Cluster.Name
		if doc.Cluster.VPC != nil && doc.Cluster.VPC.EndpointPublicAccess != nil && *doc.Cluster.VPC.EndpointPublicAccess {
			for _, cidr := range doc.Cluster.VPC.PublicAccessCidrs {
				if cidr == "0.0.0.0/0" {
					public = append(public, id)
					break
				}
			}
		}
		if len(doc.Cluster.EncryptionConfig) == 0 {
			plain = append(plain, id)
		}
	}
	if len(public) > 0 {
		add(r, "HIGH: EKS API is public", strings.Join(public, ","))
	}
	if len(plain) > 0 {
		add(r, "MEDIUM: EKS secrets are not encrypted with a customer key", strings.Join(plain, ","))
	}
}

func lambdaExposure(rgn string, r *report.Report) {
	var urls []string
	for _, f := range glob(rgn, "*/lambda/functions/*-url-configs.json") {
		var doc struct {
			Configs []struct {
				AuthType string `json:"AuthType"`
			} `json:"FunctionUrlConfigs"`
		}
		if readJSON(f, &doc) != nil || len(doc.Configs) == 0 {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), "-url-configs.json")
		if name == "" {
			continue
		}
		for _, c := range doc.Configs {
			if c.AuthType == "NONE" {
				urls = append(urls, regionOf(f)+"/"+name)
				break
			}
		}
	}
	if len(urls) > 0 {
		add(r, "HIGH: Lambda function URL allows unauthenticated calls", strings.Join(urls, ","))
	}
}

func resourcePolicies(rgn string, r *report.Report) {
	var hit []string
	for _, f := range glob(rgn, "*/lambda/functions/*-policy.json") {
		var doc struct {
			Policy string `json:"Policy"`
		}
		if readJSON(f, &doc) != nil || strings.TrimSpace(doc.Policy) == "" || !allowsAnyPrincipal(doc.Policy) {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), "-policy.json")
		if name != "" {
			hit = append(hit, regionOf(f)+"/lambda/"+name)
		}
	}
	for _, f := range glob(rgn, "*/sqs/queues/*-attributes.json") {
		var doc struct {
			Attributes map[string]string `json:"Attributes"`
		}
		if readJSON(f, &doc) != nil || doc.Attributes == nil {
			continue
		}
		if !allowsAnyPrincipal(doc.Attributes["Policy"]) {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(f), "-attributes.json")
		if name != "" {
			hit = append(hit, regionOf(f)+"/sqs/"+name)
		}
	}
	for _, f := range glob(rgn, "*/sns/topics/*-attributes.json") {
		var doc struct {
			Attributes map[string]string `json:"Attributes"`
		}
		if readJSON(f, &doc) != nil || doc.Attributes == nil {
			continue
		}
		if !allowsAnyPrincipal(doc.Attributes["Policy"]) {
			continue
		}
		name := firstNonEmpty(doc.Attributes["TopicArn"], strings.TrimSuffix(filepath.Base(f), "-attributes.json"))
		if name != "" {
			hit = append(hit, regionOf(f)+"/sns/"+name)
		}
	}
	for _, f := range glob(rgn, "*/ecr/repositories/*-policy.json") {
		var doc struct {
			PolicyText     string `json:"PolicyText"`
			RepositoryName string `json:"RepositoryName"`
		}
		if readJSON(f, &doc) != nil || strings.TrimSpace(doc.PolicyText) == "" || !allowsAnyPrincipal(doc.PolicyText) {
			continue
		}
		name := firstNonEmpty(doc.RepositoryName, strings.TrimSuffix(filepath.Base(f), "-policy.json"))
		if name != "" {
			hit = append(hit, regionOf(f)+"/ecr/"+name)
		}
	}
	var os []string
	for _, f := range glob(rgn, "*/opensearch/domains/*.json") {
		if filepath.Base(f) == "domains.json" {
			continue
		}
		var doc struct {
			Domain *struct {
				Name     string  `json:"DomainName"`
				Policies *string `json:"AccessPolicies"`
			} `json:"DomainStatus"`
		}
		if readJSON(f, &doc) != nil || doc.Domain == nil {
			continue
		}
		name := firstNonEmpty(doc.Domain.Name, strings.TrimSuffix(filepath.Base(f), ".json"))
		if name == "" || doc.Domain.Policies == nil || !allowsAnyPrincipal(*doc.Domain.Policies) {
			continue
		}
		os = append(os, regionOf(f)+"/"+name)
	}
	if len(hit) > 0 {
		sort.Strings(hit)
		add(r, "HIGH: Resource policy allows any principal", strings.Join(hit, ","))
	}
	if len(os) > 0 {
		add(r, "HIGH: OpenSearch domain endpoint policy allows any principal", strings.Join(os, ","))
	}
}

func dynamoTables(rgn string, r *report.Report) {
	var noDelete, noPITR, sseOff []string
	for _, f := range glob(rgn, "*/dynamodb/tables/*.json") {
		if strings.HasSuffix(f, "-continuous-backups.json") {
			var doc struct {
				Desc *struct {
					PITR *struct {
						Status string `json:"PointInTimeRecoveryStatus"`
					} `json:"PointInTimeRecoveryDescription"`
				} `json:"ContinuousBackupsDescription"`
			}
			if readJSON(f, &doc) != nil || doc.Desc == nil {
				continue
			}
			name := strings.TrimSuffix(filepath.Base(f), "-continuous-backups.json")
			status := ""
			if doc.Desc.PITR != nil {
				status = doc.Desc.PITR.Status
			}
			if name != "" && status != "ENABLED" {
				noPITR = append(noPITR, regionOf(f)+"/"+name)
			}
			continue
		}
		var doc struct {
			Table *struct {
				Name    string `json:"TableName"`
				Protect *bool  `json:"DeletionProtectionEnabled"`
				SSE     *struct {
					Status string `json:"Status"`
				} `json:"SSEDescription"`
			} `json:"Table"`
		}
		if readJSON(f, &doc) != nil || doc.Table == nil || doc.Table.Name == "" {
			continue
		}
		id := regionOf(f) + "/" + doc.Table.Name
		if doc.Table.Protect == nil || !*doc.Table.Protect {
			noDelete = append(noDelete, id)
		}
		if doc.Table.SSE != nil && doc.Table.SSE.Status == "DISABLED" {
			sseOff = append(sseOff, id)
		}
	}
	if len(noDelete) > 0 {
		add(r, "MEDIUM: DynamoDB table deletion protection is disabled", strings.Join(noDelete, ","))
	}
	if len(noPITR) > 0 {
		add(r, "MEDIUM: DynamoDB point-in-time recovery is disabled", strings.Join(noPITR, ","))
	}
	if len(sseOff) > 0 {
		add(r, "MEDIUM: DynamoDB table is not encrypted with a customer key", strings.Join(sseOff, ","))
	}
}

func openSearchDomains(rgn string, r *report.Report) {
	var public, restOff, nodeOff []string
	for _, f := range glob(rgn, "*/opensearch/domains/*.json") {
		if filepath.Base(f) == "domains.json" {
			continue
		}
		var doc struct {
			Domain *struct {
				Name string `json:"DomainName"`
				VPC  *struct {
					VPCId *string `json:"VPCId"`
				} `json:"VPCOptions"`
				AtRest *struct {
					Enabled *bool `json:"Enabled"`
				} `json:"EncryptionAtRestOptions"`
				Node *struct {
					Enabled *bool `json:"Enabled"`
				} `json:"NodeToNodeEncryptionOptions"`
			} `json:"DomainStatus"`
		}
		if readJSON(f, &doc) != nil || doc.Domain == nil {
			continue
		}
		name := firstNonEmpty(doc.Domain.Name, strings.TrimSuffix(filepath.Base(f), ".json"))
		if name == "" {
			continue
		}
		id := regionOf(f) + "/" + name
		if doc.Domain.VPC == nil || doc.Domain.VPC.VPCId == nil || *doc.Domain.VPC.VPCId == "" {
			public = append(public, id)
		}
		if doc.Domain.AtRest != nil && doc.Domain.AtRest.Enabled != nil && !*doc.Domain.AtRest.Enabled {
			restOff = append(restOff, id)
		}
		if doc.Domain.Node != nil && doc.Domain.Node.Enabled != nil && !*doc.Domain.Node.Enabled {
			nodeOff = append(nodeOff, id)
		}
	}
	if len(public) > 0 {
		add(r, "HIGH: OpenSearch domain has a public endpoint", strings.Join(public, ","))
	}
	if len(restOff) > 0 {
		add(r, "MEDIUM: OpenSearch domain is not encrypted at rest", strings.Join(restOff, ","))
	}
	if len(nodeOff) > 0 {
		add(r, "MEDIUM: OpenSearch node-to-node encryption is disabled", strings.Join(nodeOff, ","))
	}
}

func guardDutyDetectors(rgn string, r *report.Report) {
	var off []string
	for _, f := range glob(rgn, "*/security/guardduty/*.json") {
		var doc struct {
			Status string `json:"Status"`
		}
		if readJSON(f, &doc) != nil || doc.Status == "" || doc.Status == "ENABLED" {
			continue
		}
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		if id == "" {
			continue
		}
		off = append(off, regionOf(f)+"/"+id+" ("+doc.Status+")")
	}
	if len(off) > 0 {
		add(r, "MEDIUM: GuardDuty detector is not enabled", strings.Join(off, ","))
	}
}

func allowsAnyPrincipal(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if !json.Valid([]byte(raw)) {
		if u, err := url.QueryUnescape(raw); err == nil {
			raw = u
		}
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil || len(doc.Statement) == 0 {
		return false
	}
	var stmts []struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
	}
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var one struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
		}
		if json.Unmarshal(doc.Statement, &one) != nil {
			return false
		}
		stmts = append(stmts, one)
	}
	for _, st := range stmts {
		if strings.EqualFold(st.Effect, "Allow") && principalStar(jsonStrings(st.Principal)) {
			return true
		}
	}
	return false
}

func regionOf(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "regions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
