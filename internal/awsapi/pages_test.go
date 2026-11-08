package awsapi

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCollectPagesMergesUserArrays(t *testing.T) {
	pages := []string{
		`{"Users":[{"UserName":"a"}],"IsTruncated":true,"Marker":"m1","Count":1}`,
		`{"Users":[{"UserName":"b"}],"IsTruncated":false,"Marker":null,"NextToken":"gone","Count":2}`,
	}
	i := 0
	raw, err := collectPages(func() (any, bool, error) {
		if i >= len(pages) {
			return nil, false, nil
		}
		var v any
		if err := json.Unmarshal([]byte(pages[i]), &v); err != nil {
			return nil, false, err
		}
		i++
		return v, i < len(pages), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Users []struct {
			UserName string `json:"UserName"`
		} `json:"Users"`
		Count         int             `json:"Count"`
		IsTruncated   json.RawMessage `json:"IsTruncated"`
		Marker        json.RawMessage `json:"Marker"`
		NextToken     json.RawMessage `json:"NextToken"`
		NextMarker    json.RawMessage `json:"NextMarker"`
		PaginationTok json.RawMessage `json:"PaginationToken"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Users) != 2 || doc.Users[0].UserName != "a" || doc.Users[1].UserName != "b" {
		t.Fatalf("users: %+v", doc.Users)
	}
	if doc.Count != 2 {
		t.Fatalf("last non-array value: got %d", doc.Count)
	}
	if doc.IsTruncated != nil || doc.Marker != nil || doc.NextToken != nil || doc.NextMarker != nil || doc.PaginationTok != nil {
		t.Fatalf("pagination keys leaked: %s", raw)
	}
}

func TestCollectPagesStopsOnError(t *testing.T) {
	_, err := collectPages(func() (any, bool, error) {
		return nil, false, errors.New("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("got %v", err)
	}
}
