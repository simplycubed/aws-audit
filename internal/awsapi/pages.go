package awsapi

import (
	"bytes"
	"context"
	"encoding/json"
)

// pagination keys are dropped from the merged object. They describe a single
// page, not the combined result.
var paginationKeys = map[string]bool{
	"NextToken":       true,
	"Marker":          true,
	"NextMarker":      true,
	"IsTruncated":     true,
	"PaginationToken": true,
}

// collectPages calls next until it reports no further page. Each page is
// JSON-encoded and merged: array fields are concatenated, other fields keep
// the last value, and pagination keys are removed.
func collectPages(next func() (any, bool, error)) (json.RawMessage, error) {
	merged := map[string]json.RawMessage{}
	saw := false
	for {
		page, more, err := next()
		if err != nil {
			return nil, err
		}
		if page != nil {
			saw = true
			b, err := json.Marshal(page)
			if err != nil {
				return nil, err
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(b, &obj); err != nil {
				return nil, err
			}
			mergePage(merged, obj)
		}
		if !more {
			break
		}
	}
	if !saw {
		return json.RawMessage(`{}`), nil
	}
	return json.Marshal(merged)
}

func mergePage(dst map[string]json.RawMessage, page map[string]json.RawMessage) {
	for k, v := range page {
		if paginationKeys[k] {
			continue
		}
		v = bytes.TrimSpace(v)
		if isJSONArray(v) {
			if prev, ok := dst[k]; ok && isJSONArray(prev) {
				dst[k] = concatJSONArrays(prev, v)
				continue
			}
		}
		dst[k] = append(json.RawMessage(nil), v...)
	}
}

func isJSONArray(v json.RawMessage) bool {
	return len(bytes.TrimSpace(v)) > 0 && bytes.TrimSpace(v)[0] == '['
}

func concatJSONArrays(a, b json.RawMessage) json.RawMessage {
	a = bytes.TrimSpace(a)
	b = bytes.TrimSpace(b)
	ab := bytes.TrimSpace(a[1 : len(a)-1])
	bb := bytes.TrimSpace(b[1 : len(b)-1])
	if len(ab) == 0 {
		return append(json.RawMessage(nil), b...)
	}
	if len(bb) == 0 {
		return append(json.RawMessage(nil), a...)
	}
	out := make([]byte, 0, len(ab)+len(bb)+3)
	out = append(out, '[')
	out = append(out, ab...)
	out = append(out, ',')
	out = append(out, bb...)
	out = append(out, ']')
	return out
}

// paged walks an AWS SDK v2 paginator. has is HasMorePages; next is NextPage.
func paged(ctx context.Context, has func() bool, next func(context.Context) (any, error)) (json.RawMessage, error) {
	return collectPages(func() (any, bool, error) {
		if !has() {
			return nil, false, nil
		}
		page, err := next(ctx)
		if err != nil {
			return nil, false, err
		}
		return page, has(), nil
	})
}
