package control

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// formatConfig changes whitespace only. It preserves key/array order, unknown
// fields and numeric/string tokens without decoding through float64. JSONC is
// rejected rather than silently dropping comments. Output is idempotent.
func formatConfig(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, bytes.TrimSpace(raw), "", "  "); err != nil {
		return nil, fmt.Errorf("配置格式化失败（仅支持严格 JSON，保留原文件）: %w", err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Generated maps retain encoding/json's stable lexicographic field order.
// Do not use this for snapshot hashes: canonical must remain compact for
// compatibility with already persisted journals and baseline/inbound hashes.
func configBytes(v map[string]any) []byte {
	b, _ := formatConfig(documentBytes(v))
	return b
}
