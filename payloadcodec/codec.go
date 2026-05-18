package payloadcodec

import (
	"encoding/json"
	"strings"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

const Default = infra.JSON

func FromSetting(setting Map) string {
	for _, key := range []string{"store_codec", "payload_codec", "driver_codec"} {
		if v, ok := setting[key].(string); ok && strings.TrimSpace(v) != "" {
			return Normalize(v)
		}
	}
	return Default
}

func Normalize(codec string) string {
	codec = strings.TrimSpace(codec)
	if codec == "" {
		return Default
	}
	return codec
}

func Marshal(codec string, payload Map) ([]byte, error) {
	codec = Normalize(codec)
	if strings.EqualFold(codec, infra.JSON) {
		return json.Marshal(payload)
	}
	return infra.Marshal(codec, payload)
}

func Unmarshal(codec string, data []byte, out *Map) error {
	codec = Normalize(codec)
	if strings.EqualFold(codec, infra.JSON) {
		return json.Unmarshal(data, out)
	}
	return infra.Unmarshal(codec, data, out)
}
