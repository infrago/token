package payloadcodec

import (
	"testing"

	. "github.com/infrago/base"
)

func TestFromSettingPrefersStoreCodec(t *testing.T) {
	codec := FromSetting(Map{
		"codec":         "ignored",
		"payload_codec": "payload",
		"store_codec":   "store",
	})
	if codec != "store" {
		t.Fatalf("expected store codec, got %q", codec)
	}
}

func TestJSONCodecDoesNotRequireRegisteredInfraCodec(t *testing.T) {
	payload := Map{"uid": "u1"}

	data, err := Marshal(Default, payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := Map{}
	if err := Unmarshal(Default, data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["uid"] != "u1" {
		t.Fatalf("unexpected payload: %v", out)
	}
}
