package token

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

type testSigner struct {
	sessions map[string]infra.Token
	signErr  error
}

func newTestSigner() *testSigner {
	return &testSigner{sessions: map[string]infra.Token{}}
}

func init() {
	infra.Register("token-test-json", infra.Codec{
		Encode: func(v Any) (Any, error) {
			return json.Marshal(v)
		},
		Decode: func(d Any, v Any) (Any, error) {
			data, ok := d.([]byte)
			if !ok {
				return nil, errors.New("invalid codec data")
			}
			if v != nil {
				return v, json.Unmarshal(data, v)
			}
			var out Any
			return out, json.Unmarshal(data, &out)
		},
	})
}

func (s *testSigner) Sign(req infra.Token) (string, error) {
	if s.signErr != nil {
		return "", s.signErr
	}
	token := "signed:" + req.TokenID
	req.Token = token
	s.sessions[token] = req
	return token, nil
}

func (s *testSigner) Verify(token string) (infra.Token, error) {
	session, ok := s.sessions[token]
	if !ok {
		return infra.Token{}, errors.New("invalid token")
	}
	return session, nil
}

type testDriver struct {
	openErr           error
	saveErr           error
	loadErr           error
	revokedTokenErr   error
	revokedTokenIDErr error
	deleteErr         error
	saved             bool
	deleted           bool
}

func (d *testDriver) Open() error  { return d.openErr }
func (d *testDriver) Close() error { return nil }

func (d *testDriver) SavePayload(string, Map, int64) error {
	d.saved = true
	return d.saveErr
}

func (d *testDriver) LoadPayload(string) (Map, bool, error) {
	return nil, false, d.loadErr
}

func (d *testDriver) DeletePayload(string) error {
	d.deleted = true
	return d.deleteErr
}

func (d *testDriver) RevokeToken(string, int64) error {
	return nil
}

func (d *testDriver) RevokeTokenID(string, int64) error {
	return nil
}

func (d *testDriver) RevokedToken(string) (bool, error) {
	return false, d.revokedTokenErr
}

func (d *testDriver) RevokedTokenID(string) (bool, error) {
	return false, d.revokedTokenIDErr
}

func testModule(driver Driver, payloadMode string) *tokenModule {
	return &tokenModule{
		signer: newTestSigner(),
		driver: driver,
		config: tokenConfig{Payload: payloadMode, IDLength: 16},
	}
}

func testToken(t *testing.T, mod *tokenModule, tokenID string) string {
	t.Helper()
	token, err := mod.signer.Sign(infra.Token{
		TokenID: tokenID,
		Auth:    true,
		Payload: Map{"source": "token"},
	})
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return token
}

func TestSignReturnsPayloadSaveError(t *testing.T) {
	errBoom := errors.New("save failed")
	mod := testModule(&testDriver{saveErr: errBoom}, PayloadStore)

	_, err := mod.Sign(infra.Token{Payload: Map{"uid": "u1"}})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected save error, got %v", err)
	}
	if !errors.Is(err, ErrTokenStoreUnavailable) {
		t.Fatalf("expected store unavailable error, got %v", err)
	}
}

func TestSignStoresPayloadBeforeSigningAndCleansUpOnSignError(t *testing.T) {
	errBoom := errors.New("sign failed")
	driver := &testDriver{}
	mod := &tokenModule{
		signer: &testSigner{signErr: errBoom},
		driver: driver,
		config: tokenConfig{Payload: PayloadStore, IDLength: 16},
	}

	_, err := mod.Sign(infra.Token{Payload: Map{"uid": "u1"}})
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected sign error, got %v", err)
	}
	if !driver.saved {
		t.Fatalf("expected payload to be saved before signing")
	}
	if !driver.deleted {
		t.Fatalf("expected payload cleanup after signing failed")
	}
}

func TestSignReturnsCleanupErrorWhenPayloadDeleteFails(t *testing.T) {
	errSign := errors.New("sign failed")
	errDelete := errors.New("delete failed")
	driver := &testDriver{deleteErr: errDelete}
	mod := &tokenModule{
		signer: &testSigner{signErr: errSign},
		driver: driver,
		config: tokenConfig{Payload: PayloadStore, IDLength: 16},
	}

	_, err := mod.Sign(infra.Token{Payload: Map{"uid": "u1"}})
	if !errors.Is(err, errSign) {
		t.Fatalf("expected sign error, got %v", err)
	}
	if !errors.Is(err, errDelete) {
		t.Fatalf("expected delete error, got %v", err)
	}
	if !errors.Is(err, ErrTokenStoreUnavailable) {
		t.Fatalf("expected store unavailable cleanup error, got %v", err)
	}
}

func TestVerifyReturnsRevokeCheckErrors(t *testing.T) {
	errBoom := errors.New("revoke check failed")
	mod := testModule(&testDriver{revokedTokenErr: errBoom}, PayloadToken)

	_, err := mod.Verify(testToken(t, mod, "tid1"))
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected revoke check error, got %v", err)
	}
	if !errors.Is(err, ErrTokenStoreUnavailable) {
		t.Fatalf("expected store unavailable error, got %v", err)
	}
}

func TestVerifyReturnsPayloadLoadError(t *testing.T) {
	errBoom := errors.New("load failed")
	mod := testModule(&testDriver{loadErr: errBoom}, PayloadStore)

	_, err := mod.Verify(testToken(t, mod, "tid1"))
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected load error, got %v", err)
	}
	if !errors.Is(err, ErrTokenStoreUnavailable) {
		t.Fatalf("expected store unavailable error, got %v", err)
	}
}

func TestVerifyStoreModeRequiresStoredPayload(t *testing.T) {
	mod := testModule(&testDriver{}, PayloadStore)

	_, err := mod.Verify(testToken(t, mod, "tid1"))
	if !errors.Is(err, ErrTokenPayloadMissing) {
		t.Fatalf("expected missing payload error, got %v", err)
	}
}

func TestDefaultDriverHashesRevokedRawTokenKeys(t *testing.T) {
	driver := newDefaultDriver()
	rawToken := "raw.token.value"

	if err := driver.RevokeToken(rawToken, 0); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	if _, ok := driver.tokens[rawToken]; ok {
		t.Fatalf("raw token should not be used as revoke map key")
	}
	sum := sha1.Sum([]byte(rawToken))
	expectedKey := hex.EncodeToString(sum[:])
	if _, ok := driver.tokens[expectedKey]; !ok {
		t.Fatalf("hashed token key missing")
	}
	if hashTokenKey(rawToken) != expectedKey {
		t.Fatalf("expected sha1 hex key %q, got %q", expectedKey, hashTokenKey(rawToken))
	}
	if ok, err := driver.RevokedToken(rawToken); err != nil || !ok {
		t.Fatalf("expected revoked token, ok=%v err=%v", ok, err)
	}
}

func TestDefaultSignerWritesVersionHeader(t *testing.T) {
	signer := &defaultSigner{codec: "token-test-json", secret: "test-secret"}
	token, err := signer.Sign(infra.Token{TokenID: "tid1", Payload: Map{"uid": "u1"}})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token parts: %d", len(parts))
	}
	if strings.Contains(parts[2], "=") {
		t.Fatalf("signature should be raw base64url without padding: %q", parts[2])
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	header := defaultHeader{}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Version != defaultTokenVersion {
		t.Fatalf("expected version %d, got %d", defaultTokenVersion, header.Version)
	}
}

func TestDefaultSignerVerifiesPaddedLegacySignature(t *testing.T) {
	signer := &defaultSigner{codec: "token-test-json", secret: "test-secret"}
	token, err := signer.Sign(infra.Token{TokenID: "tid1", Payload: Map{"uid": "u1"}})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode raw signature: %v", err)
	}
	parts[2] = base64.URLEncoding.EncodeToString(sig)

	if _, err := signer.Verify(strings.Join(parts, ".")); err != nil {
		t.Fatalf("verify padded legacy signature: %v", err)
	}
}

func TestDefaultSignerAcceptsLegacyHeaderWithoutVersion(t *testing.T) {
	signer := &defaultSigner{codec: "token-test-json", secret: "test-secret"}
	header := defaultHeader{ID: "legacy-tid", Auth: true}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(Map{"uid": "u1"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	unsigned := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := defaultSign(unsigned, signer.secret)
	if err != nil {
		t.Fatalf("sign legacy token: %v", err)
	}

	session, err := signer.Verify(unsigned + "." + sig)
	if err != nil {
		t.Fatalf("verify legacy token: %v", err)
	}
	if session.TokenID != "legacy-tid" || !session.Auth {
		t.Fatalf("unexpected legacy session: %+v", session)
	}
}

func TestOpenPanicsOnDriverOpenError(t *testing.T) {
	errBoom := errors.New("open failed")
	mod := testModule(&testDriver{openErr: errBoom}, PayloadToken)

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected panic")
		}
		if !strings.Contains(recovered.(string), errBoom.Error()) {
			t.Fatalf("expected open error in panic, got %v", recovered)
		}
	}()
	mod.Open()
}

func TestSetupPanicsOnUnknownDriver(t *testing.T) {
	mod := &tokenModule{
		signers: map[string]Signer{"default": &defaultSigner{}},
		drivers: map[string]Driver{},
		config:  tokenConfig{Signer: "default", Driver: "missing", Payload: PayloadToken},
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected panic")
		}
		if recovered != "invalid token driver: missing" {
			t.Fatalf("unexpected panic: %v", recovered)
		}
	}()
	mod.Setup()
}
