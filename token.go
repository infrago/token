package token

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

const (
	PayloadToken  = "token"
	PayloadStore  = "store"
	PayloadHybrid = "hybrid"
)

var module = &tokenModule{
	signers: map[string]Signer{},
	drivers: map[string]Driver{},
	config: tokenConfig{
		Signer:  "default",
		Driver:  "default",
		Payload: PayloadToken,
		Setting: Map{},
	},
}

type (
	Signer interface {
		Sign(meta *infra.Meta, req infra.TokenSignRequest) (infra.TokenSession, error)
		Verify(meta *infra.Meta, token string) (infra.TokenSession, error)
	}

	Driver interface {
		Open() error
		Close() error

		SavePayload(meta *infra.Meta, tokenID string, payload Map, exp int64) error
		LoadPayload(meta *infra.Meta, tokenID string) (Map, bool, error)
		DeletePayload(meta *infra.Meta, tokenID string) error

		RevokeToken(meta *infra.Meta, token string, exp int64) error
		RevokeTokenID(meta *infra.Meta, tokenID string, exp int64) error
		RevokedToken(meta *infra.Meta, token string) (bool, error)
		RevokedTokenID(meta *infra.Meta, tokenID string) (bool, error)
	}

	Configurable interface {
		Configure(setting Map)
	}

	SignerEntry struct {
		Name   string
		Signer Signer
	}

	DriverEntry struct {
		Name   string
		Driver Driver
	}

	tokenConfig struct {
		Signer  string
		Driver  string
		Payload string
		Setting Map
	}

	tokenModule struct {
		mutex   sync.RWMutex
		signers map[string]Signer
		drivers map[string]Driver

		config tokenConfig

		signer Signer
		driver Driver
	}
)

func init() {
	module.RegisterSigner("default", &defaultSigner{})
	module.RegisterDriver("default", newDefaultDriver())
	infra.Mount(module)
}

func (m *tokenModule) Register(_ string, value Any) {
	switch v := value.(type) {
	case SignerEntry:
		m.RegisterSigner(v.Name, v.Signer)
	case DriverEntry:
		m.RegisterDriver(v.Name, v.Driver)
	}
}

func (m *tokenModule) Config(global Map) {
	cfg, _ := global["token"].(Map)
	if cfg == nil {
		return
	}
	if v, ok := cfg["signer"].(string); ok && strings.TrimSpace(v) != "" {
		m.config.Signer = strings.TrimSpace(v)
	}
	if v, ok := cfg["driver"].(string); ok && strings.TrimSpace(v) != "" {
		m.config.Driver = strings.TrimSpace(v)
	}
	if v, ok := cfg["payload"].(string); ok && strings.TrimSpace(v) != "" {
		m.config.Payload = normalizePayloadMode(v)
	}
	if v, ok := cfg["setting"].(Map); ok && v != nil {
		m.config.Setting = v
	}
}

func (m *tokenModule) Setup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.signer = m.signers[strings.ToLower(m.config.Signer)]
	m.driver = m.drivers[strings.ToLower(m.config.Driver)]

	if m.signer == nil {
		m.signer = m.signers["default"]
	}
	if m.driver == nil {
		m.driver = m.drivers["default"]
	}
	m.config.Payload = normalizePayloadMode(m.config.Payload)

	if c, ok := m.signer.(Configurable); ok {
		c.Configure(m.config.Setting)
	}
	if c, ok := m.driver.(Configurable); ok {
		c.Configure(m.config.Setting)
	}
}

func (m *tokenModule) Open() {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver != nil {
		_ = driver.Open()
	}
}

func (m *tokenModule) Start() {}
func (m *tokenModule) Stop()  {}

func (m *tokenModule) Close() {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver != nil {
		_ = driver.Close()
	}
}

func (m *tokenModule) Sign(meta *infra.Meta, req infra.TokenSignRequest) (infra.TokenSession, error) {
	m.mutex.RLock()
	signer := m.signer
	driver := m.driver
	payloadMode := m.config.Payload
	m.mutex.RUnlock()

	if signer == nil {
		return infra.TokenSession{}, errors.New("token signer missing")
	}

	origPayload := req.Payload
	signReq := req
	if payloadMode == PayloadStore {
		signReq.Payload = Map{}
	}

	session, err := signer.Sign(meta, signReq)
	if err != nil {
		return infra.TokenSession{}, err
	}

	if driver != nil && (payloadMode == PayloadStore || payloadMode == PayloadHybrid) && session.TokenID != "" {
		if origPayload == nil {
			origPayload = Map{}
		}
		_ = driver.SavePayload(meta, session.TokenID, origPayload, session.Expires)
	}
	if payloadMode == PayloadStore {
		session.Payload = origPayload
	}

	return session, nil
}

func (m *tokenModule) Verify(meta *infra.Meta, token string) (infra.TokenSession, error) {
	m.mutex.RLock()
	signer := m.signer
	driver := m.driver
	payloadMode := m.config.Payload
	m.mutex.RUnlock()

	if signer == nil {
		return infra.TokenSession{}, errors.New("token signer missing")
	}

	session, err := signer.Verify(meta, token)
	if err != nil {
		return infra.TokenSession{}, err
	}

	if driver != nil {
		if ok, _ := driver.RevokedToken(meta, token); ok {
			return infra.TokenSession{}, errors.New("token revoked")
		}
		if ok, _ := driver.RevokedTokenID(meta, session.TokenID); ok {
			return infra.TokenSession{}, errors.New("token id revoked")
		}

		if session.TokenID != "" && (payloadMode == PayloadStore || payloadMode == PayloadHybrid) {
			if stored, ok, err := driver.LoadPayload(meta, session.TokenID); err == nil && ok && stored != nil {
				if payloadMode == PayloadStore {
					session.Payload = stored
				} else {
					session.Payload = mergePayload(session.Payload, stored)
				}
			}
		}
	}

	return session, nil
}

func (m *tokenModule) RevokeToken(meta *infra.Meta, token string, exp int64) error {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver == nil {
		return nil
	}
	return driver.RevokeToken(meta, token, exp)
}

func (m *tokenModule) RevokeTokenID(meta *infra.Meta, tokenID string, exp int64) error {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver == nil {
		return nil
	}
	return driver.RevokeTokenID(meta, tokenID, exp)
}

func (m *tokenModule) RegisterSigner(name string, signer Signer) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || signer == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.signers[name] = signer
}

func (m *tokenModule) RegisterDriver(name string, driver Driver) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || driver == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.drivers[name] = driver
}

func normalizePayloadMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case PayloadStore:
		return PayloadStore
	case PayloadHybrid, "hybird":
		return PayloadHybrid
	default:
		return PayloadToken
	}
}

func mergePayload(tokenPayload, storePayload Map) Map {
	if tokenPayload == nil {
		tokenPayload = Map{}
	}
	if storePayload == nil {
		return tokenPayload
	}
	out := Map{}
	for k, v := range tokenPayload {
		out[k] = v
	}
	for k, v := range storePayload {
		out[k] = v
	}
	return out
}

type defaultSigner struct {
	secret string
	codec  string
}

type defaultHeader struct {
	ID    string `json:"i,omitempty"`
	Begin int64  `json:"b,omitempty"`
	End   int64  `json:"e,omitempty"`
	Auth  bool   `json:"a,omitempty"`
	Role  string `json:"r,omitempty"`
}

func (d *defaultSigner) Configure(setting Map) {
	if v, ok := setting["secret"].(string); ok && strings.TrimSpace(v) != "" {
		d.secret = strings.TrimSpace(v)
	}
	if v, ok := setting["codec"].(string); ok && strings.TrimSpace(v) != "" {
		d.codec = strings.TrimSpace(v)
	}
}

func (d *defaultSigner) Sign(_ *infra.Meta, req infra.TokenSignRequest) (infra.TokenSession, error) {
	now := time.Now().Unix()
	tokenID := req.TokenID
	if tokenID == "" || req.NewID {
		tokenID = infra.Generate()
	}

	header := defaultHeader{ID: tokenID, Auth: req.Auth, Role: req.Role}
	if req.Expires > 0 {
		header.End = now + int64(req.Expires.Seconds())
	}

	payload := req.Payload
	if payload == nil {
		payload = Map{}
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return infra.TokenSession{}, err
	}
	hs, err := infra.EncodeTextBytes(hb)
	if err != nil {
		return infra.TokenSession{}, err
	}

	codec := d.codec
	if codec == "" {
		codec = infra.GOB
	}
	pb, err := infra.Marshal(codec, payload)
	if err != nil {
		return infra.TokenSession{}, err
	}
	ps, err := infra.EncodeTextBytes(pb)
	if err != nil {
		return infra.TokenSession{}, err
	}

	unsigned := hs + "." + ps
	sig, err := defaultSign(unsigned, d.secret)
	if err != nil {
		return infra.TokenSession{}, err
	}
	token := unsigned + "." + sig

	return infra.TokenSession{
		Token:   token,
		TokenID: tokenID,
		Role:    header.Role,
		Auth:    header.Auth,
		Payload: payload,
		Begin:   header.Begin,
		Expires: header.End,
	}, nil
}

func (d *defaultSigner) Verify(_ *infra.Meta, token string) (infra.TokenSession, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return infra.TokenSession{}, errors.New("invalid token")
	}
	unsigned := parts[0] + "." + parts[1]
	if !defaultVerify(unsigned, parts[2], d.secret) {
		return infra.TokenSession{}, errors.New("invalid token sign")
	}

	hb, err := infra.DecodeTextBytes(parts[0])
	if err != nil {
		return infra.TokenSession{}, err
	}
	pb, err := infra.DecodeTextBytes(parts[1])
	if err != nil {
		return infra.TokenSession{}, err
	}

	head := defaultHeader{}
	if err := json.Unmarshal(hb, &head); err != nil {
		return infra.TokenSession{}, err
	}
	now := time.Now().Unix()
	if head.Begin > 0 && now < head.Begin {
		return infra.TokenSession{}, errors.New("token not active")
	}
	if head.End > 0 && now > head.End {
		return infra.TokenSession{}, errors.New("token expired")
	}

	payload := Map{}
	codec := d.codec
	if codec == "" {
		codec = infra.GOB
	}
	if err := infra.Unmarshal(codec, pb, &payload); err != nil {
		if err := json.Unmarshal(pb, &payload); err != nil {
			return infra.TokenSession{}, err
		}
	}
	if payload == nil {
		payload = Map{}
	}

	return infra.TokenSession{
		Token:   token,
		TokenID: head.ID,
		Role:    head.Role,
		Auth:    head.Auth,
		Payload: payload,
		Begin:   head.Begin,
		Expires: head.End,
	}, nil
}

type defaultDriver struct {
	mutex    sync.Mutex
	payloads map[string]payloadItem
	tokens   map[string]int64
	tokenIDs map[string]int64
}

type payloadItem struct {
	data Map
	exp  int64
}

func newDefaultDriver() *defaultDriver {
	return &defaultDriver{
		payloads: map[string]payloadItem{},
		tokens:   map[string]int64{},
		tokenIDs: map[string]int64{},
	}
}

func (d *defaultDriver) Open() error   { return nil }
func (d *defaultDriver) Close() error  { return nil }
func (d *defaultDriver) Configure(Map) {}

func (d *defaultDriver) SavePayload(_ *infra.Meta, tokenID string, payload Map, exp int64) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.payloads[tokenID] = payloadItem{data: payload, exp: exp}
	return nil
}

func (d *defaultDriver) LoadPayload(_ *infra.Meta, tokenID string) (Map, bool, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil, false, nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	item, ok := d.payloads[tokenID]
	if !ok {
		return nil, false, nil
	}
	if item.exp > 0 && time.Now().Unix() > item.exp {
		delete(d.payloads, tokenID)
		return nil, false, nil
	}
	return item.data, true, nil
}

func (d *defaultDriver) DeletePayload(_ *infra.Meta, tokenID string) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	delete(d.payloads, tokenID)
	return nil
}

func (d *defaultDriver) RevokeToken(_ *infra.Meta, token string, exp int64) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.tokens[token] = exp
	return nil
}

func (d *defaultDriver) RevokeTokenID(_ *infra.Meta, tokenID string, exp int64) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.tokenIDs[tokenID] = exp
	return nil
}

func (d *defaultDriver) RevokedToken(_ *infra.Meta, token string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return false, nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	exp, ok := d.tokens[token]
	if !ok {
		return false, nil
	}
	if exp > 0 && time.Now().Unix() > exp {
		delete(d.tokens, token)
		return false, nil
	}
	return true, nil
}

func (d *defaultDriver) RevokedTokenID(_ *infra.Meta, tokenID string) (bool, error) {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return false, nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	exp, ok := d.tokenIDs[tokenID]
	if !ok {
		return false, nil
	}
	if exp > 0 && time.Now().Unix() > exp {
		delete(d.tokenIDs, tokenID)
		return false, nil
	}
	return true, nil
}

func defaultSign(data, secret string) (string, error) {
	if secret == "" {
		secret = defaultSecret()
	}
	if secret == "" {
		return "", errors.New("empty token secret")
	}
	h := hmac.New(sha1.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

func defaultVerify(data, sign, secret string) bool {
	if secret == "" {
		secret = defaultSecret()
	}
	sig, err := base64.URLEncoding.DecodeString(sign)
	if err != nil {
		sig, err = base64.RawURLEncoding.DecodeString(sign)
		if err != nil {
			return false
		}
	}
	h := hmac.New(sha1.New, []byte(secret))
	_, _ = h.Write([]byte(data))
	return hmac.Equal(sig, h.Sum(nil))
}

func defaultSecret() string {
	if v := strings.TrimSpace(os.Getenv("INFRAGO_TOKEN_SECRET")); v != "" {
		return v
	}
	return infra.INFRAGO
}

func RegisterSigner(name string, signer Signer) {
	module.RegisterSigner(name, signer)
}

func RegisterDriver(name string, driver Driver) {
	module.RegisterDriver(name, driver)
}

func Register(name string, value Any) {
	infra.Register(name, value)
}

func Sign(meta *infra.Meta, req infra.TokenSignRequest) (infra.TokenSession, error) {
	return module.Sign(meta, req)
}

func Verify(meta *infra.Meta, token string) (infra.TokenSession, error) {
	return module.Verify(meta, token)
}

func RevokeToken(meta *infra.Meta, token string, exp int64) error {
	return module.RevokeToken(meta, token, exp)
}

func RevokeTokenID(meta *infra.Meta, tokenID string, exp int64) error {
	return module.RevokeTokenID(meta, tokenID, exp)
}
