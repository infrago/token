package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		Signer:   "default",
		Driver:   "default",
		Payload:  PayloadToken,
		IDLength: 16,
		Setting:  Map{},
	},
}

type (
	Signer interface {
		Sign(req infra.Token) (string, error)
		Verify(token string) (infra.Token, error)
	}

	Driver interface {
		Open() error
		Close() error

		SavePayload(tokenID string, payload Map, exp int64) error
		LoadPayload(tokenID string) (Map, bool, error)
		DeletePayload(tokenID string) error

		RevokeToken(token string, exp int64) error
		RevokeTokenID(tokenID string, exp int64) error
		RevokedToken(token string) (bool, error)
		RevokedTokenID(tokenID string) (bool, error)
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
		Signer   string
		Driver   string
		Payload  string
		Secret   string
		IDLength int
		Setting  Map
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
	if v, ok := cfg["secret"].(string); ok {
		m.config.Secret = strings.TrimSpace(v)
	}
	if v, ok := parseConfigInt(cfg["idLength"]); ok {
		m.config.IDLength = v
	} else if v, ok := parseConfigInt(cfg["idlength"]); ok {
		m.config.IDLength = v
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
	m.config.IDLength = normalizeIDLength(m.config.IDLength)

	if c, ok := m.signer.(Configurable); ok {
		c.Configure(m.config.Setting)
	}
	if c, ok := m.driver.(Configurable); ok {
		c.Configure(m.config.Setting)
	}
	if s, ok := m.signer.(interface{ SetSecret(string) }); ok {
		s.SetSecret(m.config.Secret)
	}
	if s, ok := m.signer.(interface{ SetIDLength(int) }); ok {
		s.SetIDLength(m.config.IDLength)
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

func (m *tokenModule) Sign(req infra.Token) (string, error) {
	m.mutex.RLock()
	signer := m.signer
	driver := m.driver
	payloadMode := m.config.Payload
	m.mutex.RUnlock()

	if signer == nil {
		return "", errors.New("token signer missing")
	}

	origPayload := req.Payload
	signReq := req
	if signReq.TokenID == "" {
		signReq.TokenID = infra.GenerateTokenID(m.config.IDLength)
	}
	if payloadMode == PayloadStore {
		signReq.Payload = Map{}
	}

	token, err := signer.Sign(signReq)
	if err != nil {
		return "", err
	}

	if driver != nil && (payloadMode == PayloadStore || payloadMode == PayloadHybrid) && signReq.TokenID != "" {
		if origPayload == nil {
			origPayload = Map{}
		}
		_ = driver.SavePayload(signReq.TokenID, origPayload, signReq.Expires)
	}
	return token, nil
}

func (m *tokenModule) Verify(token string) (infra.Token, error) {
	m.mutex.RLock()
	signer := m.signer
	driver := m.driver
	payloadMode := m.config.Payload
	m.mutex.RUnlock()

	if signer == nil {
		return infra.Token{}, errors.New("token signer missing")
	}

	session, err := signer.Verify(token)
	if err != nil {
		return infra.Token{}, err
	}

	if driver != nil {
		if ok, _ := driver.RevokedToken(token); ok {
			return infra.Token{}, errors.New("token revoked")
		}
		if ok, _ := driver.RevokedTokenID(session.TokenID); ok {
			return infra.Token{}, errors.New("token id revoked")
		}

		if session.TokenID != "" && (payloadMode == PayloadStore || payloadMode == PayloadHybrid) {
			if stored, ok, err := driver.LoadPayload(session.TokenID); err == nil && ok && stored != nil {
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

func (m *tokenModule) RevokeToken(token string, exp int64) error {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver == nil {
		return nil
	}
	return driver.RevokeToken(token, exp)
}

func (m *tokenModule) RevokeTokenID(tokenID string, exp int64) error {
	m.mutex.RLock()
	driver := m.driver
	m.mutex.RUnlock()
	if driver == nil {
		return nil
	}
	return driver.RevokeTokenID(tokenID, exp)
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
	secret   string
	codec    string
	idLength int
}

type defaultHeader struct {
	ID    string `json:"i,omitempty"`
	Begin int64  `json:"b,omitempty"`
	End   int64  `json:"e,omitempty"`
	Auth  bool   `json:"a,omitempty"`
}

func (d *defaultSigner) Configure(setting Map) {
	if v, ok := setting["codec"].(string); ok && strings.TrimSpace(v) != "" {
		d.codec = strings.TrimSpace(v)
	}
}

func (d *defaultSigner) SetSecret(secret string) {
	d.secret = strings.TrimSpace(secret)
}

func (d *defaultSigner) SetIDLength(length int) {
	d.idLength = normalizeIDLength(length)
}

func (d *defaultSigner) Sign(req infra.Token) (string, error) {
	tokenID := req.TokenID
	if tokenID == "" {
		tokenID = infra.GenerateTokenID(d.idLength)
	}

	header := defaultHeader{ID: tokenID, Begin: req.Begin, End: req.Expires, Auth: req.Auth}

	payload := req.Payload
	if payload == nil {
		payload = Map{}
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	hs := base64.RawURLEncoding.EncodeToString(hb)

	codec := d.codec
	if codec == "" {
		codec = infra.GOB
	}
	pb, err := infra.Marshal(codec, payload)
	if err != nil {
		return "", err
	}
	ps := base64.RawURLEncoding.EncodeToString(pb)

	unsigned := hs + "." + ps
	sig, err := defaultSign(unsigned, d.secret)
	if err != nil {
		return "", err
	}
	token := unsigned + "." + sig
	return token, nil
}

func (d *defaultSigner) Verify(token string) (infra.Token, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return infra.Token{}, errors.New("invalid token")
	}
	unsigned := parts[0] + "." + parts[1]
	if !defaultVerify(unsigned, parts[2], d.secret) {
		return infra.Token{}, errors.New("invalid token sign")
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return infra.Token{}, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return infra.Token{}, err
	}

	head := defaultHeader{}
	if err := json.Unmarshal(hb, &head); err != nil {
		return infra.Token{}, err
	}
	now := time.Now().Unix()
	if head.Begin > 0 && now < head.Begin {
		return infra.Token{}, errors.New("token not active")
	}
	if head.End > 0 && now > head.End {
		return infra.Token{}, errors.New("token expired")
	}

	payload := Map{}
	codec := d.codec
	if codec == "" {
		codec = infra.GOB
	}
	if err := infra.Unmarshal(codec, pb, &payload); err != nil {
		if err := json.Unmarshal(pb, &payload); err != nil {
			return infra.Token{}, err
		}
	}
	if payload == nil {
		payload = Map{}
	}

	return infra.Token{
		Token:   token,
		TokenID: head.ID,
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

func (d *defaultDriver) SavePayload(tokenID string, payload Map, exp int64) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.payloads[tokenID] = payloadItem{data: payload, exp: exp}
	return nil
}

func (d *defaultDriver) LoadPayload(tokenID string) (Map, bool, error) {
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

func (d *defaultDriver) DeletePayload(tokenID string) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	delete(d.payloads, tokenID)
	return nil
}

func (d *defaultDriver) RevokeToken(token string, exp int64) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.tokens[token] = exp
	return nil
}

func (d *defaultDriver) RevokeTokenID(tokenID string, exp int64) error {
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.tokenIDs[tokenID] = exp
	return nil
}

func (d *defaultDriver) RevokedToken(token string) (bool, error) {
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

func (d *defaultDriver) RevokedTokenID(tokenID string) (bool, error) {
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
	h := hmac.New(sha256.New, []byte(secret))
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
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(data))
	return hmac.Equal(sig, h.Sum(nil))
}

func defaultSecret() string {
	if project := strings.TrimSpace(infra.Identity().Project); project != "" {
		return project
	}
	return infra.INFRAGO
}

func parseConfigInt(v Any) (int, bool) {
	switch vv := v.(type) {
	case int:
		return vv, true
	case int8:
		return int(vv), true
	case int16:
		return int(vv), true
	case int32:
		return int(vv), true
	case int64:
		return int(vv), true
	case uint:
		return int(vv), true
	case uint8:
		return int(vv), true
	case uint16:
		return int(vv), true
	case uint32:
		return int(vv), true
	case uint64:
		return int(vv), true
	case float32:
		return int(vv), true
	case float64:
		return int(vv), true
	default:
		return 0, false
	}
}

func normalizeIDLength(length int) int {
	if length <= 0 {
		return 16
	}
	if length > 128 {
		return 128
	}
	return length
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

func Sign(req infra.Token) (string, error) {
	return module.Sign(req)
}

func Verify(token string) (infra.Token, error) {
	return module.Verify(token)
}

func RevokeToken(token string, exp int64) error {
	return module.RevokeToken(token, exp)
}

func RevokeTokenID(tokenID string, exp int64) error {
	return module.RevokeTokenID(tokenID, exp)
}
