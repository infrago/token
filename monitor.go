package token

import (
	"github.com/infrago/base"
	"github.com/infrago/infra"
)

func (m *tokenModule) Ready() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.signer != nil
}

func (m *tokenModule) Health() infra.ModuleHealth {
	m.mutex.RLock()
	ready := m.signer != nil
	driver := m.driver != nil
	m.mutex.RUnlock()
	return infra.NewModuleHealth("token", ready, nil, base.Map{"driver": driver})
}

func (m *tokenModule) Stats() infra.ModuleStats {
	m.mutex.RLock()
	ready := m.signer != nil
	driver := m.driver != nil
	payload := m.config.Payload
	m.mutex.RUnlock()
	return infra.NewModuleStats("token", ready, base.Map{"driver": driver, "payload": payload})
}
