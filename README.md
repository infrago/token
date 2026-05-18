# token

`token` 是 infrago 的令牌模块（module: `github.com/infrago/token`）。

## 包定位

- 类型：模块
- 作用：统一 token 的签发、验证、吊销，并支持 payload 在 token/store/hybrid 三种模式。

## 设计（v1）

模块只保留两个可插拔组件：

- `Signer`：签发和验证 token（算法层）
- `Driver`：存储能力（revoke 必选，payload 可选）

`Driver` 统一负责：

- `Open/Close`
- `RevokeToken/RevokeTokenID`
- `RevokedToken/RevokedTokenID`
- `SavePayload/LoadPayload/DeletePayload`

## 配置

```toml
[token]
signer = "default"
driver = "default"
payload = "token"  # token | store | hybrid
secret = "token-secret" # 为空时默认使用 infra.Project

[token.setting]
# signer 和 driver 都可读取本节配置
token_codec = "gob"   # token 内 payload codec，兼容旧键 codec
store_codec = "json"  # driver 存储 payload codec，兼容 payload_codec / driver_codec
```

## payload 模式

- `token`：payload 只在 token 内，driver 主要用于 revoke
- `store`：payload 以 driver 为准
- `hybrid`：token payload + store payload 合并（store 优先）

`store` 模式是强一致读取：签发时 payload 必须成功写入 driver，验证时必须能从 driver 读回 payload。缺少 `tokenId`、payload 不存在、driver 不可用都会导致验证失败。`hybrid` 模式会在 driver 可用且存在存储 payload 时合并，否则保留 token 内 payload。

签发顺序为先写入 store payload，再签名 token；如果签名失败，会调用 `DeletePayload` 尝试清理已经写入的 payload。这样调用方不会拿到一个 payload 未成功落库的 token。

payload codec 分为两类：

- `token_codec` / `signer_codec` / `codec`：默认 signer 用于 token 内 payload。
- `store_codec` / `payload_codec` / `driver_codec`：driver 用于 store payload，默认 `json`。

`codec` 保留为默认 signer 的兼容键；driver 不读取 `codec`，避免旧配置无意改变 store payload 编码。

## 错误语义

模块导出可用于 `errors.Is` 判断的错误：

- `ErrTokenInvalid`
- `ErrTokenInvalidSign`
- `ErrTokenNotActive`
- `ErrTokenExpired`
- `ErrTokenSignerMissing`
- `ErrTokenRevoked`
- `ErrTokenIDRevoked`
- `ErrTokenIDMissing`
- `ErrTokenPayloadMissing`
- `ErrTokenStoreUnavailable`

driver 打不开会在启动阶段失败；签发 payload 写入失败、验证 revoke 检查失败、验证 payload 加载失败都会返回 `ErrTokenStoreUnavailable` 包装后的错误，避免存储异常时放行 token。

调用示例：

```go
session, err := token.Verify(raw)
switch {
case err == nil:
	_ = session
case errors.Is(err, token.ErrTokenExpired):
	// token 已过期
case errors.Is(err, token.ErrTokenRevoked), errors.Is(err, token.ErrTokenIDRevoked):
	// token 或 tokenId 已吊销
case errors.Is(err, token.ErrTokenStoreUnavailable):
	// driver 不可用，按认证失败或服务异常处理
default:
	// 其它 token 无效错误
}
```

## token 格式

内置 signer 生成三段式 token：`base64url(header).base64url(payload).signature`。header 当前版本为 `v=1`，同时保留对早期无 `v` header 的兼容；遇到高于当前实现支持的版本会返回 `ErrTokenInvalid`。签名段使用无 padding 的 `base64.RawURLEncoding`，验证仍兼容历史带 `=` padding 的签名。

## 吊销过期时间

`Meta.RevokeToken` 和 `Meta.RevokeTokenID` 在未显式传入 expires 时，会在目标是当前 token / tokenId 的情况下默认使用当前 token 的 `Expires`，避免吊销记录无意永久保存。也可以直接使用 `RevokeCurrentToken()` / `RevokeCurrentTokenID()`：

```go
if err := ctx.RevokeCurrentTokenID(); err != nil {
	return err
}
```

显式传入 expires 时仍以调用方参数为准；传 `0` 表示永久吊销。

## 过期时间语义

`exp` 使用 Unix 秒，和内置 signer 的验证逻辑一致：当前秒仍有效，超过该秒才过期。驱动共用 `github.com/infrago/token/expire` 中的 helper 来判断过期和计算 TTL，避免不同存储实现出现边界语义差异。

## 默认实现

- `signer=default`：当前内置签名方式
- `driver=default`：内存 revoke + 内存 payload
