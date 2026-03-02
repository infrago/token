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

[token.setting]
# signer 和 driver 都可读取本节配置
```

## payload 模式

- `token`：payload 只在 token 内，driver 主要用于 revoke
- `store`：payload 以 driver 为准
- `hybrid`：token payload + store payload 合并（store 优先）

## 默认实现

- `signer=default`：当前内置签名方式
- `driver=default`：内存 revoke + 内存 payload
