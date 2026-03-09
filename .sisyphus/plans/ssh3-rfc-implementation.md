# SSH3 RFC 合规 Greenfield 重写

## TL;DR

> **Quick Summary**: 在独立 worktree（ssh3-rfc 分支）中，从零重写 SSH3 实现以完全符合 draft-michel-ssh3-00 RFC。采用 h3x 编码风格，remoc RTC 跨进程通信，两进程架构（主进程 HTTP/3 + 子进程 SSH3 会话）。
>
> **Deliverables**:
> - `genmeta-ssh3-proto`: SSH3 wire format codec + Conversation trait + SshSession RTC trait + 错误模型
> - `genmeta-ssh3-server`: Extended CONNECT handler + Ssh3Protocol + PAM 认证 + 子进程管理
> - `genmeta-ssh3-server/src/bin/ssh3-session`: 子进程二进制（PAM + SSH3 会话处理）
> - `genmeta-ssh3-client`: SSH3 客户端连接 + 会话 + 转发
> - 完整 TDD 测试套件 + E2E 冒烟测试
>
> **Estimated Effort**: XL
> **Parallel Execution**: YES — 6 waves
> **Critical Path**: Task 1 → Task 2 → Task 5 → Task 6 → Task 8 → Task 14 → Task 15 → Task 21 → Task 24 → Final

---

## Context

### Original Request
在独立 worktree 中对 SSH3 实现进行 RFC 合规的 greenfield 重写。代码风格参考 h3x（Encode/Decode trait、snafu 错误、newtype、pub(crate)）。Server 端按 axum handler 风格设计。多进程架构使用 remoc RTC。

### Interview Summary
**Key Discussions**:
- **重写策略**: Greenfield — 旧实现仅作参考，不做迁移骨架
- **crate 边界**: 方案 A — 保留现有 crate 名称（proto/client/server/ssh-config），内部全新
- **认证**: MVP 只支持 Basic（password），PAM 4 阶段，子进程执行
- **IPC**: remoc RTC（`#[rtc::remote] trait SshSession`）替代手动消息 enum
- **Protocol 路由**: 全在主进程（Ssh3Protocol.accept_bi → LocalConversation → remoc → RemoteConversation）
- **版本协商**: ssh-version HTTP header，RFC Section 6
- **转发**: TCP + Unix socket + SOCKS5（服务端）
- **排除项**: x11/UDP/agent forwarding、JWT/Bearer/Concealed auth、heartbeat、gateway/gmutils 集成

**Research Findings**:
- h3x Protocol trait 流程：ConnectionBuilder::protocol() → ConnectionState.protocols → accept_bi_stream_task 循环 → Protocol 链
- DHttpProtocol 在 Ssh3Protocol 前注册，优先处理 HTTP/3 frame type
- remoc RTC 宏生成 Client/Server，支持 `provide()/consume()` 一行建连
- conversation_id = CONNECT 的 QUIC stream ID（u64），RFC Section 3 明确
- signal_value = 0xaf3627e6（RFC Section 3.1）

### Metis Review
**Identified Gaps** (addressed):
- VarInt 不重新实现，复用 h3x::varint::VarInt
- 补充 SSH_MSG_CHANNEL_EOF(96) 和 SSH_MSG_CHANNEL_CLOSE(97)
- ForwardPort 语义明确：global request 用于绑定监听，channel open 用于每个新连接
- 增加 Wave 2 后的 E2E 冒烟测试
- 增加 wire format hex dump 对比测试
- 增加 RemoteQuicConnection 序列化 spike 验证

---

## Work Objectives

### Core Objective
从零实现 RFC draft-michel-ssh3-00 合规的 SSH3 协议栈，包含完整的 codec/server/client，采用两进程架构（root 主进程 + 用户权限子进程），所有实现在独立 worktree 中完成。

### Concrete Deliverables
- `genmeta-ssh3-proto/src/`: wire format codec、SshMessage enum、Conversation trait、SshSession RTC trait、错误模型
- `genmeta-ssh3-server/src/`: Extended CONNECT handler、Ssh3Protocol、ChildProcess 管理、PAM wrapper
- `genmeta-ssh3-server/src/bin/ssh3-session.rs`: 子进程入口
- `genmeta-ssh3-client/src/`: 连接建立、会话管理、转发客户端

### Definition of Done
- [ ] `cargo build --workspace` 在 ssh3-rfc worktree 中无错误
- [ ] `cargo test --workspace` 全部通过
- [ ] `cargo clippy --workspace -- -D warnings` 无警告
- [ ] E2E 测试：客户端连接 → Basic 认证 → exec "echo hello" → 收到 "hello\n"
- [ ] TCP 转发测试：direct-tcp + reverse-tcp 端到端验证
- [ ] 多进程测试：主进程 spawn 子进程 → RTC authenticate → run_session

### Must Have
- SSH3 wire format 严格符合 RFC（CBOR 编码、message type 值、signal_value 0xaf3627e6）
- PAM 4 阶段完整调用 + timing attack 防护
- Basic 认证按 scheme 分派，不支持的返回 401 + WWW-Authenticate
- Conversation trait 抽象（LocalConversation + RemoteConversation）
- 版本协商 ssh-version header
- h3x 编码风格（Encode/Decode trait、snafu 错误、newtype、pub(crate)）

### Must NOT Have (Guardrails)
- **不实现** x11 forwarding、UDP forwarding、agent-connection channel
- **不实现** JWT/Bearer、Concealed Auth、OIDC 认证
- **不实现** heartbeat message
- **不集成** gateway 或 gmutils（推迟到单独计划）
- **不重新实现** VarInt — 复用 h3x::varint::VarInt
- **不发明** 不存在的 h3x API — 先验证再使用
- **不设置** tracing event 的 target
- **不使用** h3x::message::unify — HTTP API 用 http crate 类型
- **不预留** AuthCredential 未来变体定义
- **不做** PAM service name 自动降级 fallback
- **不在** 子进程中注册 Protocol 或路由 stream

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: YES（workspace 有 Cargo.toml + 测试框架）
- **Automated tests**: TDD (RED → GREEN → REFACTOR)
- **Framework**: cargo test (Rust built-in)
- **Each task**: 先写失败测试 → 实现通过 → 重构

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Wire format**: cargo test + hex dump 比对
- **Protocol**: cargo test --test integration
- **Server/Client**: tmux 启动服务 → 客户端连接 → 验证输出
- **IPC**: cargo test 子进程 spawn + RTC 调用验证

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — worktree + codec foundation):
├── Task 1: Worktree 创建 + crate 骨架 [quick]
├── Task 2: Wire format codec — CBOR 消息编解码 [deep]
├── Task 3: SSH3 错误模型 [quick]

Wave 2 (After Wave 1 — protocol abstractions):
├── Task 4: Conversation trait + LocalConversation [deep]
├── Task 5: SshMessage enum 完整定义 [unspecified-high]
├── Task 6: Ssh3Protocol (h3x Protocol trait 实现) [deep]

Wave 3 (After Wave 2 — server HTTP layer):
├── Task 7: 版本协商 + 认证解析 [unspecified-high]
├── Task 8: Extended CONNECT handler [deep]
├── Task 9: E2E 冒烟测试骨架 [quick]

Wave 4 (After Wave 2 — multi-process, parallel with Wave 3):
├── Task 10: SshSession RTC trait + SessionInit/AuthError [deep]
├── Task 11: PAM wrapper [unspecified-high]
├── Task 12: ssh3-session 子进程二进制 [deep]
├── Task 13: ChildProcess 主进程管理 [unspecified-high]

Wave 5 (After Wave 3+4 — session + forwarding):
├── Task 14: Channel open/close/data 处理 [deep]
├── Task 15: Exec/Shell/Subsystem 请求处理 [deep]
├── Task 16: PTY 分配 + 终端处理 [unspecified-high]
├── Task 17: Direct-TCP 转发 [unspecified-high]
├── Task 18: Reverse-TCP 转发 (global request + channel open) [deep]
├── Task 19: Streamlocal (Unix socket) 转发 [unspecified-high]
├── Task 20: SOCKS5 代理（服务端） [unspecified-high]

Wave 6 (After Wave 5 — client + integration):
├── Task 21: SSH3 客户端连接 + 认证 [deep]
├── Task 22: 客户端会话 + 转发请求 [deep]
├── Task 23: 客户端 SOCKS5 [unspecified-high]
├── Task 24: 完整 E2E 集成测试 [deep]

Wave FINAL (After ALL tasks — independent review, 4 parallel):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)

Critical Path: T1 → T2 → T5 → T6 → T8 → T14 → T15 → T21 → T24 → FINAL
Parallel Speedup: ~60% faster than sequential
Max Concurrent: 7 (Wave 5)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 2, 3 | 1 |
| 2 | 1 | 4, 5, 6 | 1 |
| 3 | 1 | 6, 7, 8, 11 | 1 |
| 4 | 2 | 6, 8, 10, 14 | 2 |
| 5 | 2 | 6, 14, 15 | 2 |
| 6 | 2, 3, 4, 5 | 8, 9 | 2 |
| 7 | 3 | 8 | 3 |
| 8 | 3, 4, 6, 7 | 9, 24 | 3 |
| 9 | 6, 8 | 24 | 3 |
| 10 | 4 | 12, 13 | 4 |
| 11 | 3 | 12 | 4 |
| 12 | 10, 11 | 13, 24 | 4 |
| 13 | 10, 12 | 24 | 4 |
| 14 | 4, 5 | 15, 17, 18, 19 | 5 |
| 15 | 5, 14 | 16, 24 | 5 |
| 16 | 15 | 24 | 5 |
| 17 | 14 | 20, 24 | 5 |
| 18 | 14 | 24 | 5 |
| 19 | 14 | 24 | 5 |
| 20 | 14, 17 | 23, 24 | 5 |
| 21 | 6, 8 | 22, 24 | 6 |
| 22 | 14, 15, 21 | 23, 24 | 6 |
| 23 | 20, 22 | 24 | 6 |
| 24 | 8, 12, 13, 15, 16, 17, 21, 22 | FINAL | 6 |
| F1-F4 | 24 | — | FINAL |

### Agent Dispatch Summary

- **Wave 1**: **3** — T1 → `quick`, T2 → `deep`, T3 → `quick`
- **Wave 2**: **3** — T4 → `deep`, T5 → `unspecified-high`, T6 → `deep`
- **Wave 3**: **3** — T7 → `unspecified-high`, T8 → `deep`, T9 → `quick`
- **Wave 4**: **4** — T10 → `deep`, T11 → `unspecified-high`, T12 → `deep`, T13 → `unspecified-high`
- **Wave 5**: **7** — T14 → `deep`, T15 → `deep`, T16 → `unspecified-high`, T17 → `unspecified-high`, T18 → `deep`, T19 → `unspecified-high`, T20 → `unspecified-high`
- **Wave 6**: **4** — T21 → `deep`, T22 → `deep`, T23 → `unspecified-high`, T24 → `deep`
- **FINAL**: **4** — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs


### Wave 1: Worktree + Codec Foundation

- [x] 1. Worktree 创建 + Crate 骨架

  **What to do**:
  - 创建 ssh3-rfc 分支和 worktree：`git worktree add ../genmeta-ssh3-rfc ssh3-rfc`
  - 在 worktree 中清空 `genmeta-ssh3-proto/src/lib.rs`、`genmeta-ssh3-server/src/lib.rs`、`genmeta-ssh3-client/src/lib.rs` 的实现内容，只保留空 module 声明
  - 保留 Cargo.toml workspace 结构和依赖声明
  - 添加新依赖：`remoc`（features: ["serde", "codec-bincode"]）、`ciborium`（CBOR）、`snafu`
  - 验证 `cargo check --workspace` 通过（空 crate 应该可编译）
  - 验证 h3x API 可用性：检查 `PendingRequest::with_protocol()`、`Protocol` trait、`ConnectionBuilder::protocol()`、`Router::connect()` 的 pub 可见性

  **Must NOT do**:
  - 不修改 h3x 仓库中的任何代码
  - 不删除 Cargo.toml 中的 workspace 成员

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 纯 scaffolding，创建分支/worktree/空文件
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `git-master`: worktree 创建是简单 git 命令，不需要复杂 git 操作

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 首任务
  - **Blocks**: Tasks 2, 3
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `Cargo.toml`（workspace root）— workspace members 和 dependency 声明
  - `genmeta-ssh3-proto/Cargo.toml` — proto crate 现有依赖

  **API/Type References**:
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs` — Protocol trait pub 可见性验证
  - `/home/yiyue/code/reimu/h3x/src/connection.rs` — ConnectionBuilder::protocol() pub 可见性验证
  - `/home/yiyue/code/reimu/h3x/src/server/route.rs` — Router::connect() 即 Router::on(CONNECT, ...) pub 可见性验证
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/connection.rs` — LocalQuicConnection::into_remote() pub 可见性验证

  **WHY Each Reference Matters**:
  - Cargo.toml：确认 workspace 结构和现有依赖，新增 remoc/ciborium/snafu 时不破坏结构
  - h3x 文件：验证我们计划使用的 API 确实是 pub 的，避免后续 wave 发现 API 不可用

  **Acceptance Criteria**:
  - [ ] ssh3-rfc 分支存在：`git branch --list ssh3-rfc` 有输出
  - [ ] worktree 创建成功：`ls ../genmeta-ssh3-rfc/Cargo.toml` 存在
  - [ ] `cargo check --workspace` 在 worktree 中通过
  - [ ] remoc/ciborium/snafu 依赖已添加到相应 Cargo.toml

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Worktree 可编译
    Tool: Bash
    Preconditions: worktree 已创建
    Steps:
      1. cd ../genmeta-ssh3-rfc && cargo check --workspace
      2. 检查退出码 == 0
    Expected Result: 编译成功，无错误
    Failure Indicators: 任何编译错误
    Evidence: .sisyphus/evidence/task-1-worktree-check.txt

  Scenario: h3x API 可见性验证
    Tool: Bash
    Preconditions: worktree 已创建
    Steps:
      1. 在 proto/src/lib.rs 中写入临时代码引用 h3x Protocol trait 和 ConnectionBuilder
      2. cargo check -p genmeta-ssh3-proto
      3. 恢复 lib.rs
    Expected Result: 编译成功，API 可访问
    Failure Indicators: private 或 not found 错误
    Evidence: .sisyphus/evidence/task-1-api-visibility.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3): create ssh3-rfc worktree with greenfield crate scaffolding`
  - Files: `Cargo.toml`, `genmeta-ssh3-*/Cargo.toml`, `genmeta-ssh3-*/src/lib.rs`
  - Pre-commit: `cargo check --workspace`

- [x] 2. Wire Format Codec — CBOR 消息编解码

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/codec.rs` 实现 SSH3 消息的 CBOR 编解码
  - 定义 SSH3 message header 结构：message type (u8) + payload (CBOR bytes)
  - 实现 h3x 风格的 `Encode` 和 `Decode` trait（参考 h3x::codec）
  - SSH3 消息在 QUIC stream 上的帧格式：按 RFC Section 3.3，每条消息是独立的 CBOR 编码值
  - **复用** `h3x::varint::VarInt` 用于变长整数编码（不重新实现）
  - 实现 newtype 包装：`MessageType(u8)`、`ConversationId(u64)`、`ChannelId(u32)`
  - 使用 `ciborium` crate 进行 CBOR 序列化/反序列化
  - TDD：先写 roundtrip 测试 + hex dump 对比测试，再实现

  **Must NOT do**:
  - 不重新实现 VarInt（复用 h3x::varint::VarInt）
  - 不设置 tracing event 的 target
  - 不引入 serde_cbor（已停维护，用 ciborium）

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 编解码是基础核心，需要仔细对照 RFC wire format 和 h3x 风格
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 1)
  - **Parallel Group**: Wave 1 (with Task 3)
  - **Blocks**: Tasks 4, 5, 6
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/codec.rs:31-106` — Encode/Decode trait 定义，h3x 风格核心参考
  - `/home/yiyue/code/reimu/h3x/src/codec/error.rs` — snafu 错误模式参考
  - `/home/yiyue/code/reimu/h3x/src/varint.rs` — VarInt newtype 包装参考，直接 reuse
  - `/home/yiyue/code/reimu/h3x/src/qpack/field/repr.rs` — 复杂 enum Encode/Decode 参考

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3.3 — SSH3 消息格式定义
  - `https://datatracker.ietf.org/doc/html/draft-michel-ssh3-00#section-3.3`

  **WHY Each Reference Matters**:
  - h3x codec.rs：必须严格复制 Encode/Decode trait 签名风格，保证风格一致
  - h3x varint.rs：直接引用，不重复实现
  - qpack repr.rs：SshMessage 是 tagged enum，编码模式与 QPACK field repr 类似
  - RFC Section 3.3：wire format 权威定义，type 值必须完全匹配

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- codec` — 全部通过
  - [ ] MessageType/ConversationId/ChannelId newtype 定义存在
  - [ ] Encode/Decode trait impl 存在于所有 newtype
  - [ ] hex dump 测试 + roundtrip 测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: CBOR roundtrip 正确性
    Tool: Bash
    Preconditions: codec 模块实现完成
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- codec::roundtrip
      2. 检查退出码 == 0
    Expected Result: encode(value) |> decode == value 对所有消息类型
    Failure Indicators: assertion failed
    Evidence: .sisyphus/evidence/task-2-codec-roundtrip.txt

  Scenario: Wire format hex dump 对比
    Tool: Bash
    Preconditions: codec 模块实现完成
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- codec::wire_format_hex
    Expected Result: 编码结果与 RFC 定义的字节序列一致
    Failure Indicators: hex mismatch
    Evidence: .sisyphus/evidence/task-2-wire-format-hex.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `feat(ssh3-proto): implement CBOR wire format codec with h3x-style Encode/Decode`
  - Files: `genmeta-ssh3-proto/src/codec.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- codec`

- [x] 3. SSH3 错误模型

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/error.rs` 定义 snafu 风格的错误类型
  - 按 h3x error.rs 模式：枚举 + `#[snafu(display(...))]` + context selectors
  - 错误分层：CodecError、ProtocolError、ChannelError、AuthError、SessionError
  - AuthError 和 SessionError 需 `Serialize + Deserialize`（remoc RTC 跨进程要求）
  - 在 `genmeta-ssh3-proto/src/session.rs` 定义 `AuthCredential` enum（Wave 3 Task 7 和 Wave 4 Task 10 均依赖此类型，因此在 Wave 1 尽早定义）：
    ```rust
    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum AuthCredential {
        Password(String),  // Basic auth → base64 decode → password
    }
    ```
  - 不创建 catch-all Error::Other(String)

  **Must NOT do**:
  - 不使用 anyhow/eyre — 用 snafu
  - 不创建 catch-all 错误类型

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 结构化样板工作
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 1, parallel with Task 2)
  - **Parallel Group**: Wave 1 (with Task 2)
  - **Blocks**: Tasks 6, 7, 8, 11
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/codec/error.rs` — snafu 错误模式典范
  - `/home/yiyue/code/reimu/h3x/src/error.rs` — HasErrorCode trait 模式

  **WHY Each Reference Matters**:
  - 必须完全复制 snafu derive 模式保持风格一致
  - AuthError/SessionError 需 Serialize+Deserialize 因为通过 remoc RTC 跨进程传输

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- error` — 通过
  - [ ] 所有错误类型实现 Display + Error + snafu derive
  - [ ] AuthError 和 SessionError 实现 Serialize + Deserialize

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 错误类型完整性
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- error
    Expected Result: 测试通过
    Evidence: .sisyphus/evidence/task-3-error-model.txt

  Scenario: AuthError serde roundtrip
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- error::auth_serde
    Expected Result: serde_json roundtrip 成功
    Evidence: .sisyphus/evidence/task-3-auth-serde.txt

  Scenario: AuthCredential serde roundtrip
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- session::credential_serde
    Expected Result: AuthCredential::Password serde_json roundtrip 成功
    Evidence: .sisyphus/evidence/task-3-credential-serde.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `feat(ssh3-proto): define snafu error model, AuthCredential, and serde-compatible auth errors`
  - Files: `genmeta-ssh3-proto/src/error.rs`, `genmeta-ssh3-proto/src/session.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- error`

---

### Wave 2: Protocol Abstractions

- [x] 4. Conversation Trait + LocalConversation

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/conversation.rs` 定义流类型别名和 `Conversation` trait：
    ```rust
    // === 流类型统一定义 ===
    // SSH3 的 channel stream 是原始 QUIC bidi stream（非 HTTP/3 message stream）
    // 与 h3x Protocol::accept_bi() 接收的 BoxPeekableBiStream<C> 类型一致
    // 定义本 crate 自己的别名以避免与 h3x::message::stream::{ReadStream, WriteStream} 混淆
    pub type Ssh3BiStream<C> = h3x::codec::BoxPeekableBiStream<C>;
    
    pub trait Conversation: Send + Sync {
        /// 打开一个新的双向 channel stream
        async fn open_channel(&self, channel_type: ChannelType, initial_window: u32) -> Result<(ChannelId, Ssh3BiStream<C>), ChannelError>;
        /// 接受对端打开的 channel
        async fn accept_channel(&self) -> Result<(ChannelId, ChannelType, Ssh3BiStream<C>), ChannelError>;
        /// 发送 global request
        async fn send_global_request(&self, request: GlobalRequest) -> Result<GlobalReply, ProtocolError>;
        /// 接收 global request
        async fn recv_global_request(&self) -> Result<GlobalRequest, ProtocolError>;
        /// 关闭整个 conversation
        async fn close(&self) -> Result<(), ProtocolError>;
    }
    ```
  - **流类型约定**（解决 h3x 中多种 stream 类型的混淆）：
    - `Ssh3BiStream<C>` = `h3x::codec::BoxPeekableBiStream<C>`（原始 QUIC 双向流，带 peekable reader + sink writer）
    - 这是 Protocol::accept_bi() 接收和返回的同一类型
    - 与 `h3x::message::stream::{ReadStream, WriteStream}`（HTTP/3 消息层流）完全不同，不要混淆
  - 实现 `LocalConversation`：
    - 持有 QUIC connection 引用（`Arc<QuicConnection<C>>`）用于直接打开 bidi stream
    - 内部 `inbound: mpsc::Receiver<Ssh3BiStream<C>>` 接收 Ssh3Protocol 路由过来的 stream
    - `conversation_id: ConversationId` 标识
    - 方法实现通过 QUIC bidi stream 发送 signal_value(0xaf3627e6) + conversation_id 前缀
  - 实现 `RemoteConversation`：
    - 作为 remoc RTC 远程可传递的代理类型
    - 实现 `Serialize + Deserialize + Send + 'static`（RemoteSend）
    - 内部通过 remoc channel 中继到主进程的 LocalConversation
    - 这是传递给子进程 `run_session()` 的参数
  - **RemoteQuicConnection spike**：在测试中验证 `LocalQuicConnection::into_remote()` 生成的 `RemoteQuicConnection` 能通过 remoc 序列化传递到子进程并成功打开 bidi stream
  - TDD：先写 trait 定义编译测试 + LocalConversation 构造测试

  **Must NOT do**:
  - 不在子进程中直接访问 QUIC connection — 通过 RemoteConversation 中继
  - 不发明不存在的 h3x API — 先验证 LocalQuicConnection::into_remote() 可用性
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Conversation 是核心抽象，涉及 QUIC stream 管理、remoc 序列化、两种实现的一致性
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - 无特殊技能需求，深度理解 h3x + remoc 即可

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6)
  - **Blocks**: Tasks 6, 8, 10, 14
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/connection.rs` — LocalQuicConnection/RemoteQuicConnection，into_remote() API 和序列化模式
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/stream.rs` — Local/Remote ReadStream/WriteStream 中继模式
  - `/home/yiyue/code/reimu/h3x/src/dhttp/protocol.rs:accept_bi()` — DHttpProtocol 如何接受 bidi stream 并推入 channel

  **API/Type References**:
  - RFC Section 3.1 — signal_value 0xaf3627e6 + conversation_id 作为 stream 前缀
  - `/home/yiyue/code/reimu/h3x/src/varint.rs` — VarInt 用于 signal_value 和 conversation_id 编码

  **External References**:
  - `https://docs.rs/remoc/latest/remoc/` — remoc RTC provide/consume API
  - RFC draft-michel-ssh3-00 Section 3 — conversation 概念定义

  **WHY Each Reference Matters**:
  - h3x remoc connection：RemoteConversation 的中继模式直接参考 RemoteQuicConnection 的实现
  - DHttpProtocol：LocalConversation 的 inbound channel 模式参考 DHttpProtocol 的 RingChannel 推送模式
  - RFC Section 3.1：stream 前缀格式（signal_value + conversation_id）是 wire format 规范

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- conversation` — 全部通过
  - [ ] Conversation trait 定义编译通过
  - [ ] LocalConversation 构造 + open_channel 测试通过
  - [ ] RemoteConversation 实现 Serialize + Deserialize
  - [ ] RemoteQuicConnection spike 测试通过（序列化 + 反序列化 + 打开 bidi stream）

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Conversation trait 编译兼容性
    Tool: Bash
    Preconditions: Task 2 codec 完成
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- conversation::trait_compile
      2. 检查退出码 == 0
    Expected Result: trait 定义 + LocalConversation 基础实现编译通过
    Failure Indicators: compile error
    Evidence: .sisyphus/evidence/task-4-conversation-trait.txt

  Scenario: RemoteQuicConnection 序列化 spike
    Tool: Bash
    Preconditions: h3x remoc 模块可用
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- conversation::remote_spike
    Expected Result: LocalQuicConnection::into_remote() → serde roundtrip → 可用
    Failure Indicators: 序列化失败或 bidi stream 打开失败
    Evidence: .sisyphus/evidence/task-4-remote-spike.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(ssh3-proto): implement Conversation trait with Local/Remote variants`
  - Files: `genmeta-ssh3-proto/src/conversation.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- conversation`

- [x] 5. SshMessage Enum 完整定义

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/message.rs` 定义所有 SSH3 消息类型：
    ```rust
    pub enum SshMessage {
        // Channel 生命周期
        ChannelOpen(ChannelOpenMsg),           // type 90
        ChannelOpenConfirmation(ChannelOpenConfirmationMsg), // type 91
        ChannelOpenFailure(ChannelOpenFailureMsg),         // type 92
        ChannelWindowAdjust(ChannelWindowAdjustMsg),       // type 93
        ChannelData(ChannelDataMsg),           // type 94
        ChannelRequest(ChannelRequestMsg),     // type 95
        ChannelEOF(ChannelEOFMsg),             // type 96
        ChannelClose(ChannelCloseMsg),         // type 97
        // Global
        GlobalRequest(GlobalRequestMsg),
        GlobalReply(GlobalReplyMsg),
    }
    ```
  - 每个消息子结构体的字段严格按 RFC Section 4/5 定义
  - ChannelType enum：`Session`, `DirectTcp`, `ForwardedTcp`, `DirectStreamlocal`, `ForwardedStreamlocal`
  - ChannelRequest sub-types：`PtyReq`, `Shell`, `Exec`, `Subsystem`, `WindowChange`, `Signal`, `ExitStatus`, `ExitSignal`, `Env`
  - GlobalRequest sub-types：`TcpipForward`, `CancelTcpipForward`, `StreamlocalForward`, `CancelStreamlocalForward`
  - 所有类型实现 Task 2 的 Encode/Decode trait（CBOR 编解码）
  - TDD：先写每个 message type 的 roundtrip + hex dump 测试

  **Must NOT do**:
  - 不添加 RFC 未定义的消息类型
  - 不将 message type 值硬编码为 magic number — 使用 MessageType newtype 常量
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 大量结构体定义 + 编解码实现，量大但模式统一
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 4, 6)
  - **Blocks**: Tasks 6, 14, 15
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/qpack/field/repr.rs` — 复杂 tagged enum Encode/Decode 参考
  - `genmeta-ssh3-proto/src/messages.rs`（旧实现）— 消息类型列表参考（但字段名/格式以 RFC 为准）

  **API/Type References**:
  - RFC Section 4 — Channel 消息格式定义（90-97）
  - RFC Section 5 — Global request 消息格式定义
  - `https://datatracker.ietf.org/doc/html/draft-michel-ssh3-00#section-4`

  **WHY Each Reference Matters**:
  - qpack repr.rs：SshMessage 是 tagged enum（根据 type 字节分派），与 QPACK FieldRepr 编码模式一致
  - 旧 messages.rs：字段列表参考，但值和格式以 RFC 为权威
  - RFC Section 4/5：消息格式权威定义，字段名/类型/值必须完全匹配

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- message` — 全部通过
  - [ ] 所有 10 种 message type 已定义（90-97 + GlobalRequest + GlobalReply）
  - [ ] 所有 ChannelType 变体已定义
  - [ ] 所有 ChannelRequest sub-type 已定义
  - [ ] 所有 GlobalRequest sub-type 已定义
  - [ ] 每种消息 roundtrip 测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 全消息类型 roundtrip
    Tool: Bash
    Preconditions: codec (Task 2) 完成
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- message::roundtrip
    Expected Result: 所有 10 种消息 encode → decode roundtrip 一致
    Failure Indicators: assertion failed on any message type
    Evidence: .sisyphus/evidence/task-5-message-roundtrip.txt

  Scenario: Message type 值符合 RFC
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- message::type_values
    Expected Result: ChannelOpen=90, ChannelOpenConfirmation=91, ..., ChannelClose=97
    Failure Indicators: type value mismatch
    Evidence: .sisyphus/evidence/task-5-type-values.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(ssh3-proto): define complete SshMessage enum with RFC-compliant CBOR codec`
  - Files: `genmeta-ssh3-proto/src/message.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- message`

- [x] 6. Ssh3Protocol — h3x Protocol Trait 实现

  **What to do**:
  - 在 `genmeta-ssh3-server/src/protocol.rs` 实现 `h3x::protocol::Protocol` trait：
    ```rust
    use h3x::codec::BoxPeekableBiStream;
    use h3x::protocol::{Protocol, StreamVerdict};
    use genmeta_ssh3_proto::conversation::Ssh3BiStream; // = BoxPeekableBiStream<C>
    
    impl<C: QuicConnection> Protocol<C> for Ssh3Protocol<C> {
        // 注意：h3x Protocol trait 的实际签名是：
        //   fn accept_bi(&self, conn: &Arc<QuicConnection<C>>, stream: BoxPeekableBiStream<C>)
        //     -> BoxFuture<Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>>
        fn accept_bi<'a>(
            &'a self,
            connection: &'a Arc<QuicConnection<C>>,
            stream: BoxPeekableBiStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
            Box::pin(async move {
                let (mut reader, writer) = stream;
                // 1. peek signal_value (VarInt 0xaf3627e6)
                // 2. 若匹配，读取 conversation_id (VarInt)
                // 3. 查找注册的 conversation → 推入 inbound mpsc（类型为 Ssh3BiStream<C>）
                // 4. 返回 Ok(StreamVerdict::Accepted)
                // 若不匹配 → reader.reset() + Ok(StreamVerdict::Passed((reader, writer)))
            })
        }
    }
    ```
  - `Ssh3Protocol` 内部结构：
    - `conversations: Arc<RwLock<HashMap<ConversationId, mpsc::Sender<Ssh3BiStream<C>>>>>`
    - 注意：流类型统一使用 `Ssh3BiStream<C>` ( = `BoxPeekableBiStream<C>`)，与 Task 4 LocalConversation 的 inbound 类型一致
    - `register_conversation(id, sender)` 方法 — 由 Extended CONNECT handler 调用
    - `unregister_conversation(id)` 方法 — conversation 结束时清理
  - Ssh3ProtocolFactory 实现 `ProductProtocol` trait（h3x 中的 ProtocolFactory 跟名为 ProductProtocol）
  - 注册在 DHttpProtocol 之后：非 HTTP/3 stream 先被 DHttp reject → 到 Ssh3Protocol
  - TDD：写 mock QUIC stream 测试 signal_value 匹配/不匹配

  **Must NOT do**:
  - 不在子进程中注册 Protocol 或路由 stream — 全在主进程
  - 不发明不存在的 h3x API — 验证 Protocol trait 方法签名
  - 不处理 HTTP/3 frame type — 那是 DHttpProtocol 的职责
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: h3x Protocol trait 集成是核心难点，需要理解 stream 路由链
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Tasks 2, 3, 4, 5 完成)
  - **Parallel Group**: Wave 2 尾部（依赖同 Wave 其他 task）
  - **Blocks**: Tasks 8, 9
  - **Blocked By**: Tasks 2, 3, 4, 5

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs` — Protocol trait 定义 + StreamVerdict enum
  - `/home/yiyue/code/reimu/h3x/src/dhttp/protocol.rs:accept_bi()` — DHttpProtocol 的 peek + dispatch 模式
  - `/home/yiyue/code/reimu/h3x/src/connection.rs:accept_bi_stream_task()` — Protocol 链调用流程

  **API/Type References**:
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs:138-163` — Protocol trait 完整定义（accept_bi 接收 `BoxPeekableBiStream<C>`）
  - `/home/yiyue/code/reimu/h3x/src/codec.rs:26-29` — `BoxPeekableBiStream<C>` 类型定义 = `(PeekableStreamReader<...>, SinkWriter<...>)`
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs:156-163` — StreamVerdict enum（Accepted / Passed(S)）
  - `genmeta-ssh3-proto/src/conversation.rs:Ssh3BiStream<C>`（Task 4 定义）— 与 Protocol accept_bi 的流类型一致
  - RFC Section 3.1 — signal_value 0xaf3627e6 位置和格式

  **WHY Each Reference Matters**:
  - Protocol trait：必须精确匹配 accept_bi 签名，StreamVerdict 返回值正确
  - DHttpProtocol：参考 peek 模式（读取前几个字节判断是否属于本协议）
  - connection.rs：理解 Protocol 链如何被调用，Passed 如何传递到下一个

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- protocol` — 全部通过
  - [ ] Ssh3Protocol 实现 Protocol trait（编译通过）
  - [ ] signal_value 匹配 → Accepted 测试通过
  - [ ] signal_value 不匹配 → Passed 测试通过
  - [ ] register/unregister conversation 测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: signal_value 匹配路由
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- protocol::signal_match
    Expected Result: 包含 0xaf3627e6 前缀的 stream → Accepted + 推入对应 conversation
    Failure Indicators: 返回 Passed 或推入错误 conversation
    Evidence: .sisyphus/evidence/task-6-signal-match.txt

  Scenario: 非 SSH3 stream 透传
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- protocol::signal_mismatch
    Expected Result: 不含 SSH3 signal_value 的 stream → Passed
    Failure Indicators: 返回 Accepted
    Evidence: .sisyphus/evidence/task-6-signal-mismatch.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(ssh3-server): implement Ssh3Protocol with signal_value stream routing`
  - Files: `genmeta-ssh3-server/src/protocol.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- protocol`

---

### Wave 3: Server HTTP Layer

- [x] 7. 版本协商 + 认证解析

  **What to do**:
  - 在 `genmeta-ssh3-server/src/auth.rs` 实现 HTTP 认证解析（`AuthCredential` 已在 Task 3 中定义于 `genmeta-ssh3-proto/src/session.rs`，此处仅 use）：
    ```rust
    use genmeta_ssh3_proto::session::AuthCredential;
    
    pub struct AuthResult {
        pub username: String,
        pub credential: AuthCredential,
    }
    
    /// 解析 Authorization header，按 scheme 分派
    /// 不支持的 scheme 返回 Err(AuthParseError::UnsupportedScheme)
    pub fn parse_authorization(header: &http::HeaderValue) -> Result<AuthResult, AuthParseError>;
    ```
  - 在 `genmeta-ssh3-server/src/version.rs` 实现版本协商：
    ```rust
    pub const SSH3_VERSION: &str = "michel-ssh3-00";
    
    /// 解析 ssh-version header（逗号分隔列表），返回匹配的版本
    /// 无匹配返回 None
    pub fn negotiate_version(client_versions: &str) -> Option<&'static str>;
    ```
  - 不支持的认证 scheme 返回 HTTP 401 + WWW-Authenticate: Basic
  - 版本不匹配返回 HTTP 403
  - 使用 `http` crate 类型（HeaderValue, StatusCode），不用 h3x::message::unify
  - TDD：测试 Basic 解析（正常/畸形）、不支持 scheme（Bearer/unknown）、版本协商

  **Must NOT do**:
  - 不实现 JWT/Bearer/Concealed Auth — 只处理 Basic scheme
  - 不使用 h3x::message::unify — 用 http crate 原生类型
  - 不预留 AuthCredential 未来变体
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: HTTP 头解析逻辑明确但需要处理各种边界情况
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 8, 9)
  - **Blocks**: Task 8
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/auth.rs`（旧实现）— Basic 解析参考（注意修复安全问题）

  **API/Type References**:
  - RFC Section 6 — ssh-version header 格式
  - RFC Section 6.1 — Authorization header + Basic scheme 要求
  - `https://datatracker.ietf.org/doc/html/draft-michel-ssh3-00#section-6`
  - RFC 9729 — Concealed Auth 格式参考（不实现，仅用于返回正确的 401 格式）

  **WHY Each Reference Matters**:
  - 旧 auth.rs：可参考 Basic 解析逻辑但必须修复已知安全问题（timing attack 等）
  - RFC Section 6：版本协商精确格式（逗号分隔、选择规则）
  - RFC Section 6.1：Authorization header 格式要求

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- auth` — 全部通过
  - [ ] `cargo test -p genmeta-ssh3-server -- version` — 全部通过
  - [ ] Basic auth 正确解析 base64 username:password
  - [ ] 不支持的 scheme 返回 UnsupportedScheme 错误
  - [ ] 版本协商对 "michel-ssh3-00" 返回 Some，对 "unknown-v1" 返回 None

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Basic auth 正常解析
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- auth::parse_basic_valid
    Expected Result: "Basic dXNlcjpwYXNz" → username="user", credential=Password("pass")
    Failure Indicators: 解析失败或字段不匹配
    Evidence: .sisyphus/evidence/task-7-auth-basic.txt

  Scenario: 不支持的认证 scheme
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- auth::parse_unsupported_scheme
    Expected Result: "Bearer token123" → Err(UnsupportedScheme("Bearer"))
    Failure Indicators: 错误地尝试解析或返回错误类型
    Evidence: .sisyphus/evidence/task-7-auth-unsupported.txt

  Scenario: 版本协商匹配
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- version::negotiate
    Expected Result: "michel-ssh3-00,other-v1" → Some("michel-ssh3-00")
    Failure Indicators: 返回 None 或匹配错误版本
    Evidence: .sisyphus/evidence/task-7-version-negotiate.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `feat(ssh3-server): implement version negotiation and auth header parsing`
  - Files: `genmeta-ssh3-server/src/auth.rs`, `genmeta-ssh3-server/src/version.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- auth version`

- [x] 8. Extended CONNECT Handler

  **What to do**:
  - 在 `genmeta-ssh3-server/src/handler.rs` 实现 h3x Service 风格的 Extended CONNECT 处理器：
    ```rust
    /// SSH3 Extended CONNECT handler
    /// 注册路由：Router::connect("/.well-known/ssh3", Ssh3ConnectService::new(...))
    ///
    /// h3x Service trait 签名：
    ///   fn serve(&self, request: &mut h3x::server::Request, response: &mut h3x::server::Response)
    ///
    /// handler 获取 stream_id 的方式：
    ///   let stream_id = request.read_stream().stream_id().await?;
    ///   // stream_id 即为 conversation_id（按 RFC Section 3）
    ///
    /// handler 获取共享状态的方式：
    ///   Ssh3ConnectService 结构体持有 Arc<Ssh3Protocol<C>> 和 Arc<ChildProcessManager>，
    ///   实现 Clone + Service，通过 self 访问共享状态（类似 axum State 模式）
    pub struct Ssh3ConnectService<C> {
        ssh3_protocol: Arc<Ssh3Protocol<C>>,
        child_process_manager: Arc<ChildProcessManager>,
    }
    
    impl<C: QuicConnection> Service for Ssh3ConnectService<C> {
        type Future<'s> = BoxServiceFuture<'s>;
        fn serve<'s>(&self, request: &'s mut h3x::server::Request, response: &'s mut h3x::server::Response) -> Self::Future<'s> {
            // 1. request.headers().get("authorization") → Task 7 的 parse_authorization()
            // 2. request.headers().get("ssh-version") → Task 7 的 negotiate_version()
            // 3. let conversation_id = request.read_stream().stream_id().await?;
            //    （CONNECT stream 的 QUIC stream ID 即为 conversation_id）
            // 4. 创建 LocalConversation + 注册到 self.ssh3_protocol
            // 5. fork+exec 子进程（self.child_process_manager）
            // 6. remoc Connect::io_buffered() → consume() 获取 SshSessionClient
            // 7. session.authenticate(SessionInit { username, credential, ... })
            // 8. session.run_session(remote_conversation)
            // 9. 返回 HTTP 200 response
        }
    }
    ```
  - `Ssh3ConnectService` 实现 `Clone`（内部全是 Arc）+ `h3x::server::Service`
  - stream_id 通过 `request.read_stream().stream_id().await?` 获取（h3x Request 提供此 API）
  - Ssh3Protocol + ChildProcessManager 通过 Service 结构体的 self 字段访问
  - 注册方式：`Router::connect("/.well-known/ssh3", Ssh3ConnectService::new(protocol, manager))`
  - 错误处理：
    - 无 Authorization header → HTTP 401 + WWW-Authenticate: Basic
    - 不支持的 scheme → HTTP 401
    - 版本不匹配 → HTTP 403
    - 认证失败（PAM 拒绝）→ HTTP 403
    - 内部错误 → HTTP 500
  - HTTP header 读取使用 `request.headers()` / `request.header(name)` (h3x Request API，内部使用 http crate 类型)
  - TDD：mock 依赖测试 handler 各分支

  **Must NOT do**:
  - 不直接使用 `http::Request<()>` 作为 handler 参数 — h3x Service trait 给出 `&mut h3x::server::Request`，http crate 类型通过 Request API 间接使用
  - 不使用 h3x::message::unify
  - 不在 handler 中直接执行 PAM — PAM 在子进程中通过 RTC 执行
  - 不在子进程中注册 Protocol — handler 在主进程注册 conversation 路由
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 核心集成点，连接 HTTP 层和 SSH3 会话层，流程复杂
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 Wave 3 内的 Task 7）
  - **Parallel Group**: Wave 3 后半
  - **Blocks**: Tasks 9, 24
  - **Blocked By**: Tasks 3, 4, 6, 7

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/server/route.rs` — Router::connect() 注册模式
  - `genmeta-ssh3-server/src/lib.rs`（旧实现）— fork 模式参考

  **API/Type References**:
  - `h3x::server::Router::connect(path, service)` — 等价于 Router::on(CONNECT, path, service)
  - `h3x::server::message::Request` — handler 接收的请求类型，提供 `headers()`, `header(name)`, `method()`, `read_stream()` 等方法
  - `h3x::server::message::Response` — handler 的响应类型，提供 `write_stream()` 等方法
  - `/home/yiyue/code/reimu/h3x/src/server/message.rs:60-147` — Request 结构体完整 API，包括 `read_stream()` 和 `headers()`
  - `/home/yiyue/code/reimu/h3x/src/server.rs:144-145` — `read_stream.stream_id().await` 获取 stream ID 的示例
  - `h3x::server::Service` trait — `fn serve(&self, request: &mut Request, response: &mut Response)`
  - `h3x::connection::ConnectionBuilder::protocol(factory)` — Protocol 注册入口
  - RFC Section 3 — Extended CONNECT URI 和流程（conversation_id = CONNECT stream 的 QUIC stream ID）
  - `https://datatracker.ietf.org/doc/html/draft-michel-ssh3-00#section-3`

  **External References**:
  - `https://docs.rs/remoc/latest/remoc/connect/struct.Connect.html` — io_buffered + consume

  **WHY Each Reference Matters**:
  - Router::connect()：handler 注册方式
  - 旧 lib.rs fork 模式：参考 fork+exec 流程但使用新的 remoc RTC 替代旧 IPC
  - RFC Section 3：CONNECT URI path 和完整流程权威定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- handler` — 全部通过
  - [ ] handler 正确解析 Authorization → 分派认证
  - [ ] 版本不匹配 → 403 测试通过
  - [ ] 缺少 Authorization → 401 + WWW-Authenticate 测试通过
  - [ ] handler 正确创建 LocalConversation + 注册到 Ssh3Protocol

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 正常认证流程
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- handler::connect_basic_auth
    Expected Result: 带有效 Basic auth + 正确版本的 CONNECT → 200 + conversation 已注册
    Failure Indicators: 非 200 响应或 conversation 未注册
    Evidence: .sisyphus/evidence/task-8-handler-auth.txt

  Scenario: 版本不匹配拒绝
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- handler::connect_version_mismatch
    Expected Result: ssh-version: "unknown-v1" → HTTP 403
    Failure Indicators: 非 403 响应
    Evidence: .sisyphus/evidence/task-8-handler-version.txt

  Scenario: 缺少认证头
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- handler::connect_no_auth
    Expected Result: 无 Authorization header → HTTP 401 + WWW-Authenticate: Basic
    Failure Indicators: 非 401 或缺少 WWW-Authenticate header
    Evidence: .sisyphus/evidence/task-8-handler-no-auth.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `feat(ssh3-server): implement Extended CONNECT handler with auth + version negotiation`
  - Files: `genmeta-ssh3-server/src/handler.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- handler`

- [x] 9. E2E 冒烟测试骨架

  **What to do**:
  - 在 `genmeta-ssh3-server/tests/e2e.rs` 创建集成测试骨架：
    - 启动 QUIC listener + TLS（使用 self-signed test certs）
    - ConnectionBuilder 注册 DHttpProtocol + Ssh3Protocol
    - Router 注册 `/.well-known/ssh3` CONNECT handler
    - 使用 in-process client（不走完整 fork，mock 子进程）连接并验证
  - 初始测试场景（此阶段只验证 HTTP 层）：
    - `connect_auth_exec_smoke`：连接 → Basic auth → 版本协商 → 200
    - `connect_wrong_version`：错误版本 → 403
    - `connect_no_auth`：无认证 → 401
  - 创建测试工具模块 `tests/common/mod.rs`：
    - `setup_test_server()` → (addr, server_handle)
    - `test_client(addr)` → h3x client connection
    - 自签名证书生成辅助函数
  - RemoteQuicConnection 序列化验证也在此 spike
  - TDD：测试先写，确认 handler 流程可以 E2E 跑通

  **Must NOT do**:
  - 不测试完整 SSH3 会话（那是 Wave 6 的 Task 24）
  - 不测试 PAM（需要 root 权限）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 集成测试骨架 + 测试工具搭建，模式明确
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 Task 6, 8）
  - **Parallel Group**: Wave 3 尾部
  - **Blocks**: Task 24
  - **Blocked By**: Tasks 6, 8

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/tests/`（如有旧测试）— 测试结构参考

  **API/Type References**:
  - `h3x::ConnectionBuilder` — 构建 server connection
  - `h3x::server::Router` — 路由注册
  - `h3x::PendingRequest` — 客户端 CONNECT 请求

  **WHY Each Reference Matters**:
  - ConnectionBuilder：测试中需要构建完整 server connection 并注册 protocol chain
  - Router：验证 CONNECT 路径注册
  - PendingRequest：测试客户端用 connect() 发起 Extended CONNECT

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server --test e2e` — 全部通过
  - [ ] 至少 3 个 E2E 测试场景运行
  - [ ] test_server + test_client 工具函数可复用

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: E2E 冒烟测试通过
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server --test e2e -- --nocapture
    Expected Result: 3 个场景全部 PASS
    Failure Indicators: 任何测试失败或连接超时
    Evidence: .sisyphus/evidence/task-9-e2e-smoke.txt

  Scenario: 测试工具函数复用性
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server --test e2e -- connect_auth 2>&1 | grep "test result"
    Expected Result: 输出 "test result: ok"
    Failure Indicators: 编译错误或测试失败
    Evidence: .sisyphus/evidence/task-9-e2e-reusable.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `test(ssh3-server): add E2E smoke test skeleton with test utilities`
  - Files: `genmeta-ssh3-server/tests/e2e.rs`, `genmeta-ssh3-server/tests/common/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server --test e2e`

---

### Wave 4: Multi-Process Architecture

- [ ] 10. SshSession RTC Trait + SessionInit/AuthError

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/session.rs` 添加 RTC trait（该文件已由 Task 3 创建并包含 `AuthCredential` enum）：
    ```rust
    use crate::error::{AuthError, SessionError};
    use crate::conversation::RemoteConversation;
    
    #[rtc::remote]
    pub trait SshSession: Sync {
        async fn authenticate(&mut self, init: SessionInit) -> Result<(), AuthError>;
        async fn run_session(&mut self, conv: RemoteConversation) -> Result<(), SessionError>;
    }
    
    // AuthCredential 已在 Task 3 中定义（同文件），此处不重复定义
    
    #[derive(Serialize, Deserialize)]
    pub struct SessionInit {
        pub username: String,
        pub credential: AuthCredential,
        pub client_addr: SocketAddr,
        pub pam_service_name: String,
    }
    ```
  - `#[rtc::remote]` 宏自动生成 `SshSessionClient` / `SshSessionServer`（或 `SshSessionServerSharedMut`）
  - SessionInit 字段：username (String)、credential (AuthCredential)、client_addr (SocketAddr)、pam_service_name (String)
  - AuthCredential 已在 Task 3 定义，MVP 只有 Password(String)，不预留其他变体
  - 验证 rtc 宏生成的 Client/Server 类型可编译
  - TDD：写编译测试验证 trait + 生成类型
  **Must NOT do**:
  - 不重复定义 AuthCredential（已在 Task 3 定义）
  - 不预留 AuthCredential 未来变体
  - 不实现具体的会话逻辑（那是 Task 12）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: RTC 宏需要仔细理解，RemoteSend 约束影响所有参数/返回值类型
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 11, 12, 13)
  - **Blocks**: Tasks 12, 13
  - **Blocked By**: Task 4

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/conversation.rs`（Task 4）— RemoteConversation 类型作为 run_session 参数

  **API/Type References**:
  - `genmeta-ssh3-proto/src/error.rs`（Task 3）— AuthError/SessionError 定义

  **External References**:
  - `https://docs.rs/remoc/latest/remoc/rtc/` — rtc::remote 宏、provide/consume API
  - `https://docs.rs/remoc/latest/remoc/connect/struct.Connect.html` — io_buffered 用法

  **WHY Each Reference Matters**:
  - conversation.rs：RemoteConversation 是 run_session 的参数，必须实现 RemoteSend
  - error.rs：AuthError/SessionError 被 RTC 方法返回，必须 Serialize + Deserialize
  - remoc rtc 文档：理解 Server/Client 生成规则和约束

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- session` — 全部通过
  - [ ] SshSession trait 上的 `#[rtc::remote]` 宏编译通过
  - [ ] SshSessionClient / SshSessionServerSharedMut 类型存在
  - [ ] SessionInit 实现 Serialize + Deserialize
  - [ ] AuthCredential 只有 Password 变体

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: RTC 宏生成验证
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- session::rtc_compile
    Expected Result: SshSessionClient 和 SshSessionServerSharedMut 可构造
    Failure Indicators: 宏展开错误或类型不存在
    Evidence: .sisyphus/evidence/task-10-rtc-compile.txt

  Scenario: SessionInit serde roundtrip
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- session::init_serde
    Expected Result: SessionInit 可 serde_json roundtrip
    Failure Indicators: 序列化/反序列化失败
    Evidence: .sisyphus/evidence/task-10-init-serde.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(ssh3-proto): define SshSession RTC trait with SessionInit and auth types`
  - Files: `genmeta-ssh3-proto/src/session.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- session`

- [ ] 11. PAM Wrapper

  **What to do**:
  - 在 `genmeta-ssh3-server/src/pam.rs` 实现 PAM 4 阶段包装：
    ```rust
    pub struct PamAuth {
        service_name: String, // 默认 "sshd"，可配置
    }
    
    impl PamAuth {
        /// 执行完整 PAM 4 阶段：authenticate → acct_mgmt → setcred → open_session
        pub async fn authenticate(&self, username: &str, password: &str) -> Result<PamSession, AuthError>;
    }
    
    /// RAII guard：drop 时调用 close_session + end
    pub struct PamSession { ... }
    ```
  - PAM 4 阶段完整调用：authenticate → acct_mgmt → setcred → open_session
  - **Timing attack 防护**：无论认证成功/失败，响应时间恒定（参考 constant-time 模式）
  - PamSession RAII guard：drop 时自动调用 close_session + pam_end
  - PAM service name 默认 `"sshd"`，可配置，不自动降级
  - **注意**：MVP 仅支持 Password 认证，AuthCredential 只有 Password(String) 变体。若将来添加 mTLS 等无密码认证时，再扩展 AuthCredential 并在此处添加跳过 authenticate 的分支。当前实现中，authenticate 阶段始终执行。
  - 在子进程中执行（因为 PAM 会修改进程状态）
  - TDD：用 mock PAM 测试 4 阶段调用顺序 + timing + RAII cleanup

  **Must NOT do**:
  - 不做 PAM service name 自动降级（不从 "sshd" 降级到 "ssh3"）
  - 不在主进程中执行 PAM
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: PAM 是安全敏感模块，需要安全意识但模式相对固定
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 10, 12, 13)
  - **Blocks**: Task 12
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/auth/pam.rs`（旧实现）— PAM 调用参考，但必须修复安全问题

  **External References**:
  - `https://docs.rs/pam/latest/pam/` — pam crate API（或项目已用的 PAM 依赖）

  **WHY Each Reference Matters**:
  - 旧 pam.rs：4 阶段调用顺序参考，但需注意 timing attack 防护在旧代码中可能缺失

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- pam` — 全部通过
  - [ ] PAM 4 阶段顺序调用测试通过
  - [ ] Timing attack 防护测试：成功/失败时间差异 < 10ms
  - [ ] PamSession drop 时 close_session 被调用
  - [ ] service name 可配置且默认 "sshd"

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: PAM 4 阶段顺序
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- pam::four_stage_order
    Expected Result: authenticate → acct_mgmt → setcred → open_session 顺序正确
    Failure Indicators: 阶段顺序错误或跳过
    Evidence: .sisyphus/evidence/task-11-pam-order.txt

  Scenario: Timing attack 防护
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- pam::timing_protection
    Expected Result: 成功认证和失败认证的耗时差异 < 10ms
    Failure Indicators: 时间差异 > 10ms
    Evidence: .sisyphus/evidence/task-11-pam-timing.txt

  Scenario: PamSession RAII cleanup
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- pam::session_drop_cleanup
    Expected Result: drop PamSession 时 close_session 被调用（mock 验证）
    Failure Indicators: close_session 未被调用
    Evidence: .sisyphus/evidence/task-11-pam-cleanup.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(ssh3-server): implement PAM wrapper with timing attack protection`
  - Files: `genmeta-ssh3-server/src/pam.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- pam`

- [ ] 12. ssh3-session 子进程二进制

  **What to do**:
  - 创建 `genmeta-ssh3-server/src/bin/ssh3-session.rs` 子进程入口：
    ```rust
    /// ssh3-session 子进程入口
    /// fd 布局：fd 0 (stdin) = pipe 读端，fd 1 (stdout) = pipe 写端，fd 2 (stderr) = 日志
    #[tokio::main]
    async fn main() {
        // 1. remoc Connect::io_buffered(stdin, stdout)
        //    读写分离：tokio::io::join(stdin_reader, stdout_writer)
        // 2. SshSessionServerSharedMut::new(handler)
        // 3. provide(client) — 主进程 consume() 获取 SshSessionClient
        // 4. 等待 RTC 调用：
        //    authenticate(): getpwnam → PAM 4阶段 → setuid/setgid
        //    run_session(RemoteConversation): 处理 channels/转发
    }
    ```
  - 实现 SshSession trait 的具体 Server 端：
    - `authenticate()`：调用 getpwnam(username) → PAM(Task 11) → setgid/setuid
    - `run_session()`：接受 RemoteConversation，开始处理 channel/转发（Wave 5 实现具体逻辑）
  - fd 布局：
    - fd 0 (stdin) = pipe 读端 ← 主进程写
    - fd 1 (stdout) = pipe 写端 → 主进程读
    - fd 2 (stderr) = pipe 写端 → 日志
  - 子进程内 tokio::io::join(stdin, stdout) 重新聚合为单一 handle 给 remoc
  - TDD：写 in-process spawn 测试验证 remoc 连接建立

  **Must NOT do**:
  - 不在子进程中注册 Protocol 或路由 stream
  - 不在子进程中直接访问 QUIC connection
  - 不在 Wave 5 之前实现具体的 channel/转发逻辑（run_session 先留 stub）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 跨进程 IPC + remoc 连接建立 + fd 布局，涉及多个底层概念
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 Task 10, 11）
  - **Parallel Group**: Wave 4 后半
  - **Blocks**: Tasks 13, 24
  - **Blocked By**: Tasks 10, 11

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/lib.rs`（旧实现）— fork + 子进程模式参考
  - `genmeta-ssh3-server/src/session.rs`（旧实现）— setuid/setgid 模式参考

  **API/Type References**:
  - `genmeta-ssh3-proto/src/session.rs`（Task 10）— SshSession trait + SshSessionServerSharedMut
  - `genmeta-ssh3-proto/src/conversation.rs`（Task 4）— RemoteConversation
  - `genmeta-ssh3-server/src/pam.rs`（Task 11）— PamAuth::authenticate()

  **External References**:
  - `https://docs.rs/remoc/latest/remoc/connect/struct.Connect.html` — io_buffered(reader, writer)

  **WHY Each Reference Matters**:
  - 旧 lib.rs/session.rs：fork+exec + setuid 模式，但使用 remoc RTC 替代旧的 IPC
  - session.rs (Task 10)：SshSession trait 是这个二进制实现的核心接口
  - remoc Connect：io_buffered 是通过 pipe fd 建立 remoc 连接的入口

  **Acceptance Criteria**:
  - [ ] `cargo build -p genmeta-ssh3-server --bin ssh3-session` — 编译成功
  - [ ] `cargo test -p genmeta-ssh3-server -- session_binary` — 全部通过
  - [ ] 子进程通过 pipe fd 建立 remoc 连接
  - [ ] SshSession::authenticate() 执行 PAM + setuid
  - [ ] SshSession::run_session() stub 可调用（具体逻辑 Wave 5）

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: remoc 跨进程连接建立
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- session_binary::remoc_connect
    Expected Result: 主进程 spawn 子进程 → remoc 连接建立 → consume() 获取 SshSessionClient
    Failure Indicators: remoc 连接失败或超时
    Evidence: .sisyphus/evidence/task-12-remoc-connect.txt

  Scenario: authenticate RTC 调用
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- session_binary::authenticate_rtc
    Expected Result: 主进程调用 session.authenticate(init) → 子进程执行并返回 Ok/Err
    Failure Indicators: RTC 调用失败或死锁
    Evidence: .sisyphus/evidence/task-12-authenticate-rtc.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(ssh3-server): implement ssh3-session child process binary with remoc RTC`
  - Files: `genmeta-ssh3-server/src/bin/ssh3-session.rs`, `genmeta-ssh3-server/Cargo.toml`
  - Pre-commit: `cargo build -p genmeta-ssh3-server --bin ssh3-session && cargo test -p genmeta-ssh3-server -- session_binary`

- [ ] 13. ChildProcess 主进程管理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/child.rs` 实现主进程端的子进程管理：
    ```rust
    pub struct ChildProcessManager {
        session_binary_path: PathBuf,
    }
    
    impl ChildProcessManager {
        /// spawn 子进程并建立 remoc 连接
        /// 返回 SshSessionClient 用于 RTC 调用
        pub async fn spawn_session(&self) -> Result<(SshSessionClient, ChildHandle), SessionError>;
    }
    
    /// RAII guard：drop 时 kill 子进程并 wait
    pub struct ChildHandle { ... }
    ```
  - spawn_session() 流程：
    - 创建 pipe pair（stdin_r/stdin_w + stdout_r/stdout_w）
    - Command::new(session_binary_path) + stdin(stdin_r) + stdout(stdout_w) + stderr(Stdio::piped())
    - tokio::io::join(stdout_r, stdin_w) → remoc Connect::io_buffered() → consume() → SshSessionClient
  - ChildHandle RAII：drop 时 kill + wait 子进程
  - 与 Task 8 handler 集成：handler 调用 spawn_session() 获取 client
  - TDD：写 spawn + remoc 连接 + RTC 调用完整流程测试

  **Must NOT do**:
  - 不使用 fork（用 Command::new exec）
  - 不在主进程中执行 PAM
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 进程管理模式明确，主要是 pipe + spawn + remoc 集成
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 Task 10, 12）
  - **Parallel Group**: Wave 4 尾部
  - **Blocks**: Task 24
  - **Blocked By**: Tasks 10, 12

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/lib.rs`（旧实现）— 子进程 spawn 模式

  **API/Type References**:
  - `genmeta-ssh3-proto/src/session.rs`（Task 10）— SshSessionClient 类型
  - `std::process::Command` / `tokio::process::Command` — 子进程 spawn

  **External References**:
  - `https://docs.rs/remoc/latest/remoc/connect/struct.Connect.html` — io_buffered + consume

  **WHY Each Reference Matters**:
  - 旧 lib.rs：fork 模式参考，但改为 Command::new exec 模式
  - session.rs (Task 10)：SshSessionClient 是 spawn_session 的返回值类型

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- child` — 全部通过
  - [ ] spawn_session() → SshSessionClient 可调用
  - [ ] ChildHandle drop 时子进程被清理
  - [ ] 完整流程：spawn → authenticate → run_session 测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 子进程 spawn + RTC 完整流程
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- child::spawn_full_flow
    Expected Result: spawn → remoc connect → authenticate() → run_session() 全流程成功
    Failure Indicators: 任何阶段失败或超时
    Evidence: .sisyphus/evidence/task-13-spawn-full.txt

  Scenario: ChildHandle RAII cleanup
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- child::handle_drop_cleanup
    Expected Result: drop ChildHandle 后子进程不再运行
    Failure Indicators: 子进程成为 zombie 或继续运行
    Evidence: .sisyphus/evidence/task-13-handle-cleanup.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(ssh3-server): implement ChildProcessManager with remoc RTC integration`
  - Files: `genmeta-ssh3-server/src/child.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- child`

---

### Wave 5: Session + Forwarding

- [ ] 14. Channel Open/Close/Data 处理

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/channel.rs` 实现 channel 层管理：
    ```rust
    pub struct ChannelManager {
        channels: HashMap<ChannelId, ChannelState>,
        next_channel_id: u32,
    }
    
    impl ChannelManager {
        /// 处理 ChannelOpen(90) → 创建 channel → 回复 ChannelOpenConfirmation(91) 或 Failure(92)
        pub async fn handle_open(&mut self, msg: ChannelOpenMsg, conv: &dyn Conversation) -> Result<(), ChannelError>;
        /// 处理 ChannelData(94) → 转发到对应 channel
        pub async fn handle_data(&mut self, msg: ChannelDataMsg) -> Result<(), ChannelError>;
        /// 处理 ChannelWindowAdjust(93)
        pub async fn handle_window_adjust(&mut self, msg: ChannelWindowAdjustMsg) -> Result<(), ChannelError>;
        /// 处理 ChannelEOF(96) 和 ChannelClose(97)
        pub async fn handle_eof(&mut self, msg: ChannelEOFMsg) -> Result<(), ChannelError>;
        pub async fn handle_close(&mut self, msg: ChannelCloseMsg) -> Result<(), ChannelError>;
        /// 主动打开 channel（用于 reverse forwarding）
        pub async fn open_channel(&mut self, channel_type: ChannelType, conv: &dyn Conversation) -> Result<ChannelId, ChannelError>;
    }
    ```
  - ChannelState 状态机：Opening → Open → EOF → Closed
  - 每个 channel 对应一个独立的 QUIC bidi stream（通过 Conversation 打开）
  - Window 管理：ChannelWindowAdjust 控制流量
  - 在子进程中运行（通过 RemoteConversation）
  - TDD：先写 channel 状态机测试 + open/close/data 流转测试

  **Must NOT do**:
  - 不在主进程中处理 channel 逻辑（全在子进程）
  - 不实现具体的 exec/pty/转发逻辑（那是后续 tasks）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 状态机 + 流控制逻辑，需要仔细处理边界情况
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5 (with Tasks 15-20)
  - **Blocks**: Tasks 15, 17, 18, 19
  - **Blocked By**: Tasks 4, 5

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/mux.rs`（旧实现）— channel 复用模式参考

  **API/Type References**:
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— ChannelOpenMsg/ChannelDataMsg 等消息类型
  - `genmeta-ssh3-proto/src/conversation.rs`（Task 4）— Conversation trait，open_channel/accept_channel
  - RFC Section 4 — Channel 生命周期和消息格式

  **WHY Each Reference Matters**:
  - 旧 mux.rs：channel 管理参考，但类型值和状态机以 RFC 为准
  - message.rs：channel 消息结构体定义
  - Conversation：每个 channel 通过 Conversation 打开 QUIC bidi stream

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- channel` — 全部通过
  - [ ] ChannelManager 状态机测试：Opening → Open → EOF → Closed
  - [ ] channel open/confirm/failure 流程测试通过
  - [ ] channel data 转发测试通过
  - [ ] channel EOF + close 测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Channel 完整生命周期
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- channel::lifecycle
    Expected Result: open → data → EOF → close 全流程正常
    Failure Indicators: 状态转换错误或消息丢失
    Evidence: .sisyphus/evidence/task-14-channel-lifecycle.txt

  Scenario: Channel open 被拒绝
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-proto -- channel::open_failure
    Expected Result: 不支持的 channel type → ChannelOpenFailure
    Failure Indicators: 返回 Confirmation 或 panic
    Evidence: .sisyphus/evidence/task-14-channel-failure.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-proto): implement channel management with state machine`
  - Files: `genmeta-ssh3-proto/src/channel.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- channel`

- [ ] 15. Exec/Shell/Subsystem 请求处理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/exec.rs` 实现 channel request 处理（子进程内）：
    - ChannelRequest::Exec(cmd) → `Command::new("sh").arg("-c").arg(cmd)` → stdin/stdout/stderr 绑定 channel data
    - ChannelRequest::Shell → 启动用户 shell（从 getpwnam 获取）
    - ChannelRequest::Subsystem(name) → 查找子系统二进制
    - ChannelRequest::Env(key, value) → 设置环境变量
    - ChannelRequest::Signal(sig) → 向进程发送信号
  - 进程结束时发送 ExitStatus/ExitSignal + ChannelEOF + ChannelClose
  - stdin/stdout/stderr 通过 ChannelData 消息传递
  - TDD：mock exec 测试 stdin/stdout 绑定 + exit status

  **Must NOT do**:
  - 不实现 PTY（那是 Task 16）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 进程生命周期管理 + I/O 绑定，需要处理多种边界情况
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 14)
  - **Parallel Group**: Wave 5 (with Tasks 14, 16-20)
  - **Blocks**: Tasks 16, 24
  - **Blocked By**: Tasks 5, 14

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/session.rs`（旧实现）— exec/shell 启动模式

  **API/Type References**:
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— ChannelRequest sub-types (Exec/Shell/Subsystem)
  - RFC Section 4.6-4.9 — channel request 类型定义

  **WHY Each Reference Matters**:
  - 旧 session.rs：exec/shell 启动和 I/O 绑定参考
  - RFC Section 4：channel request type 和格式权威定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- exec` — 全部通过
  - [ ] exec "echo hello" → stdout "hello\n" + ExitStatus(0)
  - [ ] shell 启动 → 可交互
  - [ ] ExitStatus/ExitSignal + ChannelEOF + ChannelClose 发送顺序正确

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Exec 命令执行
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- exec::run_echo
    Expected Result: exec "echo hello" → ChannelData("hello\n") + ExitStatus(0) + EOF + Close
    Failure Indicators: 输出不匹配或缺少 EOF/Close
    Evidence: .sisyphus/evidence/task-15-exec-echo.txt

  Scenario: Exec 命令失败
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- exec::run_nonexistent
    Expected Result: exec "不存在的命令" → ExitStatus(非0) + EOF + Close
    Failure Indicators: 未发送 ExitStatus 或 panic
    Evidence: .sisyphus/evidence/task-15-exec-fail.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement exec/shell/subsystem channel request handling`
  - Files: `genmeta-ssh3-server/src/exec.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- exec`

- [ ] 16. PTY 分配 + 终端处理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/pty.rs` 实现 PTY 分配：
    - ChannelRequest::PtyReq(term, cols, rows, ...) → openpty() → master/slave fd
    - 将 slave 设为 exec/shell 的 stdin/stdout/stderr
    - ChannelRequest::WindowChange(cols, rows) → TIOCSWINSZ ioctl
  - 使用 nix crate 的 openpty() + ioctl 封装
  - PTY master 的读写通过 ChannelData 传递
  - 在子进程中执行（PTY 分配在 setuid 之后）
  - TDD：mock PTY 测试 PtyReq + WindowChange

  **Must NOT do**:
  - 不在主进程中分配 PTY
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: PTY 处理模式固定，主要是 syscall 封装
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 15)
  - **Parallel Group**: Wave 5
  - **Blocks**: Task 24
  - **Blocked By**: Task 15

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/session.rs`（旧实现）— PTY 分配模式

  **API/Type References**:
  - RFC Section 4.3 — pty-req channel request 格式
  - RFC Section 4.4 — window-change channel request 格式

  **WHY Each Reference Matters**:
  - 旧 session.rs：PTY 分配和 TIOCSWINSZ 参考
  - RFC：PtyReq/WindowChange 消息字段定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- pty` — 全部通过
  - [ ] PtyReq → openpty() + slave 绑定测试通过
  - [ ] WindowChange → TIOCSWINSZ 调用测试通过

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: PTY 分配和绑定
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- pty::allocate_bind
    Expected Result: PtyReq → 成功分配 PTY + slave 绑定到进程
    Failure Indicators: openpty 失败或绑定错误
    Evidence: .sisyphus/evidence/task-16-pty-allocate.txt

  Scenario: WindowChange ioctl
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- pty::window_change
    Expected Result: WindowChange(80, 24) → TIOCSWINSZ 成功
    Failure Indicators: ioctl 失败
    Evidence: .sisyphus/evidence/task-16-pty-resize.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement PTY allocation and window change handling`
  - Files: `genmeta-ssh3-server/src/pty.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- pty`

- [ ] 17. Direct-TCP 转发

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/tcp.rs` 实现 direct-tcp 转发：
    - 客户端发起 ChannelOpen(DirectTcp { host, port }) → 子进程 connect 目标地址
    - TCP 连接建立后，duplex 转发 ChannelData ↔ TCP 裸流
    - TCP 连接关闭时发送 ChannelEOF + ChannelClose
  - 在子进程中执行（TCP 连接在用户权限下）
  - TDD：mock TCP server → channel open → data 转发 → 关闭

  **Must NOT do**:
  - 不实现 UDP 转发
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: TCP 转发模式明确，tokio::io::copy_bidirectional
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 14)
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 20, 24
  - **Blocked By**: Task 14

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/forward.rs`（旧实现）— TCP 转发模式

  **API/Type References**:
  - RFC Section 4.11 — direct-tcpip channel type
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— ChannelType::DirectTcp

  **WHY Each Reference Matters**:
  - 旧 forward.rs：TCP 转发模式和 duplex 复制参考
  - RFC：direct-tcpip channel type 和字段定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::tcp::direct` — 全部通过
  - [ ] ChannelOpen(DirectTcp) → TCP 连接建立 + 双向转发
  - [ ] TCP 关闭 → ChannelEOF + ChannelClose

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Direct-TCP 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- forward::tcp::direct_forward
    Expected Result: mock TCP server → channel open → send "hello" → recv "hello" + close
    Failure Indicators: 数据丢失或连接失败
    Evidence: .sisyphus/evidence/task-17-direct-tcp.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement direct-TCP channel forwarding`
  - Files: `genmeta-ssh3-server/src/forward/tcp.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward::tcp::direct`

- [ ] 18. Reverse-TCP 转发（global request + channel open）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/tcp.rs` 添加 reverse-TCP 逻辑：
    - **Global Request**：GlobalRequest::TcpipForward(bind_addr, bind_port) → 子进程启动 TCP listener
    - **Channel Open**：新 TCP 连接到达时，子进程通过 Conversation 打开 ChannelOpen(ForwardedTcp) → 客户端
    - GlobalRequest::CancelTcpipForward → 停止监听
    - TCP listener 在子进程中运行（用户权限）
  - ForwardPort 语义明确：global request 用于绑定监听，channel open 用于每个新连接
  - TDD：mock 测试 TcpipForward → listener bind → connection → ChannelOpen(ForwardedTcp)

  **Must NOT do**:
  - 不在主进程中监听 TCP（在子进程）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 双向流程（global request 绑定 + channel open 转发），逻辑复杂
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 14)
  - **Parallel Group**: Wave 5
  - **Blocks**: Task 24
  - **Blocked By**: Task 14

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/listener.rs`（旧实现）— TCP listener 模式

  **API/Type References**:
  - RFC Section 5.1 — tcpip-forward global request
  - RFC Section 4.12 — forwarded-tcpip channel type
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— GlobalRequest::TcpipForward + ChannelType::ForwardedTcp

  **WHY Each Reference Matters**:
  - 旧 listener.rs：TCP listener bind 和 accept 参考
  - RFC：global request + channel open 的双向流程规范

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::tcp::reverse` — 全部通过
  - [ ] TcpipForward → listener bind 成功
  - [ ] 新连接 → ChannelOpen(ForwardedTcp) 发送成功
  - [ ] CancelTcpipForward → listener 停止

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Reverse-TCP 绑定 + 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- forward::tcp::reverse_forward
    Expected Result: TcpipForward("127.0.0.1", 0) → bind → connect → ChannelOpen(ForwardedTcp) → data duplex
    Failure Indicators: bind 失败或 ChannelOpen 未发送
    Evidence: .sisyphus/evidence/task-18-reverse-tcp.txt

  Scenario: Cancel reverse-TCP
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- forward::tcp::cancel_forward
    Expected Result: CancelTcpipForward → listener 停止 + 后续连接被拒绝
    Failure Indicators: listener 继续接受连接
    Evidence: .sisyphus/evidence/task-18-cancel-tcp.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement reverse-TCP forwarding with global request binding`
  - Files: `genmeta-ssh3-server/src/forward/tcp.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward::tcp::reverse`

- [ ] 19. Streamlocal (Unix Socket) 转发

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/streamlocal.rs` 实现 Unix socket 转发：
    - Direct streamlocal：ChannelOpen(DirectStreamlocal { path }) → connect Unix socket → duplex 转发
    - Reverse streamlocal：GlobalRequest::StreamlocalForward(path) → bind Unix socket → ChannelOpen(ForwardedStreamlocal)
    - CancelStreamlocalForward → 停止监听 + 删除 socket 文件
  - 与 TCP 转发类似模式，但使用 UnixStream/UnixListener
  - 在子进程中执行
  - TDD：mock Unix socket 测试

  **Must NOT do**:
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 与 TCP 转发模式一致，只是 transport 不同
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Task 14)
  - **Parallel Group**: Wave 5
  - **Blocks**: Task 24
  - **Blocked By**: Task 14

  **References**:

  **API/Type References**:
  - RFC Section 4.13-4.14 — direct-streamlocal / forwarded-streamlocal channel type
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— ChannelType::DirectStreamlocal/ForwardedStreamlocal

  **WHY Each Reference Matters**:
  - RFC：streamlocal channel type 和字段定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::streamlocal` — 全部通过
  - [ ] Direct streamlocal connect + duplex 测试通过
  - [ ] Reverse streamlocal bind + forward 测试通过
  - [ ] Cancel → listener 停止 + socket 文件删除

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Direct-streamlocal 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- forward::streamlocal::direct
    Expected Result: ChannelOpen(DirectStreamlocal) → connect → duplex data
    Failure Indicators: Unix socket 连接失败或数据丢失
    Evidence: .sisyphus/evidence/task-19-streamlocal-direct.txt

  Scenario: Reverse-streamlocal 绑定 + 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- forward::streamlocal::reverse
    Expected Result: StreamlocalForward("/tmp/test.sock") → bind → accept → ChannelOpen(ForwardedStreamlocal)
    Failure Indicators: bind 失败或 ChannelOpen 未发送
    Evidence: .sisyphus/evidence/task-19-streamlocal-reverse.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement Unix socket (streamlocal) forwarding`
  - Files: `genmeta-ssh3-server/src/forward/streamlocal.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward::streamlocal`

- [ ] 20. SOCKS5 代理（服务端）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/socks.rs` 实现 SOCKS5 代理（服务器侧）：
    - 通过 dynamic-forward channel 或 direct-tcp channel 实现
    - SOCKS5 协商（RFC 1928）：方法协商 → CONNECT 请求 → TCP 连接 → duplex 转发
    - 支持 CONNECT 命令（不支持 BIND/UDP）
    - 支持 IPv4/IPv6/域名目标地址
    - 在子进程中执行
  - TDD：mock SOCKS5 client → CONNECT → 目标 TCP server → duplex

  **Must NOT do**:
  - 不实现 SOCKS5 BIND 或 UDP ASSOCIATE
  - 不实现认证方法（只支持 NO AUTHENTICATION）
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: SOCKS5 协议明确，可参考旧实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (after Tasks 14, 17)
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 23, 24
  - **Blocked By**: Tasks 14, 17

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/socks.rs`（旧实现）— SOCKS5 协议解析参考

  **External References**:
  - RFC 1928 — SOCKS Protocol Version 5

  **WHY Each Reference Matters**:
  - 旧 socks.rs：SOCKS5 协商和 CONNECT 处理参考
  - RFC 1928：SOCKS5 协议权威定义

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- socks` — 全部通过
  - [ ] SOCKS5 方法协商 → CONNECT → 目标连接 → duplex
  - [ ] IPv4/IPv6/域名目标地址支持
  - [ ] 不支持的命令返回正确错误码

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: SOCKS5 CONNECT 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- socks::connect_forward
    Expected Result: SOCKS5 CONNECT 127.0.0.1:8080 → TCP 连接 → duplex 转发
    Failure Indicators: 连接失败或数据丢失
    Evidence: .sisyphus/evidence/task-20-socks5-connect.txt

  Scenario: SOCKS5 不支持的命令
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-server -- socks::unsupported_command
    Expected Result: BIND/UDP ASSOCIATE → 返回 command not supported (0x07)
    Failure Indicators: 非 0x07 响应或 panic
    Evidence: .sisyphus/evidence/task-20-socks5-unsupported.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `feat(ssh3-server): implement SOCKS5 proxy (CONNECT only, server-side)`
  - Files: `genmeta-ssh3-server/src/socks.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- socks`

### Wave 6: Client + E2E Integration

- [ ] 21. SSH3 客户端连接 + 认证

  **What to do**:
  - 在 `genmeta-ssh3-client/src/connect.rs` 实现客户端连接逻辑（greenfield 重写，参考旧实现）：
    - 使用 h3x `PendingRequest::connect(uri)` 发起 Extended CONNECT 到 `/.well-known/ssh3`
    - 设置 `Authorization: Basic base64(username:password)` header
    - 设置 `ssh-version: michel-ssh3-00` header
    - 解析响应状态码：200 → 成功，401 → 认证失败，403 → 版本不匹配
    - 解析响应 `ssh-version` header 确认服务端版本
    - 建立连接后获取 conversation_id（CONNECT stream ID）
  - 在 `genmeta-ssh3-client/src/auth.rs` 实现客户端认证构建（greenfield）：
    - `build_basic_auth(username: &str, password: &str) -> HeaderValue`
    - Base64 编码符合 RFC 7617
  - 在 `genmeta-ssh3-client/src/error.rs` 定义客户端错误类型（snafu 风格）：
    - ConnectError：连接失败、认证失败、版本不匹配
  - TDD：
    - RED：测试 connect 函数发送正确的 headers
    - RED：测试 401 响应 → AuthenticationFailed 错误
    - RED：测试 403 响应 → VersionMismatch 错误
    - GREEN：实现连接逻辑
    - REFACTOR：提取公共 header 构建逻辑

  **Must NOT do**:
  - 不实现 JWT 或 HTTP Signature 认证
  - 不实现 mTLS 客户端证书认证
  - 不使用 `h3x::message::unify`（使用 `http` crate 类型）
  - 不设置 tracing event 的 target
  - 不接入 gmutils

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要理解 h3x PendingRequest API + HTTP 认证协议 + 错误处理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (Wave 6 入口)
  - **Parallel Group**: Wave 6
  - **Blocks**: Task 22, Task 24
  - **Blocked By**: Task 6 (Ssh3Protocol), Task 8 (Extended CONNECT handler)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-client/src/connect.rs`（旧实现）— 连接流程参考（注意：旧实现使用不同 API，仅参考整体流程）
  - `genmeta-ssh3-client/src/auth.rs`（旧实现）— Basic auth 构建参考

  **API/Type References**:
  - `h3x/src/client/message.rs` — PendingRequest::connect(uri) API
  - `h3x/src/client/message.rs` — PendingRequest::with_header/with_method API
  - RFC Section 6 — ssh-version header 协商
  - RFC Section 3.1 — Extended CONNECT 请求格式
  - RFC 7617 — HTTP Basic Authentication base64 编码规范
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— SSH 消息类型
  - `genmeta-ssh3-client/src/error.rs`（Task 21 自建）— ConnectError

  **WHY Each Reference Matters**:
  - 旧 connect.rs：理解连接建立的整体步骤（虽然 API 不同），避免遗漏关键步骤
  - 旧 auth.rs：Basic auth 的 header 构建逻辑可直接参考
  - PendingRequest API：这是 h3x 客户端发起 CONNECT 请求的唯一入口
  - RFC Section 6：ssh-version 协商的权威规范，必须精确匹配
  - RFC 7617：Base64 编码的精确要求（冒号分隔、UTF-8 处理）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client -- connect` — 全部通过
  - [ ] `cargo test -p genmeta-ssh3-client -- auth` — 全部通过
  - [ ] Basic auth header 正确：`Authorization: Basic base64(user:pass)`
  - [ ] ssh-version header 正确：`ssh-version: michel-ssh3-00`
  - [ ] 401 响应映射为 AuthenticationFailed 错误
  - [ ] 403 响应映射为 VersionMismatch 错误
  - [ ] 200 响应成功解析 conversation_id

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 客户端连接 + Basic auth 成功
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- connect::test_connect_basic_auth_success
    Expected Result: PendingRequest 携带正确 Authorization + ssh-version header → 200 响应 → 返回 Ssh3Connection 含 conversation_id
    Failure Indicators: header 缺失/格式错误、conversation_id 为 0
    Evidence: .sisyphus/evidence/task-21-connect-success.txt

  Scenario: 认证失败处理
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- connect::test_connect_auth_failure
    Expected Result: 401 响应 → Err(ConnectError::AuthenticationFailed)
    Failure Indicators: 非 AuthenticationFailed 错误或 panic
    Evidence: .sisyphus/evidence/task-21-connect-auth-fail.txt

  Scenario: 版本不匹配处理
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- connect::test_connect_version_mismatch
    Expected Result: 403 响应 → Err(ConnectError::VersionMismatch)
    Failure Indicators: 非 VersionMismatch 错误或 panic
    Evidence: .sisyphus/evidence/task-21-connect-version-mismatch.txt
  ```

  **Commit**: YES (groups with Wave 6)
  - Message: `feat(ssh3-client): implement SSH3 client connection + Basic auth`
  - Files: `genmeta-ssh3-client/src/connect.rs`, `genmeta-ssh3-client/src/auth.rs`, `genmeta-ssh3-client/src/error.rs`, `genmeta-ssh3-client/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-client -- connect auth`

- [ ] 22. 客户端会话 + 转发请求

  **What to do**:
  - 在 `genmeta-ssh3-client/src/session.rs` 实现客户端会话管理（greenfield 重写）：
    - 连接成功后，客户端通过 Ssh3Protocol 在同一 QUIC 连接上打开新的 bidi stream
    - 每个 channel 请求 = 一个新的 bidi stream，前缀 signal_value(0xaf3627e6) + conversation_id
    - 实现 `open_channel(channel_type: ChannelType) -> Channel` ：
      - 构建 ChannelOpen message（CBOR 编码）
      - 发送到新 bidi stream
      - 等待 ChannelOpenConfirmation 或 ChannelOpenFailure
    - 实现 Exec/Shell 请求：
      - `exec(command: &str) -> ExecChannel`
      - `shell() -> ShellChannel`
      - ExecChannel 包含 stdin(WriteHalf)、stdout(ReadHalf)、stderr(ReadHalf)
    - 实现 Direct-TCP 转发请求：
      - `direct_tcp(host: &str, port: u16, originator_host: &str, originator_port: u16) -> TcpChannel`
      - TcpChannel 双向 duplex 转发
    - 实现 Reverse-TCP 转发请求（客户端侧）：
      - `tcpip_forward(bind_addr: &str, bind_port: u16) -> ForwardListener`
      - 发送 GlobalRequest::TcpipForward
      - 等待 GlobalRequestSuccess（含 bound port）
      - ForwardListener：accept() 接收 ChannelOpen(ForwardedTcp)
    - 实现 Streamlocal 转发请求：
      - `direct_streamlocal(path: &str) -> StreamlocalChannel`
      - `streamlocal_forward(path: &str) -> ForwardListener`
  - 在 `genmeta-ssh3-client/src/forward.rs` 实现转发辅助逻辑：
    - TCP duplex 中继：`relay_tcp(channel: TcpChannel, local_stream: TcpStream)`
    - Direct-TCP：本地 listen → accept → open_channel(DirectTcp) → relay
    - Reverse-TCP：ForwardListener.accept() → connect local → relay
  - TDD：
    - RED：测试 open_channel → ChannelOpenConfirmation
    - RED：测试 exec → 发送正确 ChannelOpen + ExecRequest
    - RED：测试 direct_tcp → ChannelOpen(DirectTcp) 字段正确
    - RED：测试 tcpip_forward → GlobalRequest + ForwardedTcp accept
    - GREEN：实现各功能
    - REFACTOR：提取 channel 公共逻辑到 Channel base struct

  **Must NOT do**:
  - 不实现 x11 forwarding
  - 不实现 agent-connection channel
  - 不设置 tracing event 的 target
  - 不接入 gmutils

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 多种 channel 类型 + global request + 双向数据流，逻辑复杂
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on Task 21)
  - **Parallel Group**: Wave 6（Task 21 完成后可与 Task 23 部分并行）
  - **Blocks**: Task 23, Task 24
  - **Blocked By**: Task 14 (channel 处理), Task 15 (exec/shell), Task 21 (客户端连接)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-client/src/session.rs`（旧实现）— 会话管理模式参考
  - `genmeta-ssh3-client/src/forward.rs`（旧实现）— 转发逻辑参考
  - `genmeta-ssh3-client/src/forward/`（旧实现目录）— 转发子模块结构参考

  **API/Type References**:
  - RFC Section 4 — SSH3 Channel 类型定义
  - RFC Section 4.3 — channel-open message 格式
  - RFC Section 4.6 — exec request channel type
  - RFC Section 5.1 — tcpip-forward global request
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— SshMessage enum + ChannelType
  - `genmeta-ssh3-proto/src/conversation.rs`（Task 4）— Conversation trait
  - `genmeta-ssh3-client/src/connect.rs`（Task 21）— Ssh3Connection

  **WHY Each Reference Matters**:
  - 旧 session.rs：整体会话管理流程参考，但 API 已完全不同
  - 旧 forward.rs：转发 relay 逻辑（TCP duplex 中继）可参考核心模式
  - RFC Section 4：每种 channel 的精确 CBOR 字段定义
  - Task 5 的 SshMessage：确保客户端发送的消息与 proto 定义一致
  - Task 4 的 Conversation：客户端需要通过 Conversation 接口与服务端通信

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client -- session` — 全部通过
  - [ ] `cargo test -p genmeta-ssh3-client -- forward` — 全部通过
  - [ ] open_channel → ChannelOpenConfirmation 正确解析
  - [ ] exec("echo hello") → 正确的 ChannelOpen + ExecRequest 消息
  - [ ] direct_tcp → ChannelOpen(DirectTcp) 含正确的 host/port/originator 字段
  - [ ] tcpip_forward → GlobalRequest → ForwardedTcp accept 正常工作
  - [ ] direct_streamlocal → ChannelOpen(DirectStreamlocal) 含正确路径

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: 客户端 exec 命令
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- session::test_exec_channel
    Expected Result: exec("echo hello") → ChannelOpen(Session) + ExecRequest → stdout 收到 "hello\n"
    Failure Indicators: ChannelOpen 消息格式错误或 stdout 无数据
    Evidence: .sisyphus/evidence/task-22-exec-channel.txt

  Scenario: 客户端 direct-tcp 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- forward::test_direct_tcp
    Expected Result: direct_tcp("127.0.0.1", 8080, ...) → ChannelOpen(DirectTcp) → duplex 数据
    Failure Indicators: channel open 失败或数据中继断裂
    Evidence: .sisyphus/evidence/task-22-direct-tcp.txt

  Scenario: 客户端 reverse-tcp 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- forward::test_reverse_tcp_forward
    Expected Result: tcpip_forward("127.0.0.1", 0) → GlobalRequestSuccess(bound_port) → ForwardedTcp accept
    Failure Indicators: GlobalRequest 超时或 ForwardedTcp 未收到
    Evidence: .sisyphus/evidence/task-22-reverse-tcp.txt

  Scenario: channel open 被拒绝
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- session::test_channel_open_failure
    Expected Result: ChannelOpenFailure → Err(ChannelError::OpenRejected { reason })
    Failure Indicators: panic 或非预期错误类型
    Evidence: .sisyphus/evidence/task-22-channel-open-failure.txt
  ```

  **Commit**: YES (groups with Wave 6)
  - Message: `feat(ssh3-client): implement session management + channel/forwarding requests`
  - Files: `genmeta-ssh3-client/src/session.rs`, `genmeta-ssh3-client/src/forward.rs`, `genmeta-ssh3-client/src/forward/*.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-client -- session forward`

- [ ] 23. 客户端 SOCKS5 代理

  **What to do**:
  - 在 `genmeta-ssh3-client/src/socks.rs` 实现客户端侧 SOCKS5 代理（greenfield 重写）：
    - 在本地启动 TCP listener（绑定指定端口）
    - 接受 SOCKS5 客户端连接
    - 解析 SOCKS5 CONNECT 请求（RFC 1928）：
      - 方法协商（NO AUTHENTICATION REQUIRED）
      - CONNECT 命令 → 目标地址（IPv4/IPv6/域名 + 端口）
    - 每个 SOCKS5 CONNECT → 打开 direct-tcp channel → duplex relay
    - 向 SOCKS5 客户端返回成功/失败响应
    - 连接关闭 → 清理 channel
  - 复用 Task 22 的 `direct_tcp()` 接口打开 channel
  - 复用 Task 22 的 `relay_tcp()` 进行 duplex 中继
  - TDD：
    - RED：测试 SOCKS5 方法协商（NO AUTH → 0x00 响应）
    - RED：测试 SOCKS5 CONNECT → direct-tcp channel 打开
    - RED：测试不支持的命令 → 返回 0x07
    - GREEN：实现 SOCKS5 代理逻辑
    - REFACTOR：提取公共 SOCKS5 解析逻辑

  **Must NOT do**:
  - 不实现 SOCKS5 BIND 或 UDP ASSOCIATE
  - 不实现 SOCKS5 认证方法（只支持 NO AUTHENTICATION）
  - 不设置 tracing event 的 target
  - 不接入 gmutils

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: SOCKS5 协议规范明确，客户端侧可参考服务端 Task 20 实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on Task 22)
  - **Parallel Group**: Wave 6
  - **Blocks**: Task 24
  - **Blocked By**: Task 20 (服务端 SOCKS5 参考), Task 22 (direct_tcp 接口)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-client/src/socks.rs`（旧实现）— 客户端 SOCKS5 代理参考
  - `genmeta-ssh3-server/src/socks.rs`（Task 20 新实现）— SOCKS5 协议解析可复用

  **API/Type References**:
  - RFC 1928 — SOCKS Protocol Version 5 完整规范
  - `genmeta-ssh3-client/src/session.rs`（Task 22）— direct_tcp() 接口
  - `genmeta-ssh3-client/src/forward.rs`（Task 22）— relay_tcp() 函数

  **WHY Each Reference Matters**:
  - 旧 socks.rs：SOCKS5 客户端侧代理的整体流程参考
  - Task 20 的 SOCKS5 解析：服务端的 SOCKS5 协议解析逻辑可复用到客户端
  - RFC 1928：SOCKS5 协议的权威定义，确保响应格式正确
  - Task 22 的 direct_tcp()：客户端 SOCKS5 的核心依赖——每个 CONNECT 需要打开 direct-tcp channel

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client -- socks` — 全部通过
  - [ ] SOCKS5 方法协商 → NO AUTH (0x00) 正确
  - [ ] SOCKS5 CONNECT → direct-tcp channel → duplex relay
  - [ ] 不支持的命令 → 返回 0x07 (command not supported)
  - [ ] IPv4/IPv6/域名目标地址正确解析

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: SOCKS5 代理 CONNECT 转发
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- socks::test_socks5_connect
    Expected Result: SOCKS5 CONNECT 127.0.0.1:8080 → direct-tcp channel → duplex 数据
    Failure Indicators: channel open 失败或 SOCKS5 响应格式错误
    Evidence: .sisyphus/evidence/task-23-socks5-connect.txt

  Scenario: SOCKS5 不支持的命令
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- socks::test_socks5_unsupported
    Expected Result: BIND 命令 → 返回 0x07 (command not supported) + 关闭连接
    Failure Indicators: 非 0x07 响应或连接未关闭
    Evidence: .sisyphus/evidence/task-23-socks5-unsupported.txt

  Scenario: SOCKS5 域名解析
    Tool: Bash
    Steps:
      1. cargo test -p genmeta-ssh3-client -- socks::test_socks5_domain_connect
    Expected Result: SOCKS5 CONNECT example.com:80 → direct-tcp channel host="example.com" port=80
    Failure Indicators: 域名未正确传递到 direct-tcp channel
    Evidence: .sisyphus/evidence/task-23-socks5-domain.txt
  ```

  **Commit**: YES (groups with Wave 6)
  - Message: `feat(ssh3-client): implement local SOCKS5 proxy via direct-tcp channels`
  - Files: `genmeta-ssh3-client/src/socks.rs`, `genmeta-ssh3-client/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-client -- socks`

- [ ] 24. 完整 E2E 集成测试

  **What to do**:
  - 在 `tests/` 目录创建完整端到端集成测试：
    - `tests/e2e_integration.rs`（或 workspace 级 integration test crate）
    - 测试框架需要：
      - 启动 SSH3 服务器（使用测试证书 + 测试 PAM 配置）
      - 客户端连接 + 认证 + 执行各种操作
      - 自动清理（drop guard）
  - E2E 场景覆盖：
    1. **Basic auth + exec**：连接 → Basic 认证 → exec "echo hello" → 断言 stdout == "hello\n"
    2. **Shell 会话**：连接 → 打开 shell → 发送命令 → 读取输出 → 退出
    3. **Direct-TCP 转发**：连接 → direct-tcp → 本地起 TCP echo server → 数据 roundtrip
    4. **Reverse-TCP 转发**：连接 → tcpip_forward → 外部连接绑定端口 → 数据 roundtrip
    5. **Streamlocal 转发**：连接 → direct-streamlocal → Unix echo server → 数据 roundtrip
    6. **SOCKS5 代理**：连接 → 启动 SOCKS5 → curl --socks5 → 目标 TCP server → 数据
    7. **认证失败**：错误密码 → 401 → 连接拒绝
    8. **版本不匹配**：错误 ssh-version → 403 → 连接拒绝
    9. **多 channel 并发**：同时打开 exec + direct-tcp → 两者均正常工作
    10. **连接断开清理**：客户端断开 → 服务端清理子进程 + listener
  - 测试辅助设施：
    - `TestServer`：管理服务器生命周期（启动/停止/端口分配）
    - `TestClient`：封装客户端连接 + 认证
    - 测试证书：自签名证书（在 test fixture 中）
    - 端口分配：使用 port 0 自动分配避免冲突
  - TDD：
    - RED：所有 E2E 场景先写测试（应在 Wave 1-5 未完成时编译失败，但到 Wave 6 应通过）
    - GREEN：确保所有场景通过
    - REFACTOR：提取 TestServer/TestClient 到测试辅助模块

  **Must NOT do**:
  - 不测试 x11 forwarding
  - 不测试 agent-connection channel
  - 不测试 JWT/HTTP Signature 认证
  - 不测试与 Go 参考实现的互操作
  - 不设置 tracing event 的 target
  - 不依赖外部网络（所有测试使用 localhost）
  - 不硬编码端口号（使用 port 0）

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 跨 client/server 全栈测试，需要同时理解两端架构 + 多进程 + 网络
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on everything)
  - **Parallel Group**: Wave 6（最后执行）
  - **Blocks**: FINAL (F1-F4)
  - **Blocked By**: Task 8, 12, 13, 15, 16, 17, 21, 22 （核心路径上所有任务）

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/` — 服务器端全部实现（Wave 3-5）
  - `genmeta-ssh3-client/src/` — 客户端全部实现（Wave 6 Task 21-23）
  - `genmeta-ssh3-server/tests/e2e.rs`（Task 9）— E2E 冒烟测试框架（TestServer 骨架可复用）

  **API/Type References**:
  - RFC draft-michel-ssh3-00 — 完整协议参考
  - `genmeta-ssh3-proto/src/message.rs`（Task 5）— 所有消息类型
  - `genmeta-ssh3-client/src/connect.rs`（Task 21）— 客户端连接 API
  - `genmeta-ssh3-client/src/session.rs`（Task 22）— 客户端会话 API
  - `genmeta-ssh3-client/src/socks.rs`（Task 23）— 客户端 SOCKS5 API

  **WHY Each Reference Matters**:
  - 服务端/客户端代码：E2E 测试需要同时使用两端的公开 API
  - Task 9 的冒烟测试：TestServer 启动/停止/端口分配骨架可直接复用和扩展
  - RFC：验证端到端行为是否符合规范（消息格式、错误码、流程）
  - 各 Task 的 API：确保 E2E 测试使用正确的公开接口

  **Acceptance Criteria**:
  - [ ] `cargo test --workspace --test e2e_integration` — 全部通过
  - [ ] 10 个 E2E 场景全部覆盖（见 What to do 列表）
  - [ ] TestServer 自动启动/停止 + 端口自动分配
  - [ ] 所有测试使用 localhost，不依赖外部网络
  - [ ] 多 channel 并发测试通过
  - [ ] 连接断开后服务端清理子进程

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: E2E Basic auth + exec
    Tool: Bash
    Steps:
      1. cargo test --workspace --test e2e_integration -- test_basic_auth_exec
    Expected Result: 连接 → Basic auth → exec "echo hello" → stdout == "hello\n" → 正常断开
    Failure Indicators: 认证失败、exec 无输出、进程泄漏
    Evidence: .sisyphus/evidence/task-24-e2e-auth-exec.txt

  Scenario: E2E TCP forwarding roundtrip
    Tool: Bash
    Steps:
      1. cargo test --workspace --test e2e_integration -- test_direct_tcp_roundtrip
    Expected Result: 启动 echo server → direct-tcp → 发送 "ping" → 收到 "ping" → 关闭
    Failure Indicators: 连接超时、数据丢失或损坏
    Evidence: .sisyphus/evidence/task-24-e2e-tcp-forward.txt

  Scenario: E2E SOCKS5 proxy
    Tool: Bash
    Steps:
      1. cargo test --workspace --test e2e_integration -- test_socks5_proxy
    Expected Result: SOCKS5 proxy → CONNECT → echo server → roundtrip data
    Failure Indicators: SOCKS5 协商失败或数据中继断裂
    Evidence: .sisyphus/evidence/task-24-e2e-socks5.txt

  Scenario: E2E 认证失败
    Tool: Bash
    Steps:
      1. cargo test --workspace --test e2e_integration -- test_auth_failure
    Expected Result: 错误密码 → 401 → ConnectError::AuthenticationFailed
    Failure Indicators: 非预期状态码或错误类型
    Evidence: .sisyphus/evidence/task-24-e2e-auth-failure.txt

  Scenario: E2E 连接清理
    Tool: Bash
    Steps:
      1. cargo test --workspace --test e2e_integration -- test_connection_cleanup
    Expected Result: 客户端断开 → 服务端子进程退出 → 无僵尸进程
    Failure Indicators: 子进程未退出或端口未释放
    Evidence: .sisyphus/evidence/task-24-e2e-cleanup.txt
  ```

  **Commit**: YES (groups with Wave 6)
  - Message: `test(ssh3): add comprehensive E2E integration tests for full protocol`
  - Files: `tests/e2e_integration.rs`, `tests/fixtures/*`
  - Pre-commit: `cargo test --workspace --test e2e_integration`

---
## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Rejection → fix → re-run.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `cargo clippy --workspace -- -D warnings` + `cargo test --workspace`. Review all changed files for: empty catches, println! in prod, commented-out code, unused imports. Check AI slop: excessive comments, over-abstraction, generic names (data/result/item/temp). Verify h3x style compliance (Encode/Decode traits, snafu errors, newtype, pub(crate)).
  Output: `Build [PASS/FAIL] | Clippy [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state in ssh3-rfc worktree. Build all binaries. Start server with test certs. Connect with client: Basic auth → exec "echo hello" → verify "hello\n". Test TCP forwarding: direct-tcp + reverse-tcp. Test streamlocal. Test SOCKS5. Test connection drop cleanup. Save evidence to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff. Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT Have" compliance. Detect cross-task contamination. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

| Wave | Commit Message | Files |
|------|---------------|-------|
| 1 | `feat(ssh3): scaffold worktree + wire format codec + error model` | proto/src/* |
| 2 | `feat(ssh3): conversation trait + message types + protocol` | proto/src/*, server/src/* |
| 3 | `feat(ssh3): extended CONNECT handler + version negotiation + auth` | server/src/* |
| 4 | `feat(ssh3): multi-process RTC + PAM + session binary` | proto/src/*, server/src/* |
| 5 | `feat(ssh3): channels + exec + TCP/streamlocal forwarding + SOCKS5` | proto/src/*, server/src/* |
| 6 | `feat(ssh3): client implementation + E2E integration tests` | client/src/*, tests/* |

---

## Success Criteria

### Verification Commands
```bash
# In ssh3-rfc worktree
cargo build --workspace        # Expected: success, no errors
cargo test --workspace         # Expected: all tests pass
cargo clippy --workspace -- -D warnings  # Expected: no warnings

# E2E smoke test
cargo test -p genmeta-ssh3-server --test e2e -- connect_auth_exec
# Expected: PASS — connects, authenticates, exec "echo hello", receives "hello\n"

# Wire format test
cargo test -p genmeta-ssh3-proto -- wire_format
# Expected: PASS — CBOR roundtrip + hex dump match

# Multi-process test
cargo test -p genmeta-ssh3-server --test multiprocess -- rtc_auth_session
# Expected: PASS — spawn child, authenticate via RTC, run session
```

### Final Checklist
- [ ] All "Must Have" present — RFC compliance, PAM, auth, Conversation, version negotiation
- [ ] All "Must NOT Have" absent — no x11, no JWT, no gateway, no VarInt reimpl
- [ ] All tests pass — unit, integration, E2E
- [ ] h3x style compliance — Encode/Decode traits, snafu, newtype, pub(crate)
- [ ] Two-process architecture working — main (HTTP/3) + child (SSH3 session)
