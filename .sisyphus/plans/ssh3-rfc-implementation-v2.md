# SSH3 RFC 合规 Greenfield 重写 (V2 — 审计修正版)

## TL;DR

> **Quick Summary**: 在独立 worktree（ssh3-rfc 分支）中，从零重写 SSH3 实现以完全符合 draft-michel-ssh3-00 RFC。采用 **SSH 二进制格式 + QUIC varint** 编码（非 CBOR），每通道独立 QUIC 双向流（非 channel number 复用），h3x 编码风格，remoc RTC 跨进程通信，两进程架构。
>
> **V2 修正要点**: 修复 V1 中 10 个 RFC 合规错误 — CBOR→SSH binary+varint, ChannelId→stream identity, ChannelOpen(90)/WindowAdjust(93)→删除, ChannelRequest 95→98, 转发通道使用原始字节流。
>
> **Deliverables**:
> - `genmeta-ssh3-proto`: SSH3 wire format codec (QUIC varint) + Conversation trait + SshSession RTC trait + 错误模型
> - `genmeta-ssh3-server`: Extended CONNECT handler + Ssh3Protocol + PAM 认证 + 子进程管理
> - `genmeta-ssh3-server/src/bin/ssh3-session`: 子进程二进制（SSH3 会话处理，setuid/setgid 后执行）
> - `genmeta-ssh3-client`: SSH3 客户端连接 + 会话 + 转发
> - 完整 TDD 测试套件 + E2E 冒烟测试 + wire format hex dump 对比验证
>
> **Estimated Effort**: XL
> **Parallel Execution**: YES — 6 waves
> **Critical Path**: Task 1 → Task 2 → Task 5 → Task 6 → Task 8 → Task 14 → Task 15 → Task 21 → Task 24 → Final

---

## Context

### Original Request
在独立 worktree 中对 SSH3 实现进行 RFC 合规的 greenfield 重写。代码风格参考 h3x（Encode/Decode trait、snafu 错误、newtype、pub(crate)）。Server 端按 axum handler 风格设计。多进程架构使用 remoc RTC。

### V1 审计结果 (导致本次重写)
V1 计划执行时发现 10 个 RFC 合规错误（8 critical + 2 moderate），核心问题：
1. 🔴 使用 CBOR 编码（53处）— RFC 要求 SSH binary + QUIC varint
2. 🔴 消息类型编码为 u8 — 应为 QUIC varint
3. 🔴 SSHv2 风格 ChannelOpen(90)/Confirm(91)/Failure(92) 消息交换 — SSH3 通过打开新 QUIC 流 + channel header 创建通道
4. 🔴 ChannelId(u32) — SSH3 无 channel number
5. 🔴 ChannelWindowAdjust(93) — QUIC 原生流控
6. 🔴 转发通道使用 SSH_MSG_CHANNEL_DATA 包装 — 应为原始字节流
7. 🔴 ChannelRequest=95 — 正确值为 98
8. 🔴 Conversation trait API 使用虚构参数 (ChannelId, initial_window)
9. 🟡 GlobalRequest 机制不明确
10. 🟡 h3x stream_id() API 未验证

**V1 代码已被用户手动删除。仓库为空白状态（仅 .git/.gitignore/.sisyphus/target/）。V2 Task 1 从零创建 workspace + crate 骨架。**

### Interview Summary
**Key Discussions**:
- **重写策略**: Greenfield — 旧实现仅作参考，不做迁移骨架
- **crate 边界**: 保留现有 crate 名称（proto/client/server/ssh-config），内部全新
- **认证**: MVP 只支持 Basic（password），PAM 4 阶段，主进程执行（root 权限），认证通过后 spawn 子进程
- **IPC**: remoc RTC（`#[rtc::remote] trait SshSession`）替代手动消息 enum
- **Protocol 路由**: 全在主进程（Ssh3Protocol.accept_bi → LocalConversation → remoc → RemoteConversation）
- **版本协商**: ssh-version HTTP header，RFC Section 6
- **转发**: TCP + Unix socket + SOCKS5（服务端）
- **排除项**: x11/UDP/agent forwarding、JWT/Bearer/Concealed auth、heartbeat、gateway/gmutils 集成
- **编码格式**: SSH 二进制格式 + QUIC varint（复用 h3x::varint::VarInt），**绝不使用 CBOR**

**Research Findings**:
- h3x Protocol trait 流程：ConnectionBuilder::protocol() → ConnectionState.protocols → accept_bi_stream_task 循环 → Protocol 链
- DHttpProtocol 在 Ssh3Protocol 前注册，优先处理 HTTP/3 frame type
- remoc RTC 宏生成 Client/Server，支持 `provide()/consume()` 一行建连
- conversation_id = CONNECT 的 QUIC stream ID（u64），RFC Section 3 明确
- signal_value = 0xaf3627e6（RFC Section 3.1），编码为 8 字节 QUIC varint（0xC000000000AF3627E6 不对，TODO 验证编码）
- Go 参考实现（francoismichel/ssh3）确认：零 CBOR、QUIC varint 编码、message type 为 varint、channel header = signal_value + conversation_id + channel_type + max_packet_size

### Metis Review (V2 前置审查)
**Identified Gaps** (addressed):
- V1 代码已被用户删除，仓库为空白状态（无 Cargo.toml、无 crate 目录、无源文件）→ V2 Task 1 从零创建 workspace + crate 骨架
- h3x::codec Encode/Decode 对自定义类型的支持需要 spike 验证
- remoc RTC 跨进程 QUIC 流传递需要 spike 验证
- pubkey auth（HTTP Signature RFC 9421）超出 MVP 范围
- Extended Data (type 95) 用于 stderr — 纳入实现范围
- ChannelSuccess(99) / ChannelFailure(100) — 作为 ChannelRequest want_reply 的回复，纳入实现范围
- GlobalRequest 机制：tcpip-forward 等通过 conversation 流上的 SSH_MSG_GLOBAL_REQUEST(80) / SSH_MSG_REQUEST_SUCCESS(81) / SSH_MSG_REQUEST_FAILURE(82) 消息实现，发送在 conversation stream（Extended CONNECT 流）上，而非 channel stream 上
- wire format hex dump 测试必须对照 Go 参考实现的字节序列

---

## 设计宗旨（Design Principles — 所有任务必须遵循）

> **本节是整个计划的根本原则。任何任务中的实现细节如果与本节矛盾，以本节为准。**

### 参考优先级（Reference Priority）

实现代码时，必须按以下优先级查阅参考资料并遵循其模式：

1. **h3x/codec（最高优先）** — h3x 是一个完备的网络传输协议库解析样例。所有编解码相关代码（类型定义、trait 实现、错误处理、流式读写）必须严格参考 h3x 的模式，包括但不限于：
   - `Encode<T>` / `Decode<T>` trait 定义在 stream/writer 类型上（h3x/src/codec.rs:31-70）
   - `EncodeExt::encode_one()` / `DecodeExt::decode_one::<T>()` 调用模式
   - `VarInt` newtype 复用（h3x/src/varint.rs）
   - `StreamReader` / `PeekableStreamReader` / `SinkWriter` 流类型（h3x/src/codec/reader.rs, writer.rs）
   - `Protocol` trait + `StreamVerdict::Accepted | Passed` 模式（h3x/src/protocol.rs）
   - snafu 错误模型（h3x/src/codec/error.rs）
   - `Frame<P>` 结构体模式（h3x/src/dhttp/frame.rs）
   - `pub(crate)` 可见性、newtype 包装、builder 模式

2. **RFC draft-michel-ssh3-00（第二优先）** — 线上格式（wire format）、消息类型常量、通道生命周期、认证流程等必须与 RFC 保持严格一致。当 h3x 模式不涉及 SSH3 特有语义时，以 RFC 为准。

3. **Go 参考实现 francoismichel/ssh3（最低优先）** — 仅在 h3x 和 RFC 都未明确的边界情况下参考。Go 实现可能存在与 RFC 不一致之处，不可盲目照搬。

### 编解码根本原则

1. **Trait-based, not free functions** — 所有编解码通过 `impl Encode<MyType> for S where S: AsyncWrite` 和 `impl Decode<MyType> for S where S: AsyncRead` 实现。调用方式为 `stream.encode_one(value).await?` / `let v: MyType = stream.decode_one().await?`。**严禁**使用 `encode_xxx()` / `decode_xxx()` free functions。

2. **Stream-centric** — 编解码操作直接在 AsyncRead/AsyncWrite stream 上进行，而非在内存 buffer（`Buf`/`BufMut`/`Vec<u8>`）上操作后再写入流。这确保了背压传播和零拷贝的可能性。

3. **复用 h3x 基础设施** — `VarInt`、`StreamReader`、`PeekableStreamReader`、`SinkWriter`、`EncodeExt`、`DecodeExt` 直接从 h3x crate 导入，不重新实现。

4. **SSH 二进制格式** — 所有线上数据使用 SSH 二进制格式 + QUIC varint 编码。**绝不使用 CBOR、JSON、MessagePack 或任何其他序列化格式。**

5. **错误模型** — 编解码错误使用 snafu 派生，遵循 h3x `EncodeError` / `DecodeError` 模式，提供上下文丰富的错误链。

### 架构根本原则

1. **每通道一条 QUIC 双向流** — 无 channel number 复用，无 `ChannelId` 类型，无 `ChannelOpen(90)` 消息。打开 QUIC 流 + 写 channel header = 打开通道。

2. **QUIC 原生流控** — 无 `ChannelWindowAdjust(93)`，无 `initial_window` 参数。

3. **两进程架构** — 主进程（root）处理认证和 Protocol 路由；子进程（用户权限）处理会话逻辑。通过 remoc RTC 通信。

4. **TCP 转发通道使用原始字节流** — 不使用 `SSH_MSG_CHANNEL_DATA` 包装。仅 session 通道使用消息包装。

---

## Work Objectives

### Core Objective
从零实现 RFC draft-michel-ssh3-00 合规的 SSH3 协议栈，使用 **SSH 二进制格式 + QUIC varint 编码**，每通道独立 QUIC 双向流，包含完整的 codec/server/client，采用两进程架构（root 主进程 + 用户权限子进程），所有实现在独立 worktree 中完成。

### Concrete Deliverables
- `genmeta-ssh3-proto/src/`: wire format codec（QUIC varint）、SshMessage enum、Conversation trait、SshSession RTC trait、错误模型
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
- [ ] wire format 字节序列与 Go 参考实现一致（hex dump 对比通过）

### Must Have
- SSH3 wire format 严格符合 RFC — **SSH 二进制格式 + QUIC varint 编码**（非 CBOR）
- 消息类型值：CHANNEL_OPEN_CONFIRMATION=91, CHANNEL_OPEN_FAILURE=92, CHANNEL_DATA=94, CHANNEL_EXTENDED_DATA=95, CHANNEL_EOF=96, CHANNEL_CLOSE=97, CHANNEL_REQUEST=98, CHANNEL_SUCCESS=99, CHANNEL_FAILURE=100
- Channel header 格式：signal_value(0xaf3627e6) + conversation_id(varint) + channel_type_length(varint) + channel_type(utf8) + max_message_size(varint)
- 通道通过 QUIC 双向流标识 — 无 channel number
- Session 通道使用 SSH_MSG_CHANNEL_DATA(94) 包装数据
- TCP 转发通道使用原始字节流（不使用消息包装）
- PAM 4 阶段完整调用 + timing attack 防护
- Basic 认证按 scheme 分派，不支持的返回 401 + WWW-Authenticate
- Conversation trait 抽象（LocalConversation + RemoteConversation）
- 版本协商 ssh-version header
- h3x 编码风格（Encode/Decode trait、snafu 错误、newtype、pub(crate)）

### Must NOT Have (Guardrails)
- **不使用** CBOR/ciborium/serde_cbor — 所有线上格式使用 SSH binary format + QUIC varint
- **不定义** ChannelId 类型 — 通道通过 QUIC 流标识，无 channel number
- **不使用** 消息类型 ChannelOpen(90) — 打开 QUIC 流 + 写 channel header = 打开通道
- **不使用** ChannelWindowAdjust(93) — QUIC 原生流控
- **不实现** 基于 channel number 的复用 — 每通道一条独立 QUIC 双向流
- **不实现** x11 forwarding、UDP forwarding、agent-connection channel
- **不实现** JWT/Bearer、Concealed Auth、OIDC 认证、HTTP Signature (RFC 9421) pubkey auth
- **不实现** heartbeat message
- **不集成** gateway 或 gmutils（推迟到单独计划）
- **不重新实现** VarInt — 复用 h3x::varint::VarInt
- **不发明** 不存在的 h3x API — 先验证再使用
- **不设置** tracing event 的 target
- **不使用** h3x::message::unify — HTTP API 用 http crate 类型
- **不预留** AuthCredential 未来变体定义
- **不做** PAM service name 自动降级 fallback
- **不在** 子进程中注册 Protocol 或路由 stream
- **不使用** initial_window 参数 — QUIC 原生流控

### SSH3 Wire Format 速查表（所有任务必须遵循）

| 元素 | 编码格式 | 示例 |
|------|---------|------|
| 整数字段 (byte/uint32/uint64) | QUIC varint (RFC 9000 §16) | `94` → `0x5e`（1字节varint） |
| 字符串字段 | varint长度前缀 + UTF-8 字节 | `"session"` → `07 73 65 73 73 69 6f 6e` |
| 布尔字段 | 单字节 (0x00/0x01) | `true` → `0x01` |
| 消息类型标签 | QUIC varint | `SSH_MSG_CHANNEL_DATA=94` → `0x5e` |
| Channel header | signal_value(varint) + conversation_id(varint) + channel_type(ssh_string) + max_message_size(varint) | — |
| Channel number | **不存在** — 通道 = QUIC 流 | — |
| Codec 模式 | h3x Encode/Decode trait impl on stream types | `stream.encode_one(SshString("session".into())).await?` |

**编解码模式（所有任务必须遵循）**: 不使用 free functions（如 encode_varint/decode_message），而是通过 h3x Encode/Decode trait 在 AsyncRead/AsyncWrite stream 上实现。调用方式：`stream.encode_one(value).await?` / `stream.decode_one::<Type>().await?`。参考 h3x/src/varint.rs:189-222 和 h3x/src/codec.rs:31-70。
---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: NO（仓库为空白状态，Task 1 从零创建 workspace + crate 骨架后才可运行 cargo test）
- **Automated tests**: TDD (RED → GREEN → REFACTOR)
- **Framework**: cargo test (Rust built-in)
- **Each task**: 先写失败测试 → 实现通过 → 重构

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Wire format**: cargo test + hex dump 对比 Go 参考实现字节序列
- **Protocol**: cargo test --test integration
- **Server/Client**: tmux 启动服务 → 客户端连接 → 验证输出
- **IPC**: cargo test 子进程 spawn + RTC 调用验证

### Wire Format 验证标准
每个 Encode/Decode 实现必须有以下测试：
1. **Roundtrip test**: encode(value) → decode → 与原值相等
2. **Hex dump test**: encode(known_value) → 与预期字节序列完全一致
3. **Cross-reference test**: 字节序列与 Go 参考实现（francoismichel/ssh3）的输出一致

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — worktree reset + codec foundation):
├── Task 1: Worktree 重置 + crate 骨架（清理 V1 CBOR 代码） [quick]
├── Task 2: SSH binary wire format codec — QUIC varint 编解码 [deep]
├── Task 3: SSH3 错误模型 [quick]

Wave 2 (After Wave 1 — protocol abstractions + message types):
├── Task 4: Conversation trait + LocalConversation [deep]
├── Task 5: SshMessage enum 完整定义 [unspecified-high]
├── Task 6: Ssh3Protocol (h3x Protocol trait 实现) [deep]
├── Task 7: h3x API 验证 spike + remoc RTC spike [quick]

Wave 3 (After Wave 2 — server HTTP layer):
├── Task 8: 版本协商 + 认证解析 [unspecified-high]
├── Task 9: Extended CONNECT handler [deep]
├── Task 10: E2E 冒烟测试骨架 [quick]

Wave 4 (After Wave 2 — multi-process, parallel with Wave 3):
├── Task 11: SshSession RTC trait + SessionInit/AuthError [deep]
├── Task 12: PAM wrapper [unspecified-high]
├── Task 13: ssh3-session 子进程二进制 [deep]
├── Task 14: ChildProcess 主进程管理 [unspecified-high]

Wave 5 (After Wave 3+4 — session + forwarding):
├── Task 15: Channel open/confirm/data 处理（session 通道） [deep]
├── Task 16: Exec/Shell/Subsystem 请求处理 [deep]
├── Task 17: PTY 分配 + 终端处理 [unspecified-high]
├── Task 18: Direct-TCP 转发（原始字节流） [unspecified-high]
├── Task 19: Reverse-TCP 转发 (global request + channel open) [unspecified-high]
├── Task 20: Streamlocal (Unix socket) 转发 [unspecified-high]
├── Task 21: SOCKS5 代理（服务端） [deep]

Wave 6 (After Wave 5 — client + integration):
├── Task 22: SSH3 客户端连接 + 认证 [deep]
├── Task 23: 客户端会话 + 转发请求 [deep]
├── Task 24: 客户端 SOCKS5 [unspecified-high]
├── Task 25: 完整 E2E 集成测试 [deep]

Wave FINAL (After ALL tasks — independent review, 4 parallel):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)

Critical Path: T1 → T2 → T5 → T6 → T9 → T15 → T16 → T22 → T25 → FINAL
Parallel Speedup: ~60% faster than sequential
Max Concurrent: 7 (Wave 5)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 2, 3 | 1 |
| 2 | 1 | 4, 5, 6, 7 | 1 |
| 3 | 1 | 6, 8, 9, 12 | 1 |
| 4 | 2 | 6, 9, 11, 15 | 2 |
| 5 | 2 | 6, 15, 16 | 2 |
| 6 | 2, 3, 4, 5 | 9, 10 | 2 |
| 7 | 2 | 9, 13 | 2 |
| 8 | 3 | 9 | 3 |
| 9 | 3, 4, 6, 7, 8 | 10, 25 | 3 |
| 10 | 6, 9 | 25 | 3 |
| 11 | 4 | 13, 14 | 4 |
| 12 | 3 | 13 | 4 |
| 13 | 7, 11, 12 | 14, 25 | 4 |
| 14 | 11, 13 | 25 | 4 |
| 15 | 4, 5 | 16, 18, 19, 20 | 5 |
| 16 | 5, 15 | 17, 25 | 5 |
| 17 | 16 | 25 | 5 |
| 18 | 15 | 21, 25 | 5 |
| 19 | 15 | 25 | 5 |
| 20 | 15 | 25 | 5 |
| 21 | 15, 18 | 24, 25 | 5 |
| 22 | 6, 9 | 23, 25 | 6 |
| 23 | 15, 16, 22 | 24, 25 | 6 |
| 24 | 21, 23 | 25 | 6 |
| 25 | 9, 13, 14, 16, 17, 18, 22, 23 | FINAL | 6 |
| F1-F4 | 25 | — | FINAL |

### Agent Dispatch Summary

- **Wave 1**: **3** — T1 → `quick`, T2 → `deep`, T3 → `quick`
- **Wave 2**: **4** — T4 → `deep`, T5 → `unspecified-high`, T6 → `deep`, T7 → `quick`
- **Wave 3**: **3** — T8 → `unspecified-high`, T9 → `deep`, T10 → `quick`
- **Wave 4**: **4** — T11 → `deep`, T12 → `unspecified-high`, T13 → `deep`, T14 → `unspecified-high`
- **Wave 5**: **7** — T15 → `deep`, T16 → `deep`, T17 → `unspecified-high`, T18 → `unspecified-high`, T19 → `unspecified-high`, T20 → `unspecified-high`, T21 → `deep`
- **Wave 6**: **4** — T22 → `deep`, T23 → `deep`, T24 → `unspecified-high`, T25 → `deep`
- **FINAL**: **4** — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

### Wave 1: Workspace 初始化 + Codec Foundation

- [x] 1. Workspace 初始化 + Crate 骨架（从零创建）

  **What to do**:
  - 在仓库根目录创建 workspace `Cargo.toml`，定义 `[workspace]` 及 `members = ["genmeta-ssh3-proto", "genmeta-ssh3-client", "genmeta-ssh3-server"]`
  - 创建 `genmeta-ssh3-proto/` 目录 + `Cargo.toml`（依赖：h3x、snafu、tracing、bytes、tokio）+ `src/lib.rs`（仅 `//! SSH3 protocol types and codec`）
  - 创建 `genmeta-ssh3-client/` 目录 + `Cargo.toml`（依赖：genmeta-ssh3-proto、h3x、tokio、tracing）+ `src/lib.rs`（仅 `//! SSH3 client implementation`）
  - 创建 `genmeta-ssh3-server/` 目录 + `Cargo.toml`（依赖：genmeta-ssh3-proto、h3x、tokio、tracing、remoc）+ `src/lib.rs`（仅 `//! SSH3 server implementation`）
  - 在 `genmeta-ssh3-server/` 中创建 `src/bin/ssh3-session.rs`（仅 `fn main() { todo!() }`）
  - 验证 `cargo check --workspace` 通过
  - 确认 `grep -r "cbor\|ciborium\|serde_cbor" --include="*.rs" --include="*.toml" .` 返回零匹配

  **Must NOT do**:
  - 不添加任何 CBOR 相关依赖（ciborium、serde_cbor 等）
  - 不创建 Task 2-3 的文件（codec.rs, error.rs）
  - 不在 src/lib.rs 中写任何实质代码

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 纯文件创建和骨架搭建，无复杂逻辑
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `git-master`: 不涉及 git 操作

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 1 (sequential — must complete first)
  - **Blocks**: Tasks 2, 3
  - **Blocked By**: None (can start immediately)

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/Cargo.toml` — h3x 的 Cargo.toml 结构参考（edition、dependencies 声明方式、feature flags）。注：h3x 为单 crate 结构（非 workspace），本项目需创建 workspace 结构，仅参考其依赖声明风格

  **External References**:
  - `https://doc.rust-lang.org/cargo/reference/workspaces.html` — Cargo workspace 官方文档

  **WHY Each Reference Matters**:
  - h3x Cargo.toml — 本项目需要与 h3x 兼容，参考其 workspace 组织方式确保依赖声明一致
  - Cargo workspace 文档 — 仓库当前为空白状态，需从零创建正确的 workspace 结构

  **File Boundary**: 只可创建 `Cargo.toml`（根目录 + 3 个 crate）、`*/src/lib.rs`（3 个 crate）、`genmeta-ssh3-server/src/bin/ssh3-session.rs`

  **Acceptance Criteria**:
  - [ ] `cargo check --workspace` 通过
  - [ ] `grep -r "cbor\|ciborium\|serde_cbor" --include="*.rs" --include="*.toml" .` 返回零匹配
  - [ ] 三个 crate 各有 Cargo.toml + src/lib.rs
  - [ ] ssh3-session bin 存在且有 main 函数
  - [ ] workspace Cargo.toml 包含全部三个 members

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Workspace 从零创建并成功编译
    Tool: Bash
    Preconditions: 仓库为空白状态（无 Cargo.toml、无 crate 目录）
    Steps:
      1. Run `ls Cargo.toml genmeta-ssh3-proto/Cargo.toml genmeta-ssh3-client/Cargo.toml genmeta-ssh3-server/Cargo.toml` — 确认四个 Cargo.toml 存在
      2. Run `cargo check --workspace` — 确认编译通过
      3. Run `grep -r "cbor\|ciborium\|serde_cbor" --include="*.rs" --include="*.toml" .` — 确认零匹配
      4. Run `ls genmeta-ssh3-server/src/bin/ssh3-session.rs` — 确认 bin 文件存在
      5. Run `grep -c "members" Cargo.toml` — 确认 workspace members 声明存在
    Expected Result: 全部命令成功，cargo check 通过，零 CBOR 引用，bin 文件存在
    Failure Indicators: 任何 Cargo.toml 不存在、cargo check 失败、grep 找到 CBOR 引用
    Evidence: .sisyphus/evidence/task-1-workspace-creation.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3): initialize workspace and create greenfield crate scaffolding`
  - Files: `Cargo.toml`, `genmeta-ssh3-proto/Cargo.toml`, `genmeta-ssh3-proto/src/lib.rs`, `genmeta-ssh3-client/Cargo.toml`, `genmeta-ssh3-client/src/lib.rs`, `genmeta-ssh3-server/Cargo.toml`, `genmeta-ssh3-server/src/lib.rs`, `genmeta-ssh3-server/src/bin/ssh3-session.rs`
  - Pre-commit: `cargo check --workspace`

- [x] 2. SSH Binary Wire Format Codec — QUIC Varint 编解码

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/codec.rs` 中实现 SSH3 wire format 编解码核心，**严格遵循 h3x 的 Encode/Decode trait 模式**
  - 复用 `h3x::varint::VarInt` 类型（已有 `Encode<VarInt>` 和 `Decode<VarInt>` trait impl），不重新实现
  - 定义以下 SSH3 协议专用 newtype，并为每个实现 `Encode<T>` / `Decode<T>` trait（在 AsyncWrite/AsyncRead 上）：
    - `SshString(String)` — varint长度前缀 + UTF-8 字节
      ```rust
      pub(crate) struct SshString(pub String);
      // impl<S: AsyncWrite + Send> Encode<SshString> for S { ... }
      // impl<S: AsyncRead + Send> Decode<SshString> for S { ... }
      ```
    - `SshBytes(Vec<u8>)` — varint长度前缀 + raw bytes
      ```rust
      pub(crate) struct SshBytes(pub Vec<u8>);
      ```
    - `SshBool(bool)` — 单字节 0x00/0x01
      ```rust
      pub(crate) struct SshBool(pub bool);
      ```
  - 定义 `ChannelHeader` struct 并实现 Encode/Decode trait：
    ```rust
    pub(crate) struct ChannelHeader {
        pub signal_value: u32,
        pub conversation_id: u64,
        pub channel_type: String,
        pub max_message_size: u64,
    }
    // impl<S: AsyncWrite + Send> Encode<&ChannelHeader> for S { ... }
    //   writes: VarInt(signal_value) + VarInt(conversation_id) + SshString(channel_type) + VarInt(max_message_size)
    // impl<S: AsyncRead + Send> Decode<ChannelHeader> for S { ... }
    //   reads: same order
    ```
  - **Encode/Decode trait 模式**（参考 h3x/src/codec.rs:31-70 和 h3x/src/varint.rs:189-222）：
    ```rust
    // h3x pattern: trait impl on stream type, NOT free function
    impl<S: AsyncWrite + Send> Encode<SshString> for S {
        type Output = ();
        type Error = EncodeError;
        async fn encode(mut self, item: SshString) -> Result<Self::Output, Self::Error> {
            self.encode_one(VarInt::try_from(item.0.len() as u64)?).await?;
            self.write_all(item.0.as_bytes()).await?;
            Ok(())
        }
    }
    // Usage: stream.encode_one(SshString("session".into())).await?;
    // Usage: let s: SshString = stream.decode_one::<SshString>().await?;
    ```
  - **重要**: 不定义 free functions（如 encode_varint/decode_varint/encode_ssh_string 等），而是通过 trait impls 提供编解码能力，使用 `EncodeExt::encode_one()` / `DecodeExt::decode_one::<T>()` 调用
  - 每个类型必须有 TDD 测试：
    - roundtrip 测试（encode → decode → assert_eq）
    - hex dump 测试（encode → 与预期字节序列逐字节对比）
    - 边界值测试（0, u32::MAX, u64::MAX, 空字符串, 长字符串）
  - **signal_value 编码**: 0xaf3627e6 作为 QUIC varint 编码（参考 Go 实现 `util/wire.go` 中 quicvarint.Append）

  **Must NOT do**:
  - 不使用 CBOR — 所有编码为 QUIC varint + raw bytes
  - 不使用 serde derive — 手动实现 Encode/Decode trait
  - 不定义 ChannelId — channel header 无 channel number 字段
  - 不实现消息级别编解码 — 只做原语类型和 channel header（消息在 Task 5）
  - 不重新实现 VarInt 类型 — 复用 h3x::varint::VarInt
  - **不使用 free functions（encode_varint/decode_varint 等）**— 全部通过 Encode/Decode trait impl
  - **不使用 Buf/BufMut 作为编解码目标** — 使用 AsyncRead/AsyncWrite stream 类型

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 二进制编解码需要精确的字节级正确性，h3x trait 模式需要仔细的 async trait impl
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: 不涉及浏览器

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 Task 1 完成骨架）
  - **Parallel Group**: Wave 1 (sequential after Task 1)
  - **Blocks**: Tasks 4, 5, 6, 7
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/varint.rs:189-222` — VarInt 的 Encode/Decode trait impl 示例（**必须严格参考此模式**）
  - `/home/yiyue/code/reimu/h3x/src/codec.rs:31-70` — Encode/Decode trait 定义 + EncodeExt/DecodeExt 辅助 trait
  - `/home/yiyue/code/reimu/h3x/src/codec/error.rs` — EncodeError/DecodeError snafu 错误类型（codec 错误应复用或仿照）
  - `/home/yiyue/code/reimu/h3x/src/dhttp/settings.rs` — Settings 类型的 Encode/Decode impl 示例（复合类型编解码参考）
  - `/home/yiyue/code/reimu/h3x/src/dhttp/goaway.rs` — Goaway 类型的 Encode/Decode impl 示例

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3 — Wire format 速查表（channel header, message types, varint 编码）

  **External References**:
  - Go 参考实现 `util/wire.go` (francoismichel/ssh3 SHA 5b4b242d) — `WriteVarInt()`, `ReadVarInt()`, `WriteSSHString()`, `ReadSSHString()` 函数，字节序列权威参考
  - Go 参考实现 `message/channel.go` — `BuildChannelHeader()` 函数，channel header 字节序列参考
  - RFC 9000 §16 — QUIC Variable-Length Integer Encoding 规范

  **WHY Each Reference Matters**:
  - h3x varint.rs: **最关键参考** — 必须严格模仿其 Encode/Decode trait impl 模式（impl on AsyncWrite/AsyncRead, type Output/Error, async fn encode/decode）
  - h3x codec.rs: Encode/Decode trait 定义和 EncodeExt 的 encode_one() 调用方式 — 所有下游 task 都通过此 API 调用编解码
  - h3x settings.rs/goaway.rs: 复合类型（多字段 struct）的 Encode/Decode impl 示例 — ChannelHeader 编解码参考
  - Go wire.go: 字节序列的唯一权威来源 — hex dump 测试必须与 Go 输出一致
  - Go channel.go: channel header 的字节序列参考 — 验证 signal_value + conversation_id 编码顺序
  **File Boundary**: 只可修改 `genmeta-ssh3-proto/src/codec.rs`、`genmeta-ssh3-proto/src/lib.rs`（添加 mod codec）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- codec` 全部通过
  - [ ] 每个编解码原语有 roundtrip + hex dump 测试
  - [ ] channel header roundtrip 测试通过
  - [ ] signal_value 0xaf3627e6 的 varint 编码字节序列正确
  - [ ] 零 CBOR 引用

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Varint encoding matches QUIC RFC 9000 §16
    Tool: Bash
    Preconditions: codec.rs implemented with tests
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- codec::tests::varint_encoding_known_values`
      2. Verify test includes hex dump assertions for: 0 → [0x00], 63 → [0x3f], 64 → [0x40, 0x40], 16383 → [0x7f, 0xff], 16384 → [0x80, 0x00, 0x40, 0x00]
    Expected Result: All varint encoding tests pass with exact byte sequences matching RFC 9000 §16 examples
    Failure Indicators: Any hex dump mismatch or test failure
    Evidence: .sisyphus/evidence/task-2-varint-encoding.txt

  Scenario: Channel header encoding matches Go reference implementation
    Tool: Bash
    Preconditions: ChannelHeader codec implemented
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- codec::tests::channel_header_roundtrip`
      2. Run `cargo test -p genmeta-ssh3-proto -- codec::tests::channel_header_hex_dump`
      3. Verify signal_value 0xaf3627e6 encodes to correct varint bytes
    Expected Result: Roundtrip preserves all fields, hex dump matches expected sequence
    Failure Indicators: Field mismatch after roundtrip, or hex bytes differ from expected
    Evidence: .sisyphus/evidence/task-2-channel-header.txt

  Scenario: SSH string encoding uses varint length prefix (not u32)
    Tool: Bash
    Preconditions: ssh_string codec implemented
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- codec::tests::ssh_string_hex_dump`
      2. Verify "session" encodes as [0x07, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e] (varint 7 + UTF-8)
      3. Verify empty string encodes as [0x00]
    Expected Result: String encoding uses varint length prefix, not fixed 4-byte u32
    Failure Indicators: Length prefix is 4 bytes instead of varint, or UTF-8 bytes wrong
    Evidence: .sisyphus/evidence/task-2-ssh-string.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-proto): implement SSH binary wire format codec with QUIC varint encoding`
  - Files: `genmeta-ssh3-proto/src/codec.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- codec`

- [x] 3. SSH3 错误模型 + AuthCredential 类型

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/error.rs` 中定义 snafu 错误类型：
    - `Ssh3Error` — 顶层错误 enum（snafu derive）
      - `CodecError` — 编解码错误（varint too large, buffer underflow, invalid message type, invalid string encoding）
      - `ProtocolError` — 协议级错误（unknown channel type, unexpected message, version mismatch）
      - `AuthError` — 认证错误（invalid credentials, PAM failure, unsupported auth scheme）
      - `ChannelError` — 通道错误（channel closed, EOF, request failed）
      - `SessionError` — 会话错误（exec failed, pty allocation failed, forwarding failed）
  - 在 `genmeta-ssh3-proto/src/auth.rs` 中定义：
    - `AuthCredential` enum — 仅 `Basic { username: String, password: String }` 一个变体
    - `AuthScheme` enum — 仅 `Basic` 一个变体
    - `parse_authorization_header(header_value: &str) -> Result<AuthCredential>` — 解析 HTTP Authorization header（Basic base64 decode）
  - 所有错误类型实现 `Display`（通过 snafu 自动生成）
  - 错误类型使用 `#[snafu(visibility(pub(crate)))]`

  **Must NOT do**:
  - 不预留 AuthCredential 未来变体定义（如 Bearer, PublicKey）— 只有 Basic
  - 不使用 anyhow/thiserror — 统一使用 snafu
  - 不设置 tracing event 的 target
  - 不定义 ChannelId 相关错误变体

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 类型定义和 snafu derive 属于直接的结构化工作
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Task 2 并行 — 但需要 Task 1 完成）
  - **Parallel Group**: Wave 1 (parallel with Task 2 after Task 1)
  - **Blocks**: Tasks 6, 8, 9, 12
  - **Blocked By**: Task 1

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/error.rs`（如果存在）— h3x 的 snafu 错误模式
  - 搜索 `#[derive(Debug, Snafu)]` 在 h3x crate 中找到示例错误定义

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 4 — 认证机制描述
  - HTTP Authorization header (RFC 7617) — Basic auth base64 格式 `Basic base64(user:pass)`

  **External References**:
  - snafu crate docs — `#[snafu(visibility(...))]`, `#[snafu(display(...))]` 用法

  **WHY Each Reference Matters**:
  - h3x error 模式: 保持 error 风格一致（visibility, display format, context selector pattern）
  - RFC Section 4: 确认 Basic auth 格式正确（仅 password-based，scheme="Basic"）

  **File Boundary**: 只可修改 `genmeta-ssh3-proto/src/error.rs`、`genmeta-ssh3-proto/src/auth.rs`、`genmeta-ssh3-proto/src/lib.rs`（添加 mod error, mod auth）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- error` 通过
  - [ ] `cargo test -p genmeta-ssh3-proto -- auth` 通过
  - [ ] AuthCredential 仅有 Basic 变体
  - [ ] `parse_authorization_header("Basic dXNlcjpwYXNz")` 返回 `Basic { username: "user", password: "pass" }`
  - [ ] 非 Basic scheme 返回 AuthError

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Basic auth header parsing
    Tool: Bash
    Preconditions: auth.rs implemented with parse_authorization_header
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- auth::tests::parse_basic_auth`
      2. Verify test covers: valid "Basic dXNlcjpwYXNz" → user/pass
      3. Verify test covers: invalid scheme "Bearer xxx" → AuthError
      4. Verify test covers: malformed base64 → CodecError or AuthError
    Expected Result: Valid Basic auth parsed correctly, non-Basic schemes rejected
    Failure Indicators: Wrong username/password, or non-Basic schemes accepted
    Evidence: .sisyphus/evidence/task-3-basic-auth.txt

  Scenario: Error types compile and display correctly
    Tool: Bash
    Preconditions: error.rs defined with snafu derives
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- error::tests`
      2. Verify each error variant has a meaningful Display implementation
      3. Run `cargo doc -p genmeta-ssh3-proto --no-deps` to verify docs build
    Expected Result: All error variants constructible, displayable, and documented
    Failure Indicators: snafu derive errors, Display shows raw debug format
    Evidence: .sisyphus/evidence/task-3-error-model.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-proto): define snafu error model and AuthCredential`
  - Files: `genmeta-ssh3-proto/src/error.rs`, `genmeta-ssh3-proto/src/auth.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto`

### Wave 2: Protocol Abstractions + Message Types

- [x] 4. Conversation Trait + LocalConversation

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/conversation.rs` 中定义：
    - `Conversation` trait：
      ```rust
      #[async_trait]
      pub(crate) trait Conversation: Send + Sync {
          /// conversation_id = CONNECT stream 的 QUIC stream ID
          fn conversation_id(&self) -> u64;
          /// 开始新通道：打开新 QUIC 双向流 + 写 channel header
          async fn open_channel(&self, channel_type: &str, max_message_size: u64) -> Result<BoxPeekableBiStream<C>>;
          /// 接受传入通道流（由 Ssh3Protocol 派发，已解码 channel header）
          async fn accept_channel(&self) -> Result<(ChannelHeader, BoxPeekableBiStream<C>)>;
          /// 发送 global request（tcpip-forward 等）—— 在 conversation stream 上发送 SSH 消息
          async fn send_global_request(&self, request_type: &str, want_reply: bool, data: &[u8]) -> Result<Option<Vec<u8>>>;
          /// 接收 global request（服务端用）—— 从 conversation stream 读取 SSH 消息
          async fn recv_global_request(&self) -> Result<(String, bool, Vec<u8>)>;
      }
      ```
    - `LocalConversation` struct：
      - 包装 `Arc<QuicConnection<C>>` + 一个内部通道队列 `mpsc::Receiver<(ChannelHeader, BoxPeekableBiStream<C>)>`（用于接收 Ssh3Protocol 派发的入站流）
      - `open_channel`: 在 QUIC 连接上打开新双向流 → 写入 channel header → 返回读写半边
      - `accept_channel`: 从内部 mpsc::Receiver 接收已派发的流（由 Ssh3Protocol.accept_bi 解码 header 后通过 mpsc::Sender 发送），**不直接从 QuicConnection 接受流**
      - `send_global_request`: 在 conversation stream（CONNECT 流）上发送 SSH_MSG_GLOBAL_REQUEST(80) 消息，若 want_reply=true 则等待 SSH_MSG_REQUEST_SUCCESS(81)/FAILURE(82)
      - `recv_global_request`: 从 conversation stream 读取 SSH_MSG_GLOBAL_REQUEST(80) 消息
      - `conversation_id`: 返回 CONNECT 流的 stream ID
    - 注意：`RemoteConversation`（通过 remoc RTC 代理）在 Task 11 中实现
  - 写 channel header 时使用 h3x Encode/Decode trait：`writer.encode_one(channel_header).await?` / `let header: ChannelHeader = reader.decode_one().await?`（参考设计宗旨 §编解码根本原则）
  - Global request 消息编解码使用 Task 5 定义的 SshMessage Encode/Decode trait
  - 单元测试：
    - mock QUIC 连接 → open_channel → verify channel header bytes on stream
    - mock mpsc 通道 → accept_channel → verify 接收派发的流
    - global request roundtrip 测试（发送 + 接收）
  **Must NOT do**:
  - 不定义 ChannelId — open_channel 返回 stream handles，不返回 channel number
  - 不实现 RemoteConversation — 延迟到 Task 11
  - 不实现 initial_window 参数 — QUIC 原生流控
  - 不使用 ChannelOpen(90) 消息 — 打开 QUIC 流 = 打开通道
  - 不在 conversation.rs 中定义消息类型 — 那是 Task 5

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 涉及 QUIC stream 抽象和异步 trait 设计，需要仔细的生命周期管理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 5, 6, 7 并行）
  - **Parallel Group**: Wave 2
  - **Blocks**: Tasks 6, 9, 11, 15
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/codec.rs:26-29` — BoxPeekableBiStream 类型（QUIC 双向流的读写端）
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/connection.rs` — QuicConnection 抽象，用于打开新双向流

  **API/Type References**:
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader 的 `Encode<ChannelHeader>` / `Decode<ChannelHeader>` trait impl（通过 `stream.encode_one(header).await?` / `stream.decode_one::<ChannelHeader>().await?` 调用）
  - RFC draft-michel-ssh3-00 Section 3 — conversation_id 定义（= CONNECT stream ID）
  - RFC draft-michel-ssh3-00 Section 3.1 — channel header 格式

  **External References**:
  - Go 参考实现 `channel.go` (francoismichel/ssh3) — `openChannel()` / `acceptChannel()` 流程

  **WHY Each Reference Matters**:
  - BoxPeekableBiStream: 了解 h3x 如何表示 QUIC 双向流，确保 Conversation 返回兼容类型
  - Go channel.go: open/accept channel 的完整流程参考（header 写入顺序、stream 管理）
  - RFC Section 3/3.1: conversation_id 和 channel header 的权威定义

  **File Boundary**: 只可修改 `genmeta-ssh3-proto/src/conversation.rs`、`genmeta-ssh3-proto/src/lib.rs`（添加 mod conversation）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- conversation` 通过
  - [ ] Conversation trait 无 ChannelId 参数
  - [ ] open_channel 写入正确的 channel header 字节序列
  - [ ] accept_channel 从内部 mpsc 队列接收派发的流（不直接访问 QuicConnection）
  - [ ] send_global_request 在 conversation stream 上发送 SSH_MSG_GLOBAL_REQUEST(80)
  - [ ] recv_global_request 从 conversation stream 读取 SSH_MSG_GLOBAL_REQUEST(80)
  - [ ] 无 ChannelOpen(90) 消息交换

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: open_channel writes correct channel header bytes
    Tool: Bash
    Preconditions: LocalConversation with mock QUIC connection
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- conversation::tests::open_channel_writes_header`
      2. Verify test opens a channel with type="session", max_message_size=32768
      3. Verify the first bytes on the stream are: signal_value(varint) + conversation_id(varint) + "session"(ssh_string) + 32768(varint)
    Expected Result: Channel header bytes match expected encoding
    Failure Indicators: Header bytes wrong, or ChannelOpen(90) message sent instead of header
    Evidence: .sisyphus/evidence/task-4-open-channel-header.txt

  Scenario: accept_channel receives from internal dispatch queue
    Tool: Bash
    Preconditions: LocalConversation with mock mpsc channel (simulating Ssh3Protocol dispatch)
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- conversation::tests::accept_channel_from_dispatch`
      2. Send a (ChannelHeader, stream) pair through the mpsc::Sender
      3. Verify accept_channel() returns the same ChannelHeader and stream
    Expected Result: accept_channel receives dispatched stream without touching QuicConnection
    Failure Indicators: accept_channel tries to accept directly from QuicConnection
    Evidence: .sisyphus/evidence/task-4-accept-channel-dispatch.txt

  Scenario: global request roundtrip on conversation stream
    Tool: Bash
    Preconditions: LocalConversation with mock conversation stream
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- conversation::tests::global_request_roundtrip`
      2. Verify send_global_request encodes SSH_MSG_GLOBAL_REQUEST(80) with request_type + want_reply + data
      3. Verify recv_global_request decodes the same message correctly
      4. Verify want_reply=true triggers wait for SSH_MSG_REQUEST_SUCCESS(81)/FAILURE(82)
    Expected Result: Global request sent and received correctly on conversation stream
    Failure Indicators: Wrong message type, or global request sent on wrong stream
    Evidence: .sisyphus/evidence/task-4-global-request.txt

  **Commit**: YES
  - Message: `feat(ssh3-proto): implement Conversation trait with LocalConversation`
  - Files: `genmeta-ssh3-proto/src/conversation.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- conversation`

- [x] 5. SshMessage Enum 完整定义 + SSH Binary Codec

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/message.rs` 中定义 `SshMessage` enum：
    ```rust
    pub(crate) enum SshMessage {
        /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
        ChannelOpenConfirmation {
            max_message_size: u64, // server 端的 max_message_size
        },
        /// SSH_MSG_CHANNEL_OPEN_FAILURE = 92
        ChannelOpenFailure {
            reason_code: u64,
            description: String,
        },
        /// SSH_MSG_CHANNEL_DATA = 94
        ChannelData {
            data: Vec<u8>,
        },
        /// SSH_MSG_CHANNEL_EXTENDED_DATA = 95
        ChannelExtendedData {
            data_type: u64, // 1 = stderr
            data: Vec<u8>,
        },
        /// SSH_MSG_CHANNEL_EOF = 96
        ChannelEof,
        /// SSH_MSG_CHANNEL_CLOSE = 97
        ChannelClose,
        /// SSH_MSG_CHANNEL_REQUEST = 98
        ChannelRequest {
            request_type: String,
            want_reply: bool,
            request_data: Vec<u8>, // 原始负载，按 request_type 解析
        },
        /// SSH_MSG_CHANNEL_SUCCESS = 99
        ChannelSuccess,
        /// SSH_MSG_CHANNEL_FAILURE = 100
        ChannelFailure,
        /// SSH_MSG_GLOBAL_REQUEST = 80 (conversation stream only)
        GlobalRequest {
            request_type: String,
            want_reply: bool,
            data: Vec<u8>,
        },
        /// SSH_MSG_REQUEST_SUCCESS = 81 (conversation stream only)
        RequestSuccess {
            data: Vec<u8>,
        },
        /// SSH_MSG_REQUEST_FAILURE = 82 (conversation stream only)
        RequestFailure,
    }
    ```
  - 实现 Encode/Decode trait（参考设计宗旨 §编解码根本原则）：
    - `impl<S: AsyncWrite + Send + Unpin> Encode<&SshMessage> for S` — 写入 message_type(varint) + 各字段(varint/ssh_string/ssh_bytes/bool)
    - `impl<S: AsyncRead + Send + Unpin> Decode<SshMessage> for S` — 读 message_type(varint) → 按类型解码各字段
    - 调用方式：`stream.encode_one(&msg).await?` / `let msg: SshMessage = stream.decode_one().await?`
    - **严禁**定义 `encode_message()` / `decode_message()` free functions
  - TDD 测试：每个消息类型的 roundtrip + hex dump
  - **关键**: ChannelRequest request_data 先作为原始字节保存，不在此处解析具体 request type（exec/shell/pty 在 Task 16 解析）
  - **关键**: GlobalRequest(80)/RequestSuccess(81)/RequestFailure(82) 属于 conversation 级消息（在 conversation stream 上发送），不在 channel stream 上使用。但它们复用同一个 SshMessage enum 以简化编解码。

  **Must NOT do**:
  - 不定义 ChannelOpen(90) — 不存在
  - 不定义 ChannelWindowAdjust(93) — 不存在
  - 不在消息中包含 channel_number 字段 — 无 ChannelId
  - 不使用 CBOR 编解码
  - 不解析 ChannelRequest 的 request_data 内容 — 只保存原始字节
  - 不使用 ChannelRequest type=95 — 正确值为 98

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 多消息类型的编解码工作量大但模式统一，需要仔细但非极度复杂
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 4, 6, 7 并行）
  - **Parallel Group**: Wave 2
  - **Blocks**: Tasks 6, 15, 16
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — VarInt/SshString/SshBytes/Bool 的 `Encode<T>`/`Decode<T>` trait impl（SshMessage 的 Encode/Decode 内部通过 `self.encode_one(VarInt(msg_type)).await?` 等调用这些原语）

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3.2-3.9 — 每个消息类型的字段定义
  - Go 参考实现 `message/message.go` (francoismichel/ssh3 SHA 5b4b242d) — 消息类型常量表（SSH_MSG_CHANNEL_DATA=94, SSH_MSG_CHANNEL_REQUEST=98 等）

  **External References**:
  - Go 参考实现 `message/message.go` (francoismichel/ssh3) — `ParseMessage()` / `Write()` 函数，message type + 字段顺序的权威参考
  - Go 参考实现 `message/channel_request.go` — ChannelRequest 的编解码细节

  **WHY Each Reference Matters**:
  - codec.rs: 复用原语而非重复实现 — 确保字节级一致性
  - Go message.go: message type varint + 字段顺序的唯一权威来源
  - Go channel_request.go: ChannelRequest 的 want_reply + request_data 编解码顺序确认

  **File Boundary**: 只可修改 `genmeta-ssh3-proto/src/message.rs`、`genmeta-ssh3-proto/src/lib.rs`（添加 mod message）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-proto -- message` 全部通过
  - [ ] 每个消息类型有 roundtrip + hex dump 测试
  - [ ] ChannelRequest type = 98（非 95）
  - [ ] 无 ChannelOpen(90)、ChannelWindowAdjust(93) 消息类型
  - [ ] 无 channel_number 字段
  - [ ] ChannelExtendedData 包含 data_type 字段
  - [ ] GlobalRequest(80)、RequestSuccess(81)、RequestFailure(82) 均有 roundtrip 测试
  - [ ] SshMessage enum 共 12 个变体（9 channel + 3 global）
  **QA Scenarios (MANDATORY):**
  ```
  Scenario: All message types roundtrip correctly
    Tool: Bash
    Preconditions: message.rs with SshMessage enum and codec
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- message::tests::roundtrip`
      2. Verify tests cover all 12 message variants: GlobalRequest(80), RequestSuccess(81), RequestFailure(82), ChannelOpenConfirmation(91), ChannelOpenFailure(92), ChannelData(94), ChannelExtendedData(95), ChannelEof(96), ChannelClose(97), ChannelRequest(98), ChannelSuccess(99), ChannelFailure(100)
    Expected Result: All 12 variants encode then decode back to identical values
    Failure Indicators: Any variant fails roundtrip, or unknown message type error
    Evidence: .sisyphus/evidence/task-5-message-roundtrip.txt

  Scenario: Message type constants are correct varint values
    Tool: Bash
    Preconditions: message type constants defined
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- message::tests::message_type_hex_dump`
      2. Verify ChannelData(94) encodes with type varint 0x5e (94 in varint)
      3. Verify ChannelRequest(98) encodes with type varint 0x62 (98 in varint)
      4. Verify NO message type 90 or 93 exists in the enum
    Expected Result: Message type constants match RFC values, encoded as QUIC varints
    Failure Indicators: Wrong type value, or types 90/93 present
    Evidence: .sisyphus/evidence/task-5-message-types.txt

  Scenario: ChannelRequest preserves raw request_data
    Tool: Bash
    Preconditions: ChannelRequest codec implemented
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- message::tests::channel_request_raw_data`
      2. Verify request_type="exec", want_reply=true, request_data=arbitrary bytes
      3. Verify request_data is NOT parsed, just stored as raw bytes
    Expected Result: request_data roundtrips as opaque bytes
    Failure Indicators: request_data modified or parsed during encode/decode
    Evidence: .sisyphus/evidence/task-5-channel-request.txt

  Scenario: GlobalRequest/RequestSuccess/RequestFailure roundtrip
    Tool: Bash
    Preconditions: SshMessage enum includes 3 global message variants
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- message::tests::global_request_roundtrip`
      2. Verify GlobalRequest encodes with type varint 0x50 (80), includes request_type + want_reply + data
      3. Verify RequestSuccess encodes with type varint 0x51 (81), includes optional data
      4. Verify RequestFailure encodes with type varint 0x52 (82), no payload
      5. Verify all 3 variants roundtrip correctly
    Expected Result: All 3 global message types encode/decode correctly with RFC-compliant type values
    Failure Indicators: Wrong type varint, missing fields, or roundtrip failure
    Evidence: .sisyphus/evidence/task-5-global-request.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-proto): define complete SshMessage enum with SSH binary codec`
  - Files: `genmeta-ssh3-proto/src/message.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto -- message`

- [x] 6. Ssh3Protocol (h3x Protocol Trait 实现)

  **What to do**:
  - 在 `genmeta-ssh3-server/src/protocol.rs` 中实现 `Ssh3Protocol` struct:
    - 实现 `h3x::protocol::Protocol` trait 的 `accept_bi` 方法
    - accept_bi 逻辑（严格参照 h3x DHttpProtocol.accept_bi 模式）：
      1. 使用 `reader.decode_one::<VarInt>().await` 尝试读取第一个 VarInt（signal_value）
      2. 如果值等于 `0xaf3627e6` → `Pin::new(&mut reader).reset()` 回退读取位置，然后 `StreamVerdict::Accepted`，解码完整 channel header（`reader.decode_one::<ChannelHeader>().await`），派发到相应 conversation
      3. 如果值不匹配或解码失败 → `Pin::new(&mut reader).reset()` 回退，返回 `StreamVerdict::Passed((reader, writer))`，让下一个 Protocol 处理
    - 保存 conversation 注册表：`HashMap<u64, mpsc::Sender<(ChannelHeader, BoxPeekableBiStream)>>`（conversation_id → 发送端）
    - 提供 `register_conversation(id: u64) -> mpsc::Receiver<(ChannelHeader, BoxPeekableBiStream)>` — 创建 mpsc channel，保存 Sender 到注册表，返回 Receiver 给 LocalConversation（Task 4 的 accept_channel 从此 Receiver 接收）
    - 提供 `unregister_conversation(id: u64)` — 从注册表移除 Sender（drop 后 Receiver 端自动收到关闭通知）
    - accept_bi 中派发逻辑：解码 channel header 后，通过 `conversation_registry[conversation_id].send((header, stream)).await` 将 stream 派发到对应的 LocalConversation
    - **关键**: Ssh3Protocol.accept_bi 是所有入站 bidi stream 的**唯一入口**，LocalConversation.accept_channel 不直接操作 QuicConnection，而是从 mpsc::Receiver 端接收被派发的 stream
  - 为 Protocol trait 的 `Any + Send + Sync + Debug` bound 添加必要的 derive/impl
  - 单元测试：mock stream 与 signal_value 开头 → Accepted + 通过 mpsc 派发到正确 conversation；非 signal_value 开头 → Passed(stream)

  **Must NOT do**:
  - 不在 Ssh3Protocol 中处理 HTTP/3 帧 — 那是 DHttpProtocol 的职责
  - 不在子进程中注册 Protocol — Protocol 仅在主进程
  - 不实现消息处理逻辑 — 只做 stream 路由到 conversation
  - 不发明不存在的 h3x API

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 需要理解 h3x Protocol trait 的精确契约并正确实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Wave 2 其他任务并行，但实际依赖 T2+T3+T4+T5）
  - **Parallel Group**: Wave 2 (但应在 T4 和 T5 完成后开始)
  - **Blocks**: Tasks 9, 10, 22
  - **Blocked By**: Tasks 2, 3, 4, 5

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs:138-154` — Protocol trait 定义（accept_bi 签名、StreamVerdict 返回类型）
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs:156-163` — StreamVerdict enum（Accepted / Passed(S)）
  - `/home/yiyue/code/reimu/h3x/src/dhttp/protocol.rs:280-324` — DHttpProtocol.accept_bi 参考实现（peek + frame type 检查流程）

  **API/Type References**:
  - `/home/yiyue/code/reimu/h3x/src/codec.rs:26-29` — BoxPeekableBiStream 类型（accept_bi 参数类型）
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader 的 `Decode<ChannelHeader>` trait impl（通过 `reader.decode_one::<ChannelHeader>().await?` 调用）
  - `genmeta-ssh3-proto/src/conversation.rs` (Task 4) — LocalConversation（Ssh3Protocol 创建 mpsc channel，将 Receiver 传给 LocalConversation 的 accept_channel）

  **WHY Each Reference Matters**:
  - h3x Protocol trait: 必须精确匹配 accept_bi 签名，返回 StreamVerdict
  - DHttpProtocol: 唯一现有的 Protocol 实现参考，理解 peek 模式
  - BoxPeekableBiStream: 精确的参数类型不可猜测
  - LocalConversation: Ssh3Protocol.accept_bi 通过 mpsc::Sender 派发 stream → LocalConversation.accept_channel 从 mpsc::Receiver 接收

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/protocol.rs`、`genmeta-ssh3-server/src/lib.rs`（添加 mod protocol）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- protocol` 通过
  - [ ] Ssh3Protocol 实现 h3x Protocol trait
  - [ ] signal_value 流 → StreamVerdict::Accepted
  - [ ] 非 signal_value 流 → StreamVerdict::Passed(stream)
  - [ ] conversation 注册返回 mpsc::Receiver，注销 drop Sender
  - [ ] accept_bi 通过 mpsc::Sender 将 (ChannelHeader, BoxPeekableBiStream) 派发到正确 conversation
  - [ ] 未注册 conversation_id 的 stream 被拒绝（不 panic）

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Ssh3Protocol routes SSH3 streams correctly
    Tool: Bash
    Preconditions: Ssh3Protocol implemented with Protocol trait
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- protocol::tests::accept_bi_ssh3_stream`
      2. Verify: mock stream starting with signal_value bytes → Accepted
      3. Verify: mock stream starting with HTTP/3 frame type → Passed(stream)
    Expected Result: SSH3 streams accepted, non-SSH3 streams passed through
    Failure Indicators: SSH3 stream passed through, or non-SSH3 stream accepted incorrectly
    Evidence: .sisyphus/evidence/task-6-protocol-routing.txt

  Scenario: Conversation registration and mpsc dispatch
    Tool: Bash
    Preconditions: Ssh3Protocol with conversation registry using mpsc channels
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- protocol::tests::conversation_dispatch`
      2. Register conversation id=42 → get mpsc::Receiver back
      3. Send mock SSH3 stream with conversation_id=42 through accept_bi
      4. Verify Receiver receives (ChannelHeader, BoxPeekableBiStream) with correct header
      5. Send mock SSH3 stream with conversation_id=999 (unregistered)
      6. Verify stream is rejected with error (not dispatched, not panicked)
      7. Unregister conversation id=42 → Receiver gets closed notification
    Expected Result: Streams dispatched via mpsc to correct conversation; unregistered IDs rejected gracefully
    Failure Indicators: Stream dispatched to wrong conversation, panic on unregistered id, or Receiver not closed on unregister
    Evidence: .sisyphus/evidence/task-6-conversation-dispatch.txt

  **Commit**: YES
  - Message: `feat(ssh3-server): implement Ssh3Protocol for h3x Protocol trait`
  - Files: `genmeta-ssh3-server/src/protocol.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- protocol`

- [x] 7. h3x API 验证 Spike + remoc RTC Spike

  **What to do**:
  - **h3x spike** — 验证以下 API 可用性：
    - `ConnectionBuilder::protocol()` 可以注册自定义 Protocol 实现
    - `QuicConnection` 可以打开新双向流（open_bi 或等效 API）
    - stream peek 可以读取前 N 字节而不消费（用于 signal_value 检测）
    - 记录任何 API 差异到 `.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`（若目录不存在则创建）
  - **remoc RTC spike** — 验证以下能力：
    - `#[rtc::remote]` trait 可以生成 Client/Server
    - `provide()` / `consume()` 可以在 QUIC 连接上工作
    - QUIC stream 可以通过 RTC 传递到子进程（或发现限制并记录 workaround）
  - 输出：将发现写入 `.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`，包括：
    - “可用/不可用”判定 + 具体 API 调用示例
    - 任何需要的 workaround 或替代方案
    - 对后续 Tasks 的影响评估

  **Must NOT do**:
  - 不发明不存在的 h3x API — spike 的目的就是验证真实可用性
  - 不写生产代码 — 只写测试/示例代码
  - 不修改 h3x crate 源代码

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 探索性验证工作，不需要复杂实现
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 4, 5, 6 并行）
  - **Parallel Group**: Wave 2
  - **Blocks**: Tasks 9, 13
  - **Blocked By**: Task 2

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/server/route.rs:59-63,65-87` — Router patterns（protocol 注册方式）
  - `/home/yiyue/code/reimu/h3x/src/protocol.rs:138-154` — Protocol trait API
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/connection.rs` — RemoteQuicConnection / LocalQuicConnection

  **External References**:
  - remoc crate docs — RTC（Remote Trait Call）宏用法和 Client/Server 生成
  - remoc examples — provide()/consume() 使用模式

  **WHY Each Reference Matters**:
  - route.rs: 确认 protocol 注册的正确 API，避免发明不存在的接口
  - remoc connection: 确认 QUIC stream 能否通过 RTC 传递到子进程

  **File Boundary**: 只可修改 `genmeta-ssh3-proto/tests/spike_*.rs`、`.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`（若不存在则创建）

  **Acceptance Criteria**:
  - [ ] h3x API spike 结果记录在 `.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`
  - [ ] remoc RTC spike 结果记录在 `.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`
  - [ ] 每个 API 有明确的 “可用/不可用/需 workaround” 判定
  - [ ] 后续任务影响评估已写入

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: h3x Protocol registration compiles and works
    Tool: Bash
    Preconditions: Spike test file created
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto --test spike_h3x -- --nocapture`
      2. Verify output shows: Protocol can be registered, stream peek works, open_bi available
    Expected Result: h3x API confirmed usable for SSH3 Protocol implementation
    Failure Indicators: Compilation errors, API not found, or unexpected behavior
    Evidence: .sisyphus/evidence/task-7-h3x-spike.txt

  Scenario: remoc RTC works across process boundary
    Tool: Bash
    Preconditions: Spike test with remoc RTC trait
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto --test spike_remoc -- --nocapture`
      2. Verify output shows: RTC trait compiles, Client/Server generated, provide/consume works
      3. Check if QUIC stream passing is possible or needs workaround
    Expected Result: remoc RTC confirmed for cross-process trait calls, limitations documented
    Failure Indicators: RTC macro fails, provide/consume errors, stream passing impossible
    Evidence: .sisyphus/evidence/task-7-remoc-spike.txt
  ```

  **Commit**: YES (group with learnings update)
  - Message: `chore(ssh3): h3x API and remoc RTC verification spike`
  - Files: `genmeta-ssh3-proto/tests/spike_*.rs`, `.sisyphus/notepads/ssh3-rfc-implementation-v2/learnings.md`
  - Pre-commit: `cargo test -p genmeta-ssh3-proto --test spike_h3x && cargo test -p genmeta-ssh3-proto --test spike_remoc`

### Wave 3: Server HTTP Layer

- [x] 8. 版本协商 + 认证解析

  **What to do**:
  - 在 `genmeta-ssh3-server/src/version.rs` 中实现：
    - SSH3 版本协商逻辑（RFC Section 6）
    - `negotiate_version(request_headers: &HeaderMap) -> Result<SshVersion>` — 解析 `ssh-version` HTTP header
    - `SshVersion` struct: `{ major: u32, minor: u32 }` 或字符串形式
    - 版本不匹配时返回 ProtocolError
  - 在 `genmeta-ssh3-server/src/auth.rs` 中实现：
    - `extract_auth_credential(request: &Request) -> Result<AuthCredential>` — 从 HTTP 请求中提取认证信息
    - 支持 Basic scheme: 解析 Authorization header → 调用 proto 层的 `parse_authorization_header()`
    - 不支持的 scheme: 返回 401 + WWW-Authenticate: Basic header
  - 单元测试：版本协商成功/失败、Basic auth 提取、不支持 scheme 拒绝

  **Must NOT do**:
  - 不实现 Bearer/JWT/PublicKey auth — 只有 Basic
  - 不做 PAM 调用 — 那是 Task 12
  - 不做 PAM service name 自动降级 fallback
  - 不设置 tracing event 的 target

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: HTTP header 解析 + 版本协商逻辑，中等复杂度
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 9, 10 并行）
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 9
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/auth.rs` (Task 3) — parse_authorization_header 函数，server 层调用 proto 层解析

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 6 — 版本协商 ssh-version header 格式
  - RFC draft-michel-ssh3-00 Section 4 — 认证流程（Basic scheme）
  - http crate 的 HeaderMap/HeaderValue 类型 — 请求 header 解析 API

  **WHY Each Reference Matters**:
  - proto auth.rs: 复用 proto 层解析而非重复实现
  - RFC Section 6: ssh-version header 格式是权威定义，不可猜测

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/version.rs`、`genmeta-ssh3-server/src/auth.rs`、`genmeta-ssh3-server/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- version` 通过
  - [ ] `cargo test -p genmeta-ssh3-server -- auth` 通过
  - [ ] ssh-version header 解析正确
  - [ ] Basic auth 提取正确
  - [ ] 不支持 scheme 返回 401 + WWW-Authenticate

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Version negotiation accepts valid ssh-version header
    Tool: Bash
    Preconditions: version.rs implemented
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- version::tests`
      2. Verify valid ssh-version header → SshVersion parsed correctly
      3. Verify missing ssh-version header → ProtocolError
      4. Verify incompatible version → ProtocolError
    Expected Result: Valid versions accepted, invalid/missing rejected with proper error
    Failure Indicators: Version parsed wrong, or missing version accepted
    Evidence: .sisyphus/evidence/task-8-version-negotiation.txt

  Scenario: Auth extraction returns 401 for unsupported schemes
    Tool: Bash
    Preconditions: auth.rs with extract_auth_credential
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- auth::tests::unsupported_scheme`
      2. Verify Bearer token → 401 + WWW-Authenticate: Basic
      3. Verify missing Authorization header → 401
    Expected Result: Non-Basic schemes rejected with 401 and correct WWW-Authenticate header
    Failure Indicators: Bearer accepted, or WWW-Authenticate header missing/wrong
    Evidence: .sisyphus/evidence/task-8-auth-401.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement version negotiation and auth parsing`
  - Files: `genmeta-ssh3-server/src/version.rs`, `genmeta-ssh3-server/src/auth.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server`

- [x] 9. Extended CONNECT Handler

  **What to do**:
  - 在 `genmeta-ssh3-server/src/handler.rs` 中实现 SSH3 Extended CONNECT handler：
    - 实现 h3x `Service` trait 或直接写 handler 函数（根据 Task 7 spike 结果确定）
    - handler 流程：
      1. 接收 Extended CONNECT 请求（`:protocol = ssh3`）
      2. 调用 version.rs 的 negotiate_version() 验证版本
      3. 调用 auth.rs 的 extract_auth_credential() 提取认证信息
      4. 创建 LocalConversation（conversation_id = CONNECT stream ID）
      5. 注册 conversation 到 Ssh3Protocol
      6. 通过 ChildProcess 派发到子进程（Task 14）或直接处理（MVP 可先 inline）
      7. 返回 200 OK + ssh-version response header
    - 错误处理：
      - 版本不匹配 → 400
      - 认证失败 → 401 + WWW-Authenticate
      - 内部错误 → 500
  - 集成测试：mock CONNECT 请求 → 验证 200 响应 + conversation 创建

  **Must NOT do**:
  - 不在子进程中注册 Protocol 或路由 stream
  - 不实现通道处理逻辑 — handler 只负责 conversation 创建和认证
  - 不使用 h3x::message::unify — 使用 http crate 类型
  - 不处理普通 HTTP 请求 — 只处理 Extended CONNECT (:protocol=ssh3)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 核心入口点，整合多个子系统（version + auth + conversation + protocol），需要仔细设计
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖多个 Wave 2 任务）
  - **Parallel Group**: Wave 3 (sequential, after T3+T4+T6+T7+T8)
  - **Blocks**: Tasks 10, 25
  - **Blocked By**: Tasks 3, 4, 6, 7, 8

  **References**:

  **Pattern References**:
  - `/home/yiyue/code/reimu/h3x/src/server/service.rs:7-11` — Service trait 定义（Request/Response 类型）
  - `/home/yiyue/code/reimu/h3x/src/server/message.rs:60-64,151-155` — Request/Response 结构体
  - `/home/yiyue/code/reimu/h3x/src/dhttp/protocol.rs:280-324` — DHttpProtocol 如何处理传入流

  **API/Type References**:
  - `genmeta-ssh3-server/src/version.rs` (Task 8) — negotiate_version()
  - `genmeta-ssh3-server/src/auth.rs` (Task 8) — extract_auth_credential()
  - `genmeta-ssh3-proto/src/conversation.rs` (Task 4) — LocalConversation
  - `genmeta-ssh3-server/src/protocol.rs` (Task 6) — Ssh3Protocol.register_conversation()

  **External References**:
  - RFC draft-michel-ssh3-00 Section 2 — Extended CONNECT 请求处理流程
  - RFC 8441 — Bootstrapping WebSockets with HTTP/2 Extended CONNECT（SSH3 复用此机制）

  **WHY Each Reference Matters**:
  - Service trait: handler 必须匹配 h3x 的 Request/Response 抽象
  - DHttpProtocol: 理解 h3x 如何派发传入 CONNECT 请求
  - RFC Section 2: Extended CONNECT 的 :protocol 字段和响应格式是权威定义

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/handler.rs`、`genmeta-ssh3-server/src/lib.rs`（添加 mod handler）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- handler` 通过
  - [ ] Extended CONNECT (:protocol=ssh3) → 200 OK + ssh-version header
  - [ ] LocalConversation 创建并注册到 Ssh3Protocol
  - [ ] 版本不匹配 → 400
  - [ ] 认证失败 → 401 + WWW-Authenticate

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Extended CONNECT handler accepts valid SSH3 connection
    Tool: Bash
    Preconditions: handler.rs with all dependencies wired
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- handler::tests::valid_ssh3_connect`
      2. Verify: CONNECT request with :protocol=ssh3 + valid ssh-version + valid Basic auth → 200 OK
      3. Verify: response includes ssh-version header
      4. Verify: LocalConversation created with correct conversation_id
    Expected Result: 200 OK response with ssh-version, conversation registered
    Failure Indicators: Non-200 status, missing ssh-version header, no conversation created
    Evidence: .sisyphus/evidence/task-9-valid-connect.txt

  Scenario: Extended CONNECT handler rejects bad auth
    Tool: Bash
    Preconditions: handler.rs with auth integration
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- handler::tests::bad_auth_connect`
      2. Verify: missing Authorization → 401
      3. Verify: Bearer token → 401 + WWW-Authenticate: Basic
      4. Verify: wrong password → 401 (after PAM integration in later task, for now mock)
    Expected Result: All bad auth scenarios return 401 with WWW-Authenticate header
    Failure Indicators: 200 returned for bad auth, or missing WWW-Authenticate
    Evidence: .sisyphus/evidence/task-9-bad-auth.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement Extended CONNECT handler`
  - Files: `genmeta-ssh3-server/src/handler.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server`

- [x] 10. E2E 冒烟测试骨架

  **What to do**:
  - 创建 `genmeta-ssh3-server/tests/e2e.rs`（server crate 集成测试，添加 genmeta-ssh3-client 为 dev-dependency）：
    - 建立测试基础设施：
      - `start_test_server()` — 启动 test QUIC server（h3x + Ssh3Protocol + DHttpProtocol）
      - `create_test_client()` — 创建 QUIC 客户端连接
      - 自签名 TLS 证书生成（用于测试）
    - 写一个最小冒烟测试：
      - 客户端发起 Extended CONNECT → 服务器响应 200
      - 验证 ssh-version header 存在
    - 这是一个“验证集成点”，后续 tasks 会扩展此测试

  **Must NOT do**:
  - 不测试通道逻辑 — 只测 CONNECT 握手
  - 不使用真实 PAM — 使用 mock auth（硬编码 test user）
  - 不启动子进程 — 还不需要（先单进程测试）

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: 测试基础设施搭建，模式明确
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T6 + T9）
  - **Parallel Group**: Wave 3 (after T6+T9)
  - **Blocks**: Task 25
  - **Blocked By**: Tasks 6, 9

  **References**:

  **Pattern References**:
  - 搜索 h3x crate 中的现有测试（`tests/` 目录）— 了解如何启动 h3x test server
  - `/home/yiyue/code/reimu/h3x/src/server/` — server 启动 API（ConnectionBuilder, bind, serve）

  **API/Type References**:
  - `genmeta-ssh3-server/src/protocol.rs` (Task 6) — Ssh3Protocol
  - `genmeta-ssh3-server/src/handler.rs` (Task 9) — CONNECT handler

  **WHY Each Reference Matters**:
  - h3x tests: 复用 h3x 的 test server 启动模式，避免重新发明
  - protocol.rs + handler.rs: E2E 测试需要将两者组装在一起

  **File Boundary**: 只可修改 `genmeta-ssh3-server/tests/e2e.rs`、`genmeta-ssh3-server/tests/common/mod.rs`、`genmeta-ssh3-server/Cargo.toml`（添加 dev-dependency）

  **Acceptance Criteria**:
  - [ ] E2E 冒烟测试可运行并通过
  - [ ] test server 启动 + 客户端连接成功
  - [ ] CONNECT 握手返回 200 + ssh-version

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: E2E smoke test passes
    Tool: Bash
    Preconditions: All Wave 1-3 tasks complete
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server --test e2e -- smoke_connect`
      2. Verify: test server starts on random port
      3. Verify: client connects and sends Extended CONNECT
      4. Verify: server responds with 200 OK + ssh-version
    Expected Result: E2E CONNECT handshake succeeds end-to-end
    Failure Indicators: Connection refused, timeout, or non-200 response
    Evidence: .sisyphus/evidence/task-10-e2e-smoke.txt
  ```

  **Commit**: YES
  - Message: `test(ssh3): add E2E smoke test scaffold for CONNECT handshake`
  - Files: `genmeta-ssh3-server/tests/e2e.rs`, `genmeta-ssh3-server/tests/common/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server --test e2e`

### Wave 4: Multi-Process Architecture

- [x] 11. SshSession RTC Trait + SessionInit/AuthResult 类型

  **What to do**:
  - 在 `genmeta-ssh3-proto/src/session.rs` 中定义：
    - `SshSession` trait（使用 remoc `#[rtc::remote]` 宏）：
      ```rust
      #[rtc::remote]
      pub(crate) trait SshSession: Send + Sync {
          /// 开始 SSH 会话处理（子进程主循环）—— 子进程 setuid/setgid 后执行
          async fn run_session(&self, init: SessionInit) -> Result<(), SessionError>;
      }
      ```
    - `SessionInit` struct：`{ conversation_id: u64, username: String, uid: u32, gid: u32, home: PathBuf, shell: PathBuf }` —— PAM 认证成功后主进程构建，传递给子进程
    - `AuthResult` enum：`Success { uid: u32, gid: u32, home: PathBuf, shell: PathBuf }` | `Failure { reason: String }` —— PAM wrapper 的返回类型，主进程使用
    - remoc RTC 会自动生成 `SshSessionClient` 和 `SshSessionServer`
  - 单元测试：SshSession trait 可编译、RTC Client/Server 可构造

  **Must NOT do**:
  - 不在 SshSession trait 中传递 ChannelId —— 无 channel number
  - 不在 trait 中使用 initial_window 参数
  - 不实现 trait 方法体 —— 只定义 trait + 类型（实现在 Task 13）
  - 不预留 pubkey auth 变体
  - 不在 SshSession trait 中定义 authenticate() —— PAM 在主进程直接调用，不经 RTC

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: RTC 宏展开行为需要理解，trait 设计影响后续多个 tasks
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 12, 13, 14 并行）
  - **Parallel Group**: Wave 4
  - **Blocks**: Tasks 13, 14
  - **Blocked By**: Task 4

  **References**:

  **Pattern References**:
  - Task 7 spike 结果 — remoc RTC 宏的实际行为和限制
  - `/home/yiyue/code/reimu/h3x/src/remoc/quic/connection.rs` — remoc QUIC 连接抽象

  **API/Type References**:
  - `genmeta-ssh3-proto/src/error.rs` (Task 3) — SessionError 类型（run_session 返回值）

  **External References**:
  - remoc crate docs — `#[rtc::remote]` 宏展开、Client/Server 生成规则

  **WHY Each Reference Matters**:
  - Task 7 spike: 确认 RTC 宏可用性和生成代码结构
  - SessionError: run_session() 返回值依赖该类型

  **File Boundary**: 只可修改 `genmeta-ssh3-proto/src/session.rs`、`genmeta-ssh3-proto/src/lib.rs`（添加 mod session）

  **Acceptance Criteria**:
  - [ ] `cargo check -p genmeta-ssh3-proto` 通过（RTC 宏展开成功）
  - [ ] `cargo test -p genmeta-ssh3-proto -- session` 通过
  - [ ] SshSessionClient 和 SshSessionServer 类型存在
  - [ ] trait 无 ChannelId / initial_window 参数

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: RTC macro generates Client/Server types
    Tool: Bash
    Preconditions: session.rs with #[rtc::remote] trait
    Steps:
      1. Run `cargo test -p genmeta-ssh3-proto -- session::tests::rtc_types_exist`
      2. Verify: SshSessionClient can be constructed
      3. Verify: SshSessionServer can be constructed from a trait implementation
    Expected Result: RTC macro correctly generates Client/Server types
    Failure Indicators: Type not found errors, macro expansion failure
    Evidence: .sisyphus/evidence/task-11-rtc-types.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-proto): define SshSession RTC trait with SessionInit/AuthResult`
  - Files: `genmeta-ssh3-proto/src/session.rs`, `genmeta-ssh3-proto/src/lib.rs`
  - Pre-commit: `cargo check -p genmeta-ssh3-proto`

- [x] 12. PAM Wrapper

  **What to do**:
  - 在 `genmeta-ssh3-server/src/auth/pam.rs` 中实现 PAM 4 阶段认证：
    - `PamAuth` struct 封装 PAM 调用：
      1. `pam_start()` — 初始化 PAM handle（service name 参数化，默认 "ssh3"）
      2. `pam_authenticate()` — 验证用户名/密码
      3. `pam_acct_mgmt()` — 账户管理检查（账户是否过期等）
      4. `pam_end()` — 清理 PAM handle
    - `async fn pam_authenticate(username: &str, password: &str) -> Result<AuthResult, AuthError>`
    - Timing attack 防护：认证失败时添加随机延迟（100-500ms）
    - 从 PAM 查询用户信息：uid, gid, home, shell（构建 AuthResult::Success）
  - 单元测试：mock PAM（用 trait 抽象或 cfg(test) mock），测试 4 阶段流程

  **Must NOT do**:
  - 不做 PAM service name 自动降级 fallback — 使用固定 service name
  - 不在子进程中调用 PAM — PAM 在主进程（root 权限）中执行
  - 不实现 pubkey auth

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: PAM C 库集成需要处理 unsafe 和错误处理，但模式明确
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 11, 13, 14 并行）
  - **Parallel Group**: Wave 4
  - **Blocks**: Task 13
  - **Blocked By**: Task 3

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/auth.rs` (Task 3) — AuthCredential::Basic 类型
  - `genmeta-ssh3-proto/src/session.rs` (Task 11) — AuthResult 类型（返回值）

  **External References**:
  - pam crate docs (pam-rs 或 pam-sys) — PAM C API 的 Rust 绑定
  - OpenSSH source (auth-pam.c) — PAM 4 阶段调用顺序参考

  **WHY Each Reference Matters**:
  - AuthResult: PAM 成功后必须构建正确的 AuthResult::Success
  - OpenSSH auth-pam.c: PAM 4 阶段顺序的权威参考

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/auth/pam.rs`、`genmeta-ssh3-server/src/auth/mod.rs`、`genmeta-ssh3-server/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- auth::pam` 通过
  - [ ] PAM 4 阶段调用顺序正确（start → authenticate → acct_mgmt → end）
  - [ ] timing attack 防护存在（失败时有随机延迟）
  - [ ] 成功认证返回 uid/gid/home/shell

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: PAM 4-stage authentication flow
    Tool: Bash
    Preconditions: pam.rs with mock PAM backend
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- auth::pam::tests::four_stage_flow`
      2. Verify: pam_start called with service="ssh3"
      3. Verify: pam_authenticate called with username+password
      4. Verify: pam_acct_mgmt called after authenticate success
      5. Verify: pam_end called in all cases (success and failure)
    Expected Result: All 4 PAM stages called in correct order
    Failure Indicators: Stage skipped, or pam_end not called on error path
    Evidence: .sisyphus/evidence/task-12-pam-flow.txt

  Scenario: PAM failure returns AuthError with timing protection
    Tool: Bash
    Preconditions: mock PAM configured to reject
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- auth::pam::tests::auth_failure_timing`
      2. Verify: failure returns AuthError, not panic
      3. Verify: failure path includes artificial delay (measure elapsed time > 100ms)
    Expected Result: Auth failure is graceful with timing protection
    Failure Indicators: Panic on failure, or response faster than 100ms
    Evidence: .sisyphus/evidence/task-12-pam-timing.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement PAM wrapper with 4-stage authentication`
  - Files: `genmeta-ssh3-server/src/auth/pam.rs`, `genmeta-ssh3-server/src/auth/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- auth::pam`

- [x] 13. ssh3-session 子进程二进制

  **What to do**:
  - 在 `genmeta-ssh3-server/src/bin/ssh3-session.rs` 中实现子进程入口：
    - `fn main()` → tokio runtime → `async fn run()`
    - 通过环境变量或命令行参数接收 remoc channel fd
    - 创建 `SshSessionServer`（从 Task 11 的 RTC trait）
    - 实现 `SshSession` trait：
      - `run_session(init: SessionInit)`: 从 SessionInit 获取 uid/gid/home/shell → setuid/setgid 切换到用户身份 → 占位符实现（实际通道处理在 Wave 5）
    - 提供 remoc RTC SshSessionServer → 主进程通过 SshSessionClient 调用 run_session()
  - 集成测试：spawn 子进程 → RTC 连接 → 调用 run_session()

  **Must NOT do**:
  - 不在子进程中注册 Protocol 或路由 stream
  - 不实现完整 run_session 逻輎 — 只做 setuid/setgid + 占位符
  - 不使用 ChannelId
  - 不在子进程中调用 PAM — PAM 在主进程执行，子进程通过 SessionInit 接收认证结果

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 跨进程 RTC 集成和子进程生命周期管理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T7+T11+T12）
  - **Parallel Group**: Wave 4 (after T7+T11+T12)
  - **Blocks**: Tasks 14, 25
  - **Blocked By**: Tasks 7, 11, 12

  **References**:

  **Pattern References**:
  - Task 7 spike 结果 — remoc RTC provide()/consume() 的实际 API 和 workaround
  - `genmeta-ssh3-proto/src/session.rs` (Task 11) — SshSession trait + SshSessionServer 类型

  **API/Type References**:
  - `genmeta-ssh3-server/src/auth/pam.rs` (Task 12) — pam_authenticate() 函数
  - `genmeta-ssh3-proto/src/session.rs` (Task 11) — SshSession trait の run_session() + SessionInit 类型（uid/gid/home/shell 包含）

  **External References**:
  - remoc crate docs — provide()/consume() 用于跨进程 RTC 建连
  - Unix setuid/setgid API — nix crate docs

  **WHY Each Reference Matters**:
  - Task 7 spike: RTC 的真实可用 API，避免发明不存在的接口
  - SessionInit 类型: run_session() 接收 uid/gid/home/shell，子进程据此 setuid/setgid

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/bin/ssh3-session.rs`、可能添加 `genmeta-ssh3-server/src/session_impl.rs`

  **Acceptance Criteria**:
  - [x] `cargo build -p genmeta-ssh3-server --bin ssh3-session` 成功
  - [x] 子进程启动后通过 RTC 提供 SshSession 服务
  - [x] 主进程可通过 SshSessionClient 调用 run_session()
  - [x] 不在子进程中注册 Protocol

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Child process starts and provides RTC service
    Tool: Bash
    Preconditions: ssh3-session binary builds
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::tests::spawn_child_rtc`
      2. Verify: child process spawns successfully
      3. Verify: RTC SshSessionClient created in parent process
      4. Verify: run_session() call reaches child process
    Expected Result: Cross-process RTC communication works
    Failure Indicators: Spawn fails, RTC connection fails, method call timeout
    Evidence: .sisyphus/evidence/task-13-child-rtc.txt

  Scenario: Child process receives SessionInit and does setuid/setgid
    Tool: Bash
    Preconditions: Child process with mock nix setuid
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::tests::child_setuid`
      2. Call run_session(SessionInit{conversation_id:1, username:"test", uid:1000, gid:1000, home:"/home/test", shell:"/bin/bash"}) via RTC
      3. Verify: setuid(1000) and setgid(1000) called in correct order (gid first, then uid)
    Expected Result: Privilege drop executed with correct uid/gid from SessionInit
    Failure Indicators: setuid/setgid not called, wrong order, wrong values
    Evidence: .sisyphus/evidence/task-13-child-setuid.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement ssh3-session child process with RTC`
  - Files: `genmeta-ssh3-server/src/bin/ssh3-session.rs`
  - Pre-commit: `cargo build -p genmeta-ssh3-server --bin ssh3-session`

- [x] 14. ChildProcess 主进程管理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/child.rs` 中实现：
    - `ChildProcess` struct — 管理子进程生命周期
      - `spawn(ssh3_session_path: &Path) -> Result<(ChildProcess, SshSessionClient)>`
        - 创建 socketpair 或 pipe 用于 remoc 传输
        - `Command::new(ssh3_session_path).spawn()` 启动子进程
        - 通过 remoc consume() 获取 SshSessionClient
      - `wait(&mut self) -> Result<ExitStatus>` — 等待子进程退出
      - `kill(&mut self)` — 强制终止子进程
      - Drop impl — 确保子进程清理
    - 与 CONNECT handler (Task 9) 集成：handler 调用 PamAuth::authenticate() → 成功后调用 ChildProcess::spawn() → 获取 SshSessionClient → 调用 run_session(SessionInit{包含 uid/gid/home/shell})
  - 单元测试：spawn + RTC 连接 + 子进程清理

  **Must NOT do**:
  - 不在子进程中注册 Protocol
  - 不传递 ChannelId 给子进程
  - 不实现通道处理 — 只做进程管理 + RTC 建连

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 进程管理 + IPC 集成，中等复杂度但需要仔细的资源清理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T11+T13）
  - **Parallel Group**: Wave 4 (after T13)
  - **Blocks**: Task 25
  - **Blocked By**: Tasks 11, 13

  **References**:

  **Pattern References**:
  - Task 7 spike 结果 — remoc provide()/consume() 的 fd 传递方式
  - `genmeta-ssh3-server/src/bin/ssh3-session.rs` (Task 13) — 子进程端 provide() 逻辑

  **API/Type References**:
  - `genmeta-ssh3-proto/src/session.rs` (Task 11) — SshSessionClient 类型
  - `genmeta-ssh3-server/src/handler.rs` (Task 9) — handler 需要调用 ChildProcess::spawn()

  **WHY Each Reference Matters**:
  - Task 13 bin: 子进程端的 provide() 和主进程端的 consume() 必须匹配
  - handler.rs: 了解 handler 如何调用 ChildProcess 才能设计正确 API

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/child.rs`、`genmeta-ssh3-server/src/lib.rs`（添加 mod child）、可能更新 `handler.rs`（集成 spawn）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- child` 通过
  - [ ] ChildProcess::spawn() 返回 SshSessionClient
  - [ ] 子进程异常退出时 Drop 清理正常
  - [ ] 不传递 ChannelId

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: ChildProcess spawn and cleanup
    Tool: Bash
    Preconditions: ssh3-session binary available
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- child::tests::spawn_and_cleanup`
      2. Verify: spawn() succeeds and returns SshSessionClient
      3. Verify: after drop(child_process), child process is terminated
      4. Verify: no zombie processes remain
    Expected Result: Child process lifecycle managed correctly
    Failure Indicators: Spawn fails, zombie process, or RTC connection error
    Evidence: .sisyphus/evidence/task-14-child-lifecycle.txt

  Scenario: ChildProcess integrates with CONNECT handler
    Tool: Bash
    Preconditions: handler.rs updated to use ChildProcess
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- handler::tests::handler_spawns_child`
      2. Verify: CONNECT request → PamAuth::authenticate() → ChildProcess::spawn() → run_session(SessionInit) → 200 OK
    Expected Result: Full CONNECT → child spawn → auth flow works
    Failure Indicators: Handler fails to spawn child, or auth not called
    Evidence: .sisyphus/evidence/task-14-handler-integration.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement ChildProcess manager with RTC integration`
  - Files: `genmeta-ssh3-server/src/child.rs`, `genmeta-ssh3-server/src/handler.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server`

### Wave 5: Session + Forwarding

- [x] 15. Channel Open/Confirm/Data 处理（Session 通道）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/channel.rs` 中实现通道生命周期处理：
    - 服务端 accept 新 QUIC 双向流（已由 Ssh3Protocol 派发，channel header 已解码）
    - 根据 channel_type 分发：
      - `"session"` → 发送 ChannelOpenConfirmation(91) → 进入消息循环
      - `"direct-tcpip"` / `"forwarded-tcpip"` → 转发到转发处理（Task 18/19）
      - `"direct-streamlocal@openssh.com"` → Unix socket 转发（Task 20）
      - 未知类型 → 发送 ChannelOpenFailure(92)
    - 消息循环（session 通道）：
      - 读取流 → `let msg: SshMessage = stream.decode_one().await?` → 匹配 SshMessage 类型 → 处理
      - ChannelData(94) → 写入 stdin / 从 stdout 读取并发送 ChannelData
      - ChannelExtendedData(95) → stderr 处理
      - ChannelRequest(98) → 解析 request_type 并派发（Task 16 处理）
      - ChannelEof(96) → 关闭 stdin
      - ChannelClose(97) → 关闭通道
    - Session 通道数据使用 SSH_MSG_CHANNEL_DATA(94) 包装
  - TDD 测试：模拟客户端发送消息序列 → 验证服务器响应正确

  **Must NOT do**:
  - 不使用 ChannelOpen(90) 消息 — 打开流 = 打开通道，通过 channel header 识别
  - 不使用 ChannelId — 通道 = QUIC 流
  - 不实现 ChannelWindowAdjust — QUIC 原生流控
  - 不在 TCP 转发通道上使用 ChannelData 包装 — TCP 转发用原始字节流
  - 不解析 ChannelRequest 的具体 request_type 内容 — 只做派发（解析在 Task 16）

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 通道生命周期和消息循环是核心逻辑，错误会影响所有下游任务
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T4+T5）
  - **Parallel Group**: Wave 5 (first task)
  - **Blocks**: Tasks 16, 18, 19, 20
  - **Blocked By**: Tasks 4, 5

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/conversation.rs` (Task 4) — accept_channel() 返回 ChannelHeader + stream
  - `genmeta-ssh3-proto/src/message.rs` (Task 5) — SshMessage 的 `Encode<SshMessage>`/`Decode<SshMessage>` trait impl（通过 `stream.encode_one(&msg).await?` / `stream.decode_one::<SshMessage>().await?` 调用）

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3 — 通道生命周期
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader 的 Encode/Decode trait impl（通过 stream trait 方法调用）

  **External References**:
  - Go 参考实现 `channel.go` (francoismichel/ssh3) — channel 消息循环和派发逻辑

  **WHY Each Reference Matters**:
  - conversation.rs: accept_channel 返回的 ChannelHeader 确定了 channel_type 和 stream handles
  - Go channel.go: 消息循环和通道类型派发的权威参考

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/channel.rs`、`genmeta-ssh3-server/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- channel` 通过
  - [ ] session 通道：ChannelOpenConfirmation(91) 正确发送
  - [ ] session 通道：ChannelData(94) 编解码正确
  - [ ] 未知 channel_type → ChannelOpenFailure(92)
  - [ ] 无 ChannelOpen(90) 消息
  - [ ] 无 ChannelId 使用

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Session channel lifecycle
    Tool: Bash
    Preconditions: channel.rs with session channel handling
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- channel::tests::session_channel_lifecycle`
      2. Verify: client opens stream with channel_type="session" → server sends ChannelOpenConfirmation(91)
      3. Verify: client sends ChannelData(94) → server receives data correctly
      4. Verify: client sends ChannelEof(96) → server closes stdin
      5. Verify: client sends ChannelClose(97) → channel closed cleanly
    Expected Result: Full session channel lifecycle works
    Failure Indicators: Wrong message sent, or lifecycle doesn't complete
    Evidence: .sisyphus/evidence/task-15-session-lifecycle.txt

  Scenario: Unknown channel type rejected
    Tool: Bash
    Preconditions: channel.rs with type dispatch
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- channel::tests::unknown_channel_type`
      2. Verify: channel_type="x11" → ChannelOpenFailure(92) sent
    Expected Result: Unknown channel types properly rejected with failure message
    Failure Indicators: Unknown type accepted, or server panics
    Evidence: .sisyphus/evidence/task-15-unknown-type.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement channel lifecycle with session channel handling`
  - Files: `genmeta-ssh3-server/src/channel.rs`, `genmeta-ssh3-server/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- channel`

- [x] 16. Exec/Shell/Subsystem 请求处理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/session/request.rs` 中解析 ChannelRequest 的 request_data：
    - `"exec"` request：
      - 解码 request_data → command(ssh_string)
      - 启动子进程执行命令（Command::new(shell) -c command）
      - 将 stdin/stdout/stderr 连接到通道 ChannelData/ChannelExtendedData
      - 等待进程结束 → 发送 exit-status request → ChannelEof → ChannelClose
    - `"shell"` request：
      - 启动登录 shell（从 AuthResult 的 shell 路径）
      - 类似 exec 但无命令参数
    - `"subsystem"` request：
      - 解码 request_data → subsystem_name(ssh_string)
      - MVP 可以只支持 "sftp"（或返回 ChannelFailure）
    - 对于 want_reply=true 的请求，发送 ChannelSuccess(99) 或 ChannelFailure(100)
    - `"exit-status"` request：解码 request_data → exit_status(uint32) → server → client 方向
    - `"exit-signal"` request：解码 request_data → signal_name + core_dumped + error_msg + language
  - 单元测试：mock 通道 → exec "echo hello" → 收到 ChannelData("hello\n") + exit-status(0) + EOF + Close

  **Must NOT do**:
  - 不使用 ChannelRequest type=95 — 正确值为 98
  - 不直接在主进程执行命令 — 通过子进程（已 setuid 到用户身份）
  - 不使用 ChannelId 来关联 request 和 channel

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 涉及子进程 stdin/stdout/stderr 管道连接、异步流处理、退出状态管理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 Tasks 18-21 并行，但依赖 T5+T15）
  - **Parallel Group**: Wave 5 (after T15)
  - **Blocks**: Tasks 17, 25
  - **Blocked By**: Tasks 5, 15

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/message.rs` (Task 5) — SshMessage::ChannelRequest, ChannelSuccess, ChannelFailure
  - `genmeta-ssh3-server/src/channel.rs` (Task 15) — ChannelRequest 派发逻辑

  **API/Type References**:
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — SshString 的 `Decode<SshString>` trait impl（通过 `stream.decode_one::<SshString>().await?` 解析 request_data 中的字符串字段）
  - RFC draft-michel-ssh3-00 Section 3.7 — ChannelRequest 格式
  - RFC 4254 Section 6.5 — exec/shell/subsystem request 字段定义（SSH3 复用 SSHv2 的 request type）

  **External References**:
  - Go 参考实现 `message/channel_request.go` — exec/shell/pty request 解析

  **WHY Each Reference Matters**:
  - RFC 4254 Section 6.5: exec/shell/subsystem 的 request_data 字段定义权威来源
  - Go channel_request.go: request_data 解析的实际字节顺序参考

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/session/request.rs`、`genmeta-ssh3-server/src/session/mod.rs`、`genmeta-ssh3-server/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- session::request` 通过
  - [ ] exec "echo hello" → ChannelData("hello\n") + exit-status(0) + EOF + Close
  - [ ] shell → 启动登录 shell
  - [ ] want_reply=true → ChannelSuccess(99) 或 ChannelFailure(100)
  - [ ] ChannelRequest 使用 type=98

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Exec request runs command and returns output
    Tool: Bash
    Preconditions: request.rs with exec handling
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::request::tests::exec_echo`
      2. Verify: exec request with command="echo hello" received
      3. Verify: ChannelSuccess(99) sent (if want_reply=true)
      4. Verify: ChannelData with "hello\n" sent back
      5. Verify: exit-status ChannelRequest with exit_status=0 sent
      6. Verify: ChannelEof(96) + ChannelClose(97) sent
    Expected Result: Full exec lifecycle: request → success → data → exit-status → eof → close
    Failure Indicators: Missing exit-status, wrong output, or channel not closed
    Evidence: .sisyphus/evidence/task-16-exec-echo.txt

  Scenario: Failed exec returns ChannelFailure
    Tool: Bash
    Preconditions: request.rs with exec handling
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::request::tests::exec_failure`
      2. Verify: exec request with nonexistent command → ChannelFailure(100)
    Expected Result: Bad command rejected with ChannelFailure
    Failure Indicators: ChannelSuccess sent for invalid command, or panic
    Evidence: .sisyphus/evidence/task-16-exec-failure.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement exec/shell/subsystem request handling`
  - Files: `genmeta-ssh3-server/src/session/request.rs`, `genmeta-ssh3-server/src/session/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- session`

- [ ] 17. PTY 分配 + 终端处理

  **What to do**:
  - 在 `genmeta-ssh3-server/src/session/pty.rs` 中实现：
    - `"pty-req"` ChannelRequest 处理：
      - 解码 request_data → term_type(ssh_string) + width_cols(uint32) + height_rows(uint32) + width_px(uint32) + height_px(uint32) + terminal_modes(ssh_bytes)
      - 使用 nix crate 分配 PTY（openpty）
      - 设置终端大小（ioctl TIOCSWINSZ）
      - 将 PTY master 连接到通道 I/O
    - `"window-change"` ChannelRequest 处理：
      - 解码 request_data → width_cols + height_rows + width_px + height_px
      - 更新 PTY 终端大小（TIOCSWINSZ）
    - `"signal"` ChannelRequest 处理：
      - 解码 signal_name → 发送信号给子进程
  - 单元测试：mock PTY 分配、window-change 处理

  **Must NOT do**:
  - 不实现 x11 forwarding
  - 不使用 ChannelId

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: PTY 分配涉及 Unix 系统调用但模式成熟
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T16）
  - **Parallel Group**: Wave 5 (after T16)
  - **Blocks**: Task 25
  - **Blocked By**: Task 16

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/session/request.rs` (Task 16) — ChannelRequest 派发逻辑

  **API/Type References**:
  - RFC 4254 Section 6.2 — pty-req request 字段定义
  - RFC 4254 Section 6.7 — window-change request 字段定义
  - nix crate docs — openpty(), ioctl TIOCSWINSZ

  **WHY Each Reference Matters**:
  - RFC 4254: pty-req 和 window-change 的 request_data 字段顺序是权威定义
  - nix crate: Rust 中分配 PTY 和设置终端大小的标准方法

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/session/pty.rs`、`genmeta-ssh3-server/src/session/mod.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- session::pty` 通过
  - [ ] pty-req 正确分配 PTY 并设置终端大小
  - [ ] window-change 正确更新终端大小
  - [ ] signal request 正确发送信号

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: PTY allocation with pty-req
    Tool: Bash
    Preconditions: pty.rs with PTY handling
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::pty::tests::pty_allocation`
      2. Verify: pty-req request → PTY allocated with correct terminal size
      3. Verify: ChannelSuccess(99) sent back (if want_reply=true)
    Expected Result: PTY allocated, terminal size set, success acknowledged
    Failure Indicators: openpty fails, wrong terminal size, or ChannelFailure sent
    Evidence: .sisyphus/evidence/task-17-pty-alloc.txt

  Scenario: Window change resizes terminal
    Tool: Bash
    Preconditions: PTY already allocated
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- session::pty::tests::window_change`
      2. Verify: window-change request → terminal size updated via TIOCSWINSZ
    Expected Result: Terminal size updated without errors
    Failure Indicators: TIOCSWINSZ ioctl fails, or new size not applied
    Evidence: .sisyphus/evidence/task-17-window-change.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement PTY allocation and terminal handling`
  - Files: `genmeta-ssh3-server/src/session/pty.rs`, `genmeta-ssh3-server/src/session/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- session::pty`


- [ ] 18. Direct-TCP 转发（原始字节流）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/direct_tcp.rs` 中实现：
    - Direct-TCP 通道打开处理：
      - 客户端打开新 QUIC bidi stream
      - 写入 channel header: signal_value(0xaf3627e6) + conversation_id + channel_type_length + "direct-tcpip" + max_message_size
      - 服务端读取 channel header，验证 channel_type=="direct-tcpip"
      - 解码 request_data: dest_host(ssh_string) + dest_port(uint32) + originator_host(ssh_string) + originator_port(uint32)
      - 建立到 dest_host:dest_port 的 TCP 连接
      - 发送 SSH_MSG_CHANNEL_OPEN_CONFIRMATION(91) 确认
    - 双向数据转发：
      - **关键**: TCP 转发通道使用原始字节流，**不**使用 SSH_MSG_CHANNEL_DATA(94) 包装
      - QUIC stream → TCP socket 直接 copy_bidirectional
      - TCP socket 关闭 → 发送 ChannelEof(96) + ChannelClose(97)
      - QUIC stream 收到 ChannelClose → 关闭 TCP socket
    - 错误处理：
      - TCP 连接失败 → SSH_MSG_CHANNEL_OPEN_FAILURE(92) with reason code
      - 传输中断 → 清理两端资源
  - 在 `genmeta-ssh3-server/src/forward/mod.rs` 中注册 direct-tcp handler
  - 单元测试：
    - channel header 编解码 round-trip（hex dump 验证）
    - 模拟 TCP 连接成功 → 数据双向传输 → 关闭
    - TCP 连接失败 → ChannelOpenFailure(92) 返回
    - 验证**不使用** SSH_MSG_CHANNEL_DATA 包装

  **Must NOT do**:
  - 不使用 ChannelId — 通道通过 QUIC 流标识
  - 不用 SSH_MSG_CHANNEL_DATA(94) 包装 TCP 数据 — 原始字节流直接传输
  - 不实现 ChannelWindowAdjust — QUIC 原生流控
  - 不实现 UDP forwarding

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 涉及 QUIC stream + TCP socket 双向桥接，需要异步 I/O 处理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 T19, T20 同波次）
  - **Parallel Group**: Wave 5 (with Tasks 19, 20, 21)
  - **Blocks**: Task 25
  - **Blocked By**: Task 15 (channel lifecycle)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader/ChannelOpenConfirmation/ChannelOpenFailure 的 Encode/Decode trait impl（通过 `stream.encode_one(header).await?` / `stream.decode_one::<ChannelHeader>().await?` 调用）
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — SshString/VarInt 的 Encode/Decode trait impl（通过 stream trait 方法编解码 direct-tcpip 的 request_data 字段）

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3.5 — TCP port forwarding
  - RFC 4254 Section 7.2 — direct-tcpip channel 的 request_data 字段: dest_host, dest_port, originator_host, originator_port
  - Go 参考实现 `channel.go` — TCP forwarding 使用 raw byte streams 的实现方式

  **External References**:
  - tokio docs — `tokio::io::copy_bidirectional` 用于双向数据桥接

  **WHY Each Reference Matters**:
  - RFC 4254 Section 7.2: direct-tcpip channel 的 request_data 字段顺序是权威定义
  - Go channel.go: 确认 TCP forwarding 使用原始字节流而非 ChannelData 包装的关键证据
  - tokio copy_bidirectional: 异步双向数据传输的标准 Rust 方案

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/forward/direct_tcp.rs`、`genmeta-ssh3-server/src/forward/mod.rs`、`genmeta-ssh3-server/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::direct_tcp` 通过
  - [ ] channel header 包含 channel_type="direct-tcpip"
  - [ ] 数据使用原始字节流传输，**无** SSH_MSG_CHANNEL_DATA(94) 包装
  - [ ] TCP 连接失败 → ChannelOpenFailure(92) 返回
  - [ ] hex dump 测试验证 channel header 字节序列
  - [ ] `grep -r 'ChannelData' genmeta-ssh3-server/src/forward/direct_tcp.rs` → 无匹配

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Direct-TCP channel opens and forwards data bidirectionally
    Tool: Bash
    Preconditions: direct_tcp.rs with forwarding logic; local TCP echo server on 127.0.0.1:9999
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::direct_tcp::tests::direct_tcp_roundtrip`
      2. Verify: channel header with channel_type="direct-tcpip" sent
      3. Verify: dest_host="127.0.0.1", dest_port=9999 decoded correctly
      4. Verify: ChannelOpenConfirmation(91) sent back
      5. Verify: raw bytes "hello" sent through QUIC stream → received by TCP server
      6. Verify: TCP server response "echo: hello" → received on QUIC stream as raw bytes
      7. Verify: NO SSH_MSG_CHANNEL_DATA(94) wrapper anywhere in data path
    Expected Result: Bidirectional raw byte transfer between QUIC stream and TCP socket
    Failure Indicators: Data wrapped in ChannelData, connection refused, or data corruption
    Evidence: .sisyphus/evidence/task-18-direct-tcp-roundtrip.txt

  Scenario: TCP connection failure returns ChannelOpenFailure
    Tool: Bash
    Preconditions: direct_tcp.rs; no server listening on target port
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::direct_tcp::tests::tcp_connect_failure`
      2. Verify: dest_host="127.0.0.1", dest_port=1 (no listener)
      3. Verify: SSH_MSG_CHANNEL_OPEN_FAILURE(92) sent back with reason code
    Expected Result: ChannelOpenFailure with appropriate reason
    Failure Indicators: Hang, panic, or ChannelOpenConfirmation sent
    Evidence: .sisyphus/evidence/task-18-tcp-connect-failure.txt
  ```

  **Commit**: YES (groups with T19, T20)
  - Message: `feat(ssh3): implement TCP forwarding with raw byte streams`
  - Files: `genmeta-ssh3-server/src/forward/direct_tcp.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward`


- [ ] 19. Reverse-TCP 转发（global request + 服务端主动开通道）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/reverse_tcp.rs` 中实现：
    - Global Request 处理（在 conversation stream 上）：
      - 客户端发送 tcpip-forward global request: bind_address(ssh_string) + bind_port(uint32)
      - 服务端监听指定地址端口
      - bind_port=0 时，服务端分配端口并在 reply 中返回 allocated_port(uint32)
      - cancel-tcpip-forward global request: 停止监听
    - 服务端主动开通道（收到 TCP 连接时）：
      - 服务端打开新 QUIC bidi stream
      - 写入 channel header: channel_type="forwarded-tcpip"
      - request_data: connected_address(ssh_string) + connected_port(uint32) + originator_address(ssh_string) + originator_port(uint32)
      - 等待客户端 SSH_MSG_CHANNEL_OPEN_CONFIRMATION(91)
      - 数据使用原始字节流（同 direct-tcp）
    - 错误处理：
      - TCP listener bind 失败 → global request failure reply
      - 客户端拒绝 channel → 关闭 TCP 连接
  - 单元测试：
    - tcpip-forward global request 解码 + reply 编码
    - 服务端主动开通道的 channel header 编码（hex dump）
    - cancel-tcpip-forward 停止监听
    - bind_port=0 时分配端口并返回

  **Must NOT do**:
  - 不使用 ChannelId — 通道通过 QUIC 流标识
  - 不用 SSH_MSG_CHANNEL_DATA(94) 包装 TCP 数据 — 原始字节流
  - 不实现 UDP forwarding

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 涉及 global request + 服务端主动开通道的双向逻辑，复杂度较高
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 T18, T20, T21 同波次）
  - **Parallel Group**: Wave 5 (with Tasks 18, 20, 21)
  - **Blocks**: Task 25
  - **Blocked By**: Task 15 (channel lifecycle)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader/ChannelOpenConfirmation 的 Encode/Decode trait impl（通过 `stream.encode_one(header).await?` / `stream.decode_one::<ChannelOpenConfirmation>().await?` 调用）
  - `genmeta-ssh3-server/src/forward/direct_tcp.rs` (Task 18) — 原始字节流数据传输模式

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 3.5 — TCP port forwarding (reverse 方向)
  - RFC 4254 Section 7.1 — tcpip-forward global request 字段定义
  - RFC 4254 Section 7.2 — forwarded-tcpip channel request_data 字段定义
  - Go 参考实现 `channel.go` — reverse forwarding 的服务端主动开通道实现

  **WHY Each Reference Matters**:
  - RFC 4254 Section 7.1: tcpip-forward global request 的 bind_address + bind_port 字段顺序是权威定义
  - RFC 4254 Section 7.2: forwarded-tcpip 的 request_data 字段顺序与 direct-tcpip 不同，必须按规范实现
  - Go channel.go: 服务端如何主动打开新流并发送 channel header 的实际流程

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/forward/reverse_tcp.rs`、`genmeta-ssh3-server/src/forward/mod.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::reverse_tcp` 通过
  - [ ] tcpip-forward global request 正确解码 bind_address + bind_port
  - [ ] bind_port=0 → reply 包含 allocated_port
  - [ ] 服务端打开新流时 channel_type="forwarded-tcpip"
  - [ ] 数据使用原始字节流传输
  - [ ] cancel-tcpip-forward 停止监听

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Reverse-TCP forward with server-initiated channel
    Tool: Bash
    Preconditions: reverse_tcp.rs with forwarding logic
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::reverse_tcp::tests::reverse_tcp_forward`
      2. Verify: tcpip-forward global request with bind_address="0.0.0.0", bind_port=8080 received
      3. Verify: server starts listening on 0.0.0.0:8080
      4. Verify: incoming TCP connection triggers server to open new QUIC bidi stream
      5. Verify: channel header with channel_type="forwarded-tcpip" written
      6. Verify: client sends ChannelOpenConfirmation(91)
      7. Verify: data forwarded bidirectionally as raw bytes (no ChannelData wrapping)
    Expected Result: Full reverse forwarding lifecycle: global request → listen → accept → channel open → data relay
    Failure Indicators: Channel type wrong, data wrapped in ChannelData, or listen failure not reported
    Evidence: .sisyphus/evidence/task-19-reverse-tcp-forward.txt

  Scenario: Bind port 0 allocates dynamic port
    Tool: Bash
    Preconditions: reverse_tcp.rs
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::reverse_tcp::tests::dynamic_port_allocation`
      2. Verify: tcpip-forward with bind_port=0 → server allocates ephemeral port
      3. Verify: reply contains allocated_port > 0
    Expected Result: Server allocates and returns a valid ephemeral port
    Failure Indicators: allocated_port=0 or port not actually listening
    Evidence: .sisyphus/evidence/task-19-dynamic-port.txt
  ```

  **Commit**: YES (groups with T18, T20)
  - Message: `feat(ssh3-server): implement reverse-TCP forwarding with global request`
  - Files: `genmeta-ssh3-server/src/forward/reverse_tcp.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward`

- [ ] 20. Streamlocal (Unix Socket) 转发

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/streamlocal.rs` 中实现：
    - Direct streamlocal 通道：
      - channel_type="direct-streamlocal@openssh.com"
      - request_data: socket_path(ssh_string) + reserved(ssh_string) + reserved(uint32)
      - 建立 Unix socket 连接到 socket_path
      - 数据使用原始字节流（同 TCP forwarding）
    - Reverse streamlocal 通道：
      - streamlocal-forward@openssh.com global request: socket_path(ssh_string)
      - cancel-streamlocal-forward@openssh.com global request: socket_path(ssh_string)
      - 服务端监听 Unix socket，收到连接时打开 channel_type="forwarded-streamlocal@openssh.com"
    - 错误处理：
      - Socket 不存在 → ChannelOpenFailure(92)
      - Socket 权限拒绝 → ChannelOpenFailure(92) with reason
  - 单元测试：
    - channel header 编解码与 direct-streamlocal channel_type 验证
    - Unix socket 连接 + 双向数据传输
    - socket 不存在时的错误处理

  **Must NOT do**:
  - 不使用 ChannelId
  - 不用 SSH_MSG_CHANNEL_DATA(94) 包装数据
  - 不实现 x11 forwarding

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: 与 direct-tcp 结构类似，但涉及 Unix socket 特有逻辑
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 T18, T19, T21 同波次）
  - **Parallel Group**: Wave 5 (with Tasks 18, 19, 21)
  - **Blocks**: Task 25
  - **Blocked By**: Task 15 (channel lifecycle)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/forward/direct_tcp.rs` (Task 18) — 直接复用原始字节流数据传输模式
  - `genmeta-ssh3-server/src/forward/reverse_tcp.rs` (Task 19) — reverse forwarding 的 global request + 服务端开通道模式

  **API/Type References**:
  - OpenSSH streamlocal extension spec — channel_type 和 request_data 字段定义
  - Go 参考实现 `channel.go` — streamlocal 处理方式

  **WHY Each Reference Matters**:
  - OpenSSH spec: direct-streamlocal@openssh.com 的正确 channel_type 和 request_data 字段定义
  - Task 18 (direct_tcp.rs): Unix socket 传输与 TCP 传输共享相同的原始字节流模式，可抽取公共逻辑

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/forward/streamlocal.rs`、`genmeta-ssh3-server/src/forward/mod.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::streamlocal` 通过
  - [ ] direct-streamlocal@openssh.com channel 正确连接 Unix socket
  - [ ] 数据使用原始字节流传输
  - [ ] streamlocal-forward@openssh.com global request 启动监听
  - [ ] cancel-streamlocal-forward@openssh.com 停止监听
  - [ ] socket 不存在 → ChannelOpenFailure(92)

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Direct streamlocal connects to Unix socket
    Tool: Bash
    Preconditions: streamlocal.rs; test Unix socket at /tmp/test-ssh3.sock (echo server)
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::streamlocal::tests::direct_streamlocal`
      2. Verify: channel_type="direct-streamlocal@openssh.com"
      3. Verify: socket_path decoded correctly from request_data
      4. Verify: Unix socket connection established
      5. Verify: raw byte data forwarded bidirectionally
    Expected Result: Data relayed between QUIC stream and Unix socket without ChannelData wrapping
    Failure Indicators: Socket connection fails, data wrapped in ChannelData, or wrong channel_type
    Evidence: .sisyphus/evidence/task-20-direct-streamlocal.txt

  Scenario: Missing socket returns ChannelOpenFailure
    Tool: Bash
    Preconditions: streamlocal.rs; no socket at /tmp/nonexistent.sock
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::streamlocal::tests::missing_socket`
      2. Verify: ChannelOpenFailure(92) sent with reason code
    Expected Result: Graceful failure with ChannelOpenFailure
    Failure Indicators: Panic, hang, or ChannelOpenConfirmation sent
    Evidence: .sisyphus/evidence/task-20-missing-socket.txt
  ```

  **Commit**: YES (groups with T18, T19)
  - Message: `feat(ssh3-server): implement streamlocal (Unix socket) forwarding`
  - Files: `genmeta-ssh3-server/src/forward/streamlocal.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward`

- [ ] 21. SOCKS5 代理（服务端）

  **What to do**:
  - 在 `genmeta-ssh3-server/src/forward/socks5.rs` 中实现：
    - SOCKS5 协议处理（RFC 1928）：
      - 客户端打开 QUIC bidi stream，channel_type="socks5"
      - 服务端解析 SOCKS5 协商: VERSION(0x05) + NMETHODS + METHODS
      - 服务端回复: VERSION(0x05) + METHOD(0x00 = no auth)
      - 解析 CONNECT 请求: VERSION + CMD(0x01) + RSV + ATYP + DST.ADDR + DST.PORT
      - 支持 ATYP: 0x01 (IPv4), 0x03 (domain name), 0x04 (IPv6)
      - 建立 TCP 连接到目标地址
      - 回复 SOCKS5 success: VERSION(0x05) + REP(0x00) + RSV + ATYP + BND.ADDR + BND.PORT
      - 之后转为原始字节流双向传输
    - 错误处理：
      - SOCKS5 协商失败 → 关闭流
      - TCP 连接失败 → SOCKS5 reply with REP=0x05 (connection refused)
      - 不支持的 CMD → REP=0x07 (command not supported)
  - 单元测试：
    - SOCKS5 协商字节序列 round-trip
    - IPv4/IPv6/domain name CONNECT 解析
    - TCP 连接成功后双向数据传输
    - TCP 连接失败的错误回复

  **Must NOT do**:
  - 不实现 SOCKS5 认证（仅 no-auth）
  - 不实现 BIND 或 UDP ASSOCIATE 命令
  - 不使用 ChannelId

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: SOCKS5 协议解析 + TCP 转发，涉及多层字节级解析，复杂度较高
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES（与 T18, T19, T20 同波次）
  - **Parallel Group**: Wave 5 (with Tasks 18, 19, 20)
  - **Blocks**: Task 24
  - **Blocked By**: Task 15 (channel lifecycle), Task 18 (TCP forwarding pattern reference)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/forward/direct_tcp.rs` (Task 18) — TCP 连接 + 原始字节流数据传输模式

  **API/Type References**:
  - RFC 1928 — SOCKS5 协议完整字节格式定义
  - RFC draft-michel-ssh3-00 Section 3.5 — SSH3 对 SOCKS5 的集成方式
  - Go 参考实现 — SOCKS5 channel 处理逻辑

  **External References**:
  - RFC 1928 full text — SOCKS5 字节级协议解析参考

  **WHY Each Reference Matters**:
  - RFC 1928: SOCKS5 协商/CONNECT/reply 的精确字节格式是权威定义，必须严格遵循
  - Task 18 (direct_tcp.rs): SOCKS5 CONNECT 成功后的数据传输与 direct-tcp 使用相同的原始字节流模式

  **File Boundary**: 只可修改 `genmeta-ssh3-server/src/forward/socks5.rs`、`genmeta-ssh3-server/src/forward/mod.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server -- forward::socks5` 通过
  - [ ] SOCKS5 VERSION/METHOD 协商正确
  - [ ] CONNECT 支持 IPv4(0x01), domain(0x03), IPv6(0x04)
  - [ ] 成功连接后数据双向传输（原始字节流）
  - [ ] TCP 连接失败 → SOCKS5 REP=0x05
  - [ ] 不支持的 CMD → REP=0x07

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: SOCKS5 CONNECT to remote host via IPv4
    Tool: Bash
    Preconditions: socks5.rs with SOCKS5 handling; TCP echo server on 127.0.0.1:9999
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::socks5::tests::socks5_connect_ipv4`
      2. Verify: SOCKS5 negotiation: client sends 05 01 00, server replies 05 00
      3. Verify: CONNECT request: 05 01 00 01 7f000001 2710 (127.0.0.1:10000 equivalent)
      4. Verify: TCP connection established
      5. Verify: SOCKS5 success reply: 05 00 00 01 ... with bound address/port
      6. Verify: raw bytes forwarded bidirectionally after SOCKS5 handshake
    Expected Result: Full SOCKS5 lifecycle: negotiate → connect → relay
    Failure Indicators: Wrong SOCKS5 reply bytes, connection not relayed, or data corruption
    Evidence: .sisyphus/evidence/task-21-socks5-connect-ipv4.txt

  Scenario: SOCKS5 CONNECT fails with connection refused
    Tool: Bash
    Preconditions: socks5.rs; no server on target port
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::socks5::tests::socks5_connect_refused`
      2. Verify: SOCKS5 negotiation succeeds
      3. Verify: CONNECT to unreachable host → SOCKS5 reply with REP=0x05
    Expected Result: SOCKS5 connection refused error properly reported
    Failure Indicators: Panic, hang, or success reply sent
    Evidence: .sisyphus/evidence/task-21-socks5-connect-refused.txt

  Scenario: Unsupported SOCKS5 command rejected
    Tool: Bash
    Preconditions: socks5.rs
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server -- forward::socks5::tests::socks5_unsupported_cmd`
      2. Verify: BIND command (CMD=0x02) → SOCKS5 reply with REP=0x07
    Expected Result: Command not supported error
    Failure Indicators: Attempt to process BIND command
    Evidence: .sisyphus/evidence/task-21-socks5-unsupported-cmd.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-server): implement SOCKS5 proxy`
  - Files: `genmeta-ssh3-server/src/forward/socks5.rs`, `genmeta-ssh3-server/src/forward/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server -- forward::socks5`

### Wave 6: Client + Integration

- [ ] 22. SSH3 客户端连接 + 认证

  **What to do**:
  - 在 `genmeta-ssh3-client/src/lib.rs` 中实现：
    - `Ssh3Client` 结构体：
      - QUIC 连接到服务端（复用 h3x QUIC 连接）
      - 发送 Extended CONNECT 请求（method=CONNECT, :protocol=ssh3, path=/.well-known/ssh3/v3, authority=host:port）
      - SSH 版本协商：发送客户端版本信息
      - Basic 认证：发送 Authorization: Basic base64(user:password) header
      - 处理服务端 200 OK 响应（认证成功）或 401/403 拒绝
      - 认证成功后，conversation stream 建立
    - `Conversation` 客户端接口：
      - open_channel(channel_type, max_message_size) → 打开新 QUIC bidi stream + 写 channel header
      - send_global_request(request_type, data) → 在 conversation stream 上发送
    - TLS 配置：设置 QUIC TLS 参数，支持自签名证书用于测试
  - 单元测试：
    - Extended CONNECT 请求构造验证
    - Basic auth header 编码验证
    - 版本协商字节序列验证

  **Must NOT do**:
  - 不实现 JWT/Bearer 或 OIDC 认证
  - 不实现 HTTP Signature pubkey auth
  - 不实现 Concealed Auth
  - 不发明不存在的 h3x API

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 客户端连接建立涉及 QUIC + Extended CONNECT + 认证，多层协议交互
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（Wave 6 基础）
  - **Parallel Group**: Wave 6 (sequential start)
  - **Blocks**: Tasks 23, 24, 25
  - **Blocked By**: Tasks 5, 6, 8, 9 (协议 + 服务端基础设施）

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-proto/src/message.rs` (Task 5) — SshMessage 的 Encode/Decode trait impl（通过 `stream.encode_one(&msg).await?` / `stream.decode_one::<SshMessage>().await?` 复用）
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader 的 Encode/Decode trait impl（通过 `stream.encode_one(header).await?` 复用）
  - `genmeta-ssh3-server/src/handler.rs` (Task 9) — Extended CONNECT 服务端处理，客户端必须匹配

  **API/Type References**:
  - RFC draft-michel-ssh3-00 Section 2 — Extended CONNECT 字段: :protocol=ssh3, path=/.well-known/ssh3/v3
  - RFC draft-michel-ssh3-00 Section 2.2 — Basic (password) 认证方式
  - h3x QUIC connection API — `RemoteQuicConnection` 客户端连接接口

  **External References**:
  - Go 参考实现 `client/` 目录 — 客户端连接建立流程

  **WHY Each Reference Matters**:
  - Task 9 (handler.rs): 客户端发送的 Extended CONNECT 必须与服务端期望的格式严格匹配
  - RFC Section 2.2: Basic auth 的 Authorization header 格式是权威定义
  - h3x RemoteQuicConnection: 客户端 QUIC 连接的实际 API 接口

  **File Boundary**: 只可修改 `genmeta-ssh3-client/src/lib.rs`、`genmeta-ssh3-client/Cargo.toml`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client` 通过
  - [ ] Extended CONNECT 请求包含 :protocol=ssh3, path=/.well-known/ssh3/v3
  - [ ] Basic auth header 正确编码 base64(user:password)
  - [ ] 认证成功后 conversation stream 可用
  - [ ] 认证失败(401) 返回错误，不 panic

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Client connects and authenticates with Basic auth
    Tool: Bash
    Preconditions: genmeta-ssh3-client crate; genmeta-ssh3-server running on localhost
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- tests::basic_auth_connect`
      2. Verify: Extended CONNECT sent with :protocol="ssh3", path="/.well-known/ssh3/v3"
      3. Verify: Authorization header contains "Basic " + base64 of "testuser:testpassword"
      4. Verify: Server responds with 200 OK
      5. Verify: conversation stream established and functional
    Expected Result: Successful client-server connection with Basic auth
    Failure Indicators: CONNECT rejected, wrong auth header format, or connection hangs
    Evidence: .sisyphus/evidence/task-22-basic-auth-connect.txt

  Scenario: Client handles authentication failure gracefully
    Tool: Bash
    Preconditions: genmeta-ssh3-client; server configured to reject credentials
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- tests::auth_failure`
      2. Verify: wrong credentials → server responds 401 Unauthorized
      3. Verify: client returns Err with descriptive message, no panic
    Expected Result: Graceful error with clear message about auth failure
    Failure Indicators: Panic, hang, or incorrect error type
    Evidence: .sisyphus/evidence/task-22-auth-failure.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-client): implement SSH3 client connection and Basic auth`
  - Files: `genmeta-ssh3-client/src/lib.rs`, `genmeta-ssh3-client/Cargo.toml`
  - Pre-commit: `cargo test -p genmeta-ssh3-client`

- [ ] 23. 客户端会话 + 转发请求

  **What to do**:
  - 在 `genmeta-ssh3-client/src/session.rs` 中实现：
    - 打开会话通道：
      - 打开 QUIC bidi stream + 写 channel header (channel_type="session")
      - 等待服务端 ChannelOpenConfirmation(91)
    - 发送 ChannelRequest：
      - exec(command) → ChannelRequest(98) with request_type="exec"
      - shell() → ChannelRequest(98) with request_type="shell"
      - pty_req(term, width, height) → ChannelRequest(98) with request_type="pty-req"
      - window_change(width, height) → ChannelRequest(98) with request_type="window-change"
    - 接收数据：
      - 读取 ChannelData(94) → stdout
      - 读取 ChannelExtendedData(95) type=1 → stderr
      - 读取 exit-status ChannelRequest → 提取退出码
      - 读取 ChannelEof(96) + ChannelClose(97) → 会话结束
  - 在 `genmeta-ssh3-client/src/forward.rs` 中实现：
    - direct_tcp_forward(dest_host, dest_port) → 打开 channel_type="direct-tcpip" 流
    - request_reverse_forward(bind_addr, bind_port) → tcpip-forward global request
    - handle_forwarded_channel() → 接受服务端主动打开的 forwarded-tcpip 通道
  - 单元测试：
    - exec request 编码验证（hex dump）
    - ChannelData/ExtendedData 解码验证
    - exit-status 提取验证

  **Must NOT do**:
  - 不使用 ChannelId
  - 不实现 agent-connection channel
  - 不使用 ChannelWindowAdjust

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: 客户端会话逻辑复杂，涉及多种通道类型和双向消息流
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T22）
  - **Parallel Group**: Wave 6 (after T22)
  - **Blocks**: Task 25
  - **Blocked By**: Task 22

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-client/src/lib.rs` (Task 22) — 客户端连接 + open_channel 接口
  - `genmeta-ssh3-proto/src/message.rs` (Task 5) — SshMessage 的 Encode/Decode trait impl（通过 stream trait 方法编解码）
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — ChannelHeader 的 Encode/Decode trait impl（通过 stream trait 方法编解码）
  - `genmeta-ssh3-server/src/session/request.rs` (Task 16) — 服务端对应的 request 处理，客户端必须匹配

  **API/Type References**:
  - RFC 4254 Section 6.5 — exec/shell/subsystem request_data 字段定义
  - RFC 4254 Section 6.2 — pty-req request_data 字段定义
  - RFC 4254 Section 7.2 — direct-tcpip channel request_data 字段定义

  **WHY Each Reference Matters**:
  - Task 16 (request.rs): 客户端发送的 request 必须与服务端解析一致，否则会话失败
  - RFC 4254: request_data 字段的精确顺序和类型是客户端服务端互操作的关键

  **File Boundary**: 只可修改 `genmeta-ssh3-client/src/session.rs`、`genmeta-ssh3-client/src/forward.rs`、`genmeta-ssh3-client/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client -- session` 通过
  - [ ] exec request 正确发送 ChannelRequest(98) with request_type="exec"
  - [ ] ChannelData(94) → stdout, ChannelExtendedData(95) type=1 → stderr
  - [ ] exit-status 正确提取
  - [ ] direct_tcp_forward 打开 channel_type="direct-tcpip" 流
  - [ ] request_reverse_forward 发送 tcpip-forward global request

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Client executes remote command and receives output
    Tool: Bash
    Preconditions: genmeta-ssh3-client with session.rs; mock server
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- session::tests::exec_remote_command`
      2. Verify: channel header with channel_type="session" sent
      3. Verify: ChannelRequest(98) with request_type="exec", command="echo hello" sent
      4. Verify: ChannelData(94) with "hello\n" received as stdout
      5. Verify: exit-status ChannelRequest received with exit_status=0
      6. Verify: ChannelEof(96) + ChannelClose(97) received
    Expected Result: Full exec lifecycle from client perspective
    Failure Indicators: Wrong message type, missing exit status, or channel not closed
    Evidence: .sisyphus/evidence/task-23-exec-remote.txt

  Scenario: Client receives stderr via ExtendedData
    Tool: Bash
    Preconditions: session.rs with ExtendedData handling
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- session::tests::stderr_via_extended_data`
      2. Verify: ChannelExtendedData(95) with data_type_code=1 decoded as stderr
      3. Verify: stderr data separated from stdout
    Expected Result: stderr correctly extracted from ExtendedData messages
    Failure Indicators: stderr mixed with stdout, or ExtendedData not handled
    Evidence: .sisyphus/evidence/task-23-stderr.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-client): implement session and forwarding requests`
  - Files: `genmeta-ssh3-client/src/session.rs`, `genmeta-ssh3-client/src/forward.rs`, `genmeta-ssh3-client/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-client`

- [ ] 24. 客户端 SOCKS5

  **What to do**:
  - 在 `genmeta-ssh3-client/src/socks5.rs` 中实现：
    - 本地 SOCKS5 服务器：
      - 监听本地端口（如 127.0.0.1:1080）
      - 接受本地 SOCKS5 客户端连接
      - 解析 SOCKS5 CONNECT 请求，提取目标地址
    - 通过 SSH3 服务端转发：
      - 打开 channel_type="direct-tcpip" 流到服务端（目标地址来自 SOCKS5 请求）
      - 等待 ChannelOpenConfirmation(91)
      - 回复 SOCKS5 success 给本地客户端
      - 双向桥接: 本地 TCP socket ↔ QUIC stream（原始字节流）
    - 或者直接使用 channel_type="socks5" 让服务端处理 SOCKS5（待确认）
  - 单元测试：
    - SOCKS5 协商解析
    - 目标地址提取后正确转发到 direct-tcpip channel

  **Must NOT do**:
  - 不实现 SOCKS5 认证（仅 no-auth）
  - 不实现 UDP ASSOCIATE
  - 不使用 ChannelId

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: SOCKS5 本地服务器 + SSH3 通道桥接，模式清晰但需细心处理
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖 T22）
  - **Parallel Group**: Wave 6 (after T22, parallel with T23)
  - **Blocks**: Task 25
  - **Blocked By**: Task 22, Task 21 (服务端 SOCKS5)

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-server/src/forward/socks5.rs` (Task 21) — SOCKS5 协议解析逻辑复用
  - `genmeta-ssh3-client/src/forward.rs` (Task 23) — direct_tcp_forward 接口复用

  **API/Type References**:
  - RFC 1928 — SOCKS5 协议格式

  **WHY Each Reference Matters**:
  - Task 21 (socks5.rs): 服务端 SOCKS5 解析逻辑可部分复用于客户端本地 SOCKS5 服务器
  - Task 23 (forward.rs): 客户端 direct_tcp_forward 接口用于将 SOCKS5 请求转发到服务端

  **File Boundary**: 只可修改 `genmeta-ssh3-client/src/socks5.rs`、`genmeta-ssh3-client/src/lib.rs`

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-client -- socks5` 通过
  - [ ] 本地 SOCKS5 服务器监听指定端口
  - [ ] SOCKS5 CONNECT 请求正确解析目标地址
  - [ ] 通过 direct-tcpip channel 转发到服务端
  - [ ] 双向数据传输正常

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Local SOCKS5 proxy forwards via SSH3 tunnel
    Tool: Bash
    Preconditions: socks5.rs; genmeta-ssh3-server + genmeta-ssh3-client running; TCP echo server at remote
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- socks5::tests::socks5_proxy_forward`
      2. Verify: local SOCKS5 server accepts connection on 127.0.0.1:1080
      3. Verify: SOCKS5 CONNECT request parsed correctly
      4. Verify: direct-tcpip channel opened to destination
      5. Verify: data relayed: local → SOCKS5 → SSH3 → remote
    Expected Result: End-to-end data flow through SOCKS5 + SSH3 tunnel
    Failure Indicators: SOCKS5 negotiation fails, channel not opened, or data lost
    Evidence: .sisyphus/evidence/task-24-socks5-proxy.txt

  Scenario: SOCKS5 proxy handles connection failure
    Tool: Bash
    Preconditions: socks5.rs; server running; no echo server at remote
    Steps:
      1. Run `cargo test -p genmeta-ssh3-client -- socks5::tests::socks5_proxy_connect_fail`
      2. Verify: direct-tcpip channel → ChannelOpenFailure(92) from server
      3. Verify: SOCKS5 connection refused reply (REP=0x05) sent to local client
    Expected Result: Failure propagated correctly from SSH3 to SOCKS5
    Failure Indicators: Local SOCKS5 client receives success, or hang
    Evidence: .sisyphus/evidence/task-24-socks5-connect-fail.txt
  ```

  **Commit**: YES
  - Message: `feat(ssh3-client): implement local SOCKS5 proxy`
  - Files: `genmeta-ssh3-client/src/socks5.rs`, `genmeta-ssh3-client/src/lib.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-client -- socks5`

- [ ] 25. 完整 E2E 集成测试

  **What to do**:
  - 在 `genmeta-ssh3-server/tests/e2e.rs` 中扩展完整端到端测试（复用 Task 10 的测试基础设施，添加 genmeta-ssh3-client 为 dev-dependency）：
    - 测试基础设施：
      - 启动 genmeta-ssh3-server 实例（使用自签名证书，随机端口）
      - 创建 genmeta-ssh3-client 实例连接到服务端
      - 测试结束后自动清理
    - E2E 测试用例：
      - `test_basic_exec`: 客户端连接 → Basic auth → 打开 session → exec "echo hello" → 收到 "hello\n" + exit_status=0
      - `test_exec_with_stderr`: exec command 产生 stderr → ChannelExtendedData(95) 正确分离
      - `test_shell_interactive`: 打开 shell → 发送命令 → 收到输出 → 发送 exit
      - `test_direct_tcp_forward`: direct-tcpip 通道 → 原始字节流转发 → 验证无 ChannelData 包装
      - `test_reverse_tcp_forward`: tcpip-forward global request → 服务端主动开通道 → 原始字节流
      - `test_auth_failure`: 错误密码 → 401 → 客户端错误处理
      - `test_multiple_channels`: 同时打开多个 session 通道，验证各通道独立工作
      - `test_wire_format_compliance`: 拦截实际网络数据，验证无 CBOR、所有整数为 QUIC varint、消息类型正确
  - 确保测试不依赖外部服务，完全自包含

  **Must NOT do**:
  - 不使用 CBOR — 验证线上格式为 SSH binary + QUIC varint
  - 不使用 ChannelId — 验证无 channel number 存在
  - 不依赖外部 SSH/PAM 服务 — 测试必须自包含

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: E2E 测试涉及客户端+服务端完整交互，需要深度理解整个协议栈
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO（依赖所有前置任务）
  - **Parallel Group**: Wave 6 (final, after all other tasks)
  - **Blocks**: Final Verification Wave
  - **Blocked By**: Tasks 17, 18, 19, 20, 21, 22, 23, 24 (全部实现任务）

  **References**:

  **Pattern References**:
  - `genmeta-ssh3-client/src/lib.rs` (Task 22) — 客户端连接接口
  - `genmeta-ssh3-client/src/session.rs` (Task 23) — 客户端会话接口
  - `genmeta-ssh3-server/src/handler.rs` (Task 9) — 服务端 Extended CONNECT 处理
  - `genmeta-ssh3-proto/src/codec.rs` (Task 2) — wire format 编解码用于拦截验证

  **API/Type References**:
  - 所有 SshMessage 类型常量（Task 5）— 验证线上格式

  **WHY Each Reference Matters**:
  - Task 22+23: E2E 测试使用客户端公开 API，必须了解接口设计
  - Task 2 (codec.rs): wire format 合规性测试需要直接检查字节序列

  **File Boundary**: 只可修改 `genmeta-ssh3-server/tests/e2e.rs`、`genmeta-ssh3-server/tests/common/mod.rs`（测试基础设施）

  **Acceptance Criteria**:
  - [ ] `cargo test -p genmeta-ssh3-server --test e2e` 全部通过
  - [ ] test_basic_exec: 收到 "hello\n" + exit_status=0
  - [ ] test_direct_tcp_forward: 原始字节流数据传输，无 ChannelData 包装
  - [ ] test_auth_failure: 401 正确处理
  - [ ] test_wire_format_compliance: 无 CBOR、所有整数 QUIC varint、无 ChannelId
  - [ ] test_multiple_channels: 多通道独立工作
  - [ ] `grep -r "cbor\|ciborium\|ChannelId\|ChannelOpen(\|ChannelWindowAdjust" --include="*.rs" .` → 无匹配

  **QA Scenarios (MANDATORY):**
  ```
  Scenario: Full E2E exec flow
    Tool: Bash
    Preconditions: All crates built; no external services needed
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server --test e2e -- test_basic_exec --nocapture`
      2. Verify: server starts on random port
      3. Verify: client connects with Basic auth
      4. Verify: exec "echo hello" returns "hello\n" via ChannelData(94)
      5. Verify: exit_status=0 via exit-status ChannelRequest
      6. Verify: channel closes cleanly (Eof+Close)
    Expected Result: Complete SSH3 exec lifecycle working end-to-end
    Failure Indicators: Any step fails, wrong output, or resource leak
    Evidence: .sisyphus/evidence/task-25-e2e-basic-exec.txt

  Scenario: Wire format compliance check
    Tool: Bash
    Preconditions: All crates built
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server --test e2e -- test_wire_format_compliance --nocapture`
      2. Verify: intercepted wire data contains NO CBOR markers (0xbf, 0xff, 0xa1)
      3. Verify: all integer fields are QUIC varint encoded
      4. Verify: string fields use QUIC varint length prefix + UTF-8 bytes
      5. Verify: boolean fields are single raw byte (0x00/0x01)
      6. Verify: message type tags are QUIC varint
    Expected Result: Wire format is 100% SSH binary + QUIC varint, zero CBOR
    Failure Indicators: Any CBOR byte pattern detected, or non-varint integers
    Evidence: .sisyphus/evidence/task-25-wire-format-compliance.txt

  Scenario: Multiple concurrent channels
    Tool: Bash
    Preconditions: All crates built
    Steps:
      1. Run `cargo test -p genmeta-ssh3-server --test e2e -- test_multiple_channels --nocapture`
      2. Verify: 3 session channels opened simultaneously (3 separate QUIC bidi streams)
      3. Verify: each channel independently executes a command and receives output
      4. Verify: no data cross-contamination between channels
      5. Verify: all 3 channels close cleanly
    Expected Result: Channels are fully independent via QUIC streams
    Failure Indicators: Data from one channel appears in another, or deadlock
    Evidence: .sisyphus/evidence/task-25-multiple-channels.txt
  ```

  **Commit**: YES
  - Message: `test(ssh3): add complete E2E integration tests`
  - Files: `genmeta-ssh3-server/tests/e2e.rs`, `genmeta-ssh3-server/tests/common/mod.rs`
  - Pre-commit: `cargo test -p genmeta-ssh3-server --test e2e`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Rejection → fix → re-run.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, curl endpoint, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan. **特别检查**: 无 CBOR 引用、无 ChannelId、无 ChannelOpen(90)、无 ChannelWindowAdjust(93)。
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `cargo build --workspace && cargo clippy --workspace -- -D warnings && cargo test --workspace`. Review all changed files for: `as any`/`@ts-ignore` (Rust equivalents: `as _`, unsafe without justification), empty catches, println!/dbg! in prod, commented-out code, unused imports. Check AI slop: excessive comments, over-abstraction, generic names (data/result/item/temp).
  Output: `Build [PASS/FAIL] | Clippy [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state. Execute EVERY QA scenario from EVERY task — follow exact steps, capture evidence. Test cross-task integration (features working together, not isolation). Test edge cases: empty state, invalid input, rapid actions. Save to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (git log/diff). Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT do" compliance. Detect cross-task contamination: Task N touching Task M's files. Flag unaccounted changes. **特别检查**: 无任何 CBOR 代码残留、ChannelRequest type=98 not 95。
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

- **Wave 1**: `feat(ssh3): reset worktree and create greenfield crate scaffolding` — Cargo.toml, src/lib.rs files
- **Wave 1**: `feat(ssh3-proto): implement SSH binary wire format codec with QUIC varint encoding` — codec.rs
- **Wave 1**: `feat(ssh3-proto): define snafu error model and AuthCredential` — error.rs, session.rs
- **Wave 2**: `feat(ssh3-proto): implement Conversation trait with Local/Remote variants` — conversation.rs
- **Wave 2**: `feat(ssh3-proto): define complete SshMessage enum with SSH binary codec` — message.rs
- **Wave 2**: `feat(ssh3-server): implement Ssh3Protocol for h3x Protocol trait` — protocol.rs
- **Wave 3**: `feat(ssh3-server): implement version negotiation and auth parsing` — auth.rs, version.rs
- **Wave 3**: `feat(ssh3-server): implement Extended CONNECT handler` — handler.rs
- **Wave 4**: `feat(ssh3-proto): define SshSession RTC trait` — session.rs
- **Wave 4**: `feat(ssh3-server): implement PAM wrapper` — auth/pam.rs
- **Wave 4**: `feat(ssh3-server): implement ssh3-session child process binary` — bin/ssh3-session.rs
- **Wave 5**: `feat(ssh3-proto): implement channel lifecycle (open/confirm/data/eof/close)` — channel.rs
- **Wave 5**: `feat(ssh3-server): implement exec/shell/pty request handling` — session/
- **Wave 5**: `feat(ssh3): implement TCP forwarding with raw byte streams` — forward/direct_tcp.rs, reverse_tcp.rs, streamlocal.rs
- **Wave 5**: `feat(ssh3-server): implement SOCKS5 proxy` — forward/socks5.rs
- **Wave 6**: `feat(ssh3-client): implement SSH3 client connection and auth` — client lib
- **Wave 6**: `feat(ssh3-client): implement session and forwarding requests` — session.rs, forward.rs
- **Wave 6**: `feat(ssh3-client): implement local SOCKS5 proxy` — socks5.rs
- **Wave 6**: `test(ssh3): add complete E2E integration tests` — tests/

---

## Success Criteria

### Verification Commands
```bash
cargo build --workspace  # Expected: success
cargo test --workspace   # Expected: all tests pass
cargo clippy --workspace -- -D warnings  # Expected: no warnings
# E2E test
cargo test -p genmeta-ssh3-server --test e2e -- basic_exec  # Expected: "hello\n" received
# Wire format verification
cargo test -p genmeta-ssh3-proto -- wire_format  # Expected: hex dumps match Go reference
# No CBOR anywhere
grep -r "cbor\|ciborium\|serde_cbor" --include="*.rs" .  # Expected: no matches
# No ChannelId anywhere
grep -r "ChannelId" --include="*.rs" .  # Expected: no matches
# No ChannelOpen(90) or ChannelWindowAdjust(93)
grep -r "ChannelOpen\|ChannelWindowAdjust" --include="*.rs" .  # Expected: no matches
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] All tests pass
- [ ] Wire format hex dumps match Go reference implementation
- [ ] No CBOR/ciborium references in codebase
- [ ] No ChannelId type defined
- [ ] No ChannelOpen(90) or ChannelWindowAdjust(93) message types
- [ ] ChannelRequest type value = 98 (not 95)
- [ ] TCP forwarding uses raw byte streams
- [ ] Session channels use SSH_MSG_CHANNEL_DATA(94) wrapping
