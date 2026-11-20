# T298 DTLS 握手期不可归因记录处置修复 — 交付说明

## 1. 背景与现象

安全接入平台对 DTLS 接入口的握手失败按错误串分类归档告警。排查中出现一类
无法归因的握手失败，触发条件为：同一出口 NAT 后并存旧版本终端与扫描器探活系统，
它们向 DTLS 端口误发手工构造的 UDP 数据；灰度期新旧协议客户端的内容类型集合
不一致。

具体构造输入：DTLS 1.2 证书握手中途，自客户端一侧混入一条 **15 字节明文记录**
（固定头 13 字节 + 2 字节负载），其内容类型为 **27**
（`ContentTypeReturnRoutabilityCheck`，RFC 9853 Return Routability Check）、
**epoch 为 0**。混入后两端握手全部失败，且浮出的错误串均不指向该混入记录：

- 服务端：`data length and declared length do not match`（长度类错误，与混入记录无直接关系）。
- 客户端：对端致命告警导致的连接拆除（实测为 `alert: Alert Fatal: DecodeError`，
  告警先于本地关闭感知时；若传输先关闭则表现为 `conn is closed`）。

对照实验：同形态记录仅把首字节内容类型换成其他取值（落在 DTLS 1.3 密文判定
区间 32..63）时，被既有路径静默丢弃，握手照常完成；对端明确拒绝类路径浮出的
错误可正常分类。说明问题只出在"DTLS 1.2 固定头 + 未知/不可归因内容类型"这一支。

---

## 2. 根因链分析（现象 → 根因，每跳附实测证据）

### 跳 1：记录能通过帧级解帧，进入内容分发

`recordlayer.UnpackDatagram` → `nextRecord` 只做帧头/长度/版本形态校验
（`pkg/protocol/recordlayer/recordlayer.go:280`）。类型 27 不是密文区间值
（`protocol.IsDTLS13Ciphertext` 判定 `ct > 31 && ct < 64`，见
`pkg/protocol/content.go:31`），因此按普通固定头记录处理；15 字节 = 13 字节头 +
声明负载 2 字节，帧长度自洽，不触发任何帧级错误。

证据：复现测试中该记录被 `UnpackDatagram` 正常切分，`processDatagram`
（`conn.go:1959`）拿到非空 `pkts`，未走"framing errors are unauthenticated input"
的整包丢弃分支。

### 跳 2：握手期记录被路由到 RRC 内容类型的解码

`processDatagramPackets` 逐条调用 `processIncomingPacket` →
`handleIncomingPacket`（`conn.go:3081`）。该记录非 Handshake，进入
`unmarshalRecordContent`（`conn.go:3105`）。其 switch 对
`ContentTypeReturnRoutabilityCheck` 构造 `&protocol.ReturnRoutabilityCheck{}`
并调用 `Unmarshal`（`conn.go` 中 `unmarshalRecordContent` 的 RRC 分支）。

### 跳 3：RRC 负载长度不符，浮出与混入记录无关的长度错误

`ReturnRoutabilityCheck.Unmarshal`（`pkg/protocol/return_routability_check.go:60`）：
已知消息类型要求负载恰为 1 + 8（cookie）= 9 字节，而实际负载只有 2 字节，
于是在 `return_routability_check.go:74` 返回
`dtlserrors.ErrLengthMismatch`
（"data length and declared length do not match"）。

证据（修复前实测，`go test -run TestReproDefectErrors`）：

```
record length=15 ct=27 epoch=[0 0]
SERVER_ERROR_TEXT: handshake failed: data length and declared length do not match
```

`errors.Is(serverErr, dtlserrors.ErrLengthMismatch) == true`。该错误串描述的是
RRC 消息体长度，而非"混入了一条不可归因记录"，因此监控无法归到真实根因。

### 跳 4：解码错误被包装成致命 DecodeError 告警并终止握手

回到 `handleIncomingPacket`：`unmarshalRecordContent` 返回错误后，被包装为
`packetOutcome{responseAlert: {Level: Fatal, Description: DecodeError}}`
（`conn.go:3107` 一带）。`processIncomingPacket`（`conn.go:3122`）见到
`responseAlert` 即调用 `notify` 发出致命告警，错误沿读循环
`runHandshakeReader` → `firstErr` → `translateHandshakeCtxError`
（`conn.go`，统一加 `"handshake failed: "` 前缀）浮出，握手终止。

### 跳 5：客户端只感知到对端拆除，错误串与根因错位

服务端发出的致命告警到达客户端，客户端读循环将其分类为
`readLoopCloseAndStop` 并关闭底层连接。客户端握手浮出的是对端告警/连接关闭，
完全不含"类型 27 记录"信息。

证据（修复前实测，连续 3 次稳定复现）：

```
CLIENT_ERROR_TEXT: handshake failed: alert: Alert Fatal: DecodeError
```

在传输关闭先于告警处理的时序下，同一根因也可能浮出 `conn is closed`
（`dtlserrors.ErrConnClosed`）。两种客户端串都与混入记录无关，这正是题面所述
"两条错误串均未指向混入记录的处理结果"。

### 对照实验为何不失败

把首字节改为 `0x20`（落密文区间 32..63）后，`prepareIncomingPacket`
（`conn.go:2403`）首条判定 `IsDTLS13Ciphertext` 为真；在已选定 DTLS 1.2 的
连接上走 `"discarded DTLS 1.3 ciphertext on a DTLS 1.2 connection"` 静默丢弃分支，
不进入内容解码，握手照常完成。帧级损坏记录则在
`unmarshalLegacyHeader`/`UnpackDatagram` 处按既有 RFC 6347 静默丢弃路径收敛。

### 根因结论

握手期（认证完成前）对一条**结构合法、但内容类型在当前未认证协议状态下没有
归属者**的固定头记录，代码直接进入了面向"已协商/已认证"场景的内容解码与致命
告警路径，而不是按"未认证不可归因输入"丢弃收敛。RRC(27) 是典型的仅在握手后、
经协商且受保护的场景才合法的内容类型，却在 epoch 0 明文阶段被当成可解码消息，
最终以不相干的 `ErrLengthMismatch` 触发致命告警，造成双端错误串与真实根因错位。

---

## 3. 修复方案与设计取舍

### 在案边界（必须满足）

1. 认证完成前，无法归属已知内容的输入不得终止握手，以丢弃或延后处理收敛。
2. 认证完成后，对已认证对端的协议错误仍按现语义回致命告警。
3. 既有帧级与版本级解析失败的静默丢弃路径语义不变。
4. DTLS 1.3 密文判定区间（32..63）与 DTLS 1.2 未知内容类型判定互不越界；
   对照实验中两类取值的行为差异保持。
5. 握手失败向业务浮出的错误串须与真实根因一致，不得再出现与混入记录无关的
   长度类错误串。

### 取舍决策（自行设计部分）

- **收敛方式选择"静默丢弃"而非"延后排队"。** 不可归因内容类型在当前及任何
  可预见的未来 epoch 都不会变成可归因（RRC 永远不会以 epoch 0 明文形式合法；
  未知/保留值无协商 owner）。延后排队只对"未来 epoch 会变合法"的记录有意义
  （该能力已由 `handleFutureLegacyPacket`/`queueIfCipherSuiteUninitialized`
  提供），对本类输入排队只会无谓占用 `encryptedPackets` 队列并放大扫描器流量
  的内存压力。因此在记录分发最前端直接丢弃，语义最清晰、攻击面最小。
- **闸门位置选在 `prepareIncomingPacket`、legacy 分发之前。** 此处已经过完
  帧级解帧与版本形态判定，能同时拿到首字节内容类型和握手完成标志，且位于
  任何内容解码/告警产生之前，保证"不产生告警、不触碰解码"。
- **以"握手是否已建立"作为认证前后分界**（`isHandshakeCompletedSuccessfully`），
  与代码库既有的认证边界判定保持同一信号，避免新增并行的状态口径。
- **判定逻辑下沉到 `internal/handshake` 作为纯函数分类器**
  `IsUnauthenticatedPlaintextContentType`，conn 层只负责"丢弃"动作；分类器可被
  独立单测覆盖，且显式排除密文区间，从结构上保证两类判定不越界。
- **新增控制流哨兵错误 `ErrUnauthenticatedRecordDiscarded` 仅用于日志可观测性**，
  不作为连接错误返回、不触发告警；监控若需要可据此统计被丢弃的未归因记录，
  但它不进入握手失败路径。

### 修复后行为

- 认证前：类型 27（及任何未知/保留固定头类型）的明文记录在
  `prepareIncomingPacket` 被识别为不可归因，记 Debug 日志后返回
  `(incomingPacketState{}, false, nil)`，握手继续直至成功，双端无错误、无告警。
- 认证后：闸门因 `isHandshakeCompletedSuccessfully()` 为真而整体旁路，RRC 等
  仍走 `handleRecordContent`/`returnRoutabilityConn.HandleRecord` 的现有致命
  告警语义（未协商 RRC 时 `ErrUnexpectedPostHandshakeMessage` +
  `UnexpectedMessage` 致命告警），保持不变。
- 密文区间与帧级/版本级丢弃路径：完全不经新闸门，行为零变化。

---

## 4. 逐文件改动登记

| 文件 | 类型 | 改动内容 |
| --- | --- | --- |
| `internal/errors/errors.go` | 修改 | 新增哨兵错误 `ErrUnauthenticatedRecordDiscarded`（含完整变量说明注释，明确其为控制流信号而非连接失败、禁止告警、认证后不映射）。 |
| `internal/handshake/record_content.go` | 新增 | 纯函数 `IsUnauthenticatedPlaintextContentType`：固定头内容类型在认证前是否不可归因；显式 `IsDTLS13Ciphertext` 守卫保证密文区间不越界；6 类有 epoch-0 处理者的类型判为可归因，其余（含 27 与未知/保留值）判为不可归因。 |
| `conn.go` | 修改 | `prepareIncomingPacket`（约 `conn.go:2420`）在 DTLS 1.3 明文形态判定之后、`prepareLegacyPacket` 之前插入认证前丢弃闸门：未建立握手且分类器判定不可归因时，记日志并返回丢弃，不进入解码/告警。 |
| `internal/handshake/record_content_test.go` | 新增 | 分类器单测：可归因集合、不可归因集合（含 27、0、24、28..31）、密文区间 32..63 全部不被该分类器认领。 |
| `injection_matrix_test.go`（根包） | 新增 | 注入回归矩阵 + 题面构造输入端到端用例（同目录同框架，与既有 `conn_test.go` 一致）。 |

改动面严格收在题面允许的 **根包 `conn.go`、`internal/errors`、
`internal/handshake` 及其对应测试文件**。生产代码净增 25 行
（`git diff --stat`：`conn.go` +17、`internal/errors/errors.go` +8），
未改动任何帧级/版本级既有丢弃路径与 RRC 认证后处理逻辑。

---

## 5. 题面要求 → 具体改动映射

| 题面要求 | 对应改动 |
| --- | --- |
| 认证完成前不可归因输入不得终止握手，以丢弃/延后收敛 | `conn.go` 认证前闸门 + 选择静默丢弃（理由见 §3） |
| 认证完成后已认证对端协议错误仍回致命告警 | 闸门以 `isHandshakeCompletedSuccessfully()` 为界整体旁路；`TestInjectionMatrixAuthenticatedProtocolError` 固化 RRC 仍回 `UnexpectedMessage` 致命告警 |
| 帧级与版本级解析失败静默丢弃语义不变 | 未触碰 `UnpackDatagram`/`unmarshalLegacyHeader`/密文区间分支；`FrameLevelCorruption`、`CiphertextRangeSameShape` 用例反证 |
| 密文区间与 1.2 未知类型判定互不越界、对照差异保持 | 分类器首行 `IsDTLS13Ciphertext` 守卫 + 单测遍历 32..63；E2E `CiphertextRangeSameShape` 与 `UnknownContentTypeRRC27` 行为对照 |
| 错误串与真实根因一致、不出现无关长度类错误 | 混入记录不再进入 RRC 解码，`ErrLengthMismatch` 不可能由该路径产生；用例断言双端 nil 且 `errors.Is(..., ErrLengthMismatch)==false` |
| 错误变量说明注释同步更新 | `ErrUnauthenticatedRecordDiscarded` 附完整注释 |
| 注入回归用例随修复同步、并入根包/同目录同框架 | `injection_matrix_test.go`（根包 `package dtls`）、`record_content_test.go`（handshake 包） |
| 注入矩阵覆盖四类构造输入 | ①握手期未知内容类型 ②密文区间同形态 ③已认证会话期协议错误 ④帧级损坏，见 §6 |
| 根因链与逐文件登记写入交付说明 | 本文件 §2、§4 |
| 验收命令零失败 + 双端错误串原文 | §7、§8 |

---

## 6. 注入矩阵覆盖（四类构造输入）

测试入口：根包 `TestInjectionMatrixHandshakeDiscard`、
`TestInjectionMatrixAuthenticatedProtocolError`、
`TestInjectedRRC27EpochZeroRecordBothEndsSucceed`；
handshake 包 `TestIsUnauthenticatedPlaintextContentType`。

1. **握手期未知内容类型记录**：`UnknownContentTypeRRC27`（类型 27，15 字节，
   epoch 0）、`UnknownContentTypeReserved24`（未分配值 24）→ 静默丢弃，握手成功。
2. **落在密文判定区间的同形态记录**：`CiphertextRangeSameShape`（同形态但首字节
   改为 `0x20`）→ 走既有版本级丢弃，握手成功；与第 1 类形成行为对照。
3. **已认证会话期协议错误**：建立真实 DTLS 1.2 握手后，对未协商 RRC 的连接注入
   RRC（经 `handleRecordContent`）→ 仍返回 `ErrUnexpectedPostHandshakeMessage`
   并带 `Fatal/UnexpectedMessage` 告警，证认证后语义不变。
4. **帧级损坏记录**：`FrameLevelCorruption`（声明长度大于实际字节）→ 既有帧级
   静默丢弃路径，握手成功。

---

## 7. 验收命令最终读数

题面指定验收命令（修复后实测）：

```
$ go test -count=1 -run "TestUnpackDatagramMixedFixedRecords|TestUnpackDatagramTargetVersion12RejectsUnified|TestAlertLevelsByVersion" ./pkg/protocol/recordlayer/ .
ok  	github.com/pion/dtls/v4/pkg/protocol/recordlayer	0.777s
ok  	github.com/pion/dtls/v4	0.093s
```

零失败。新增回归用例读数：

```
$ go test -count=1 -run "TestInjectedRRC27|TestInjectionMatrix|TestIsUnauthenticated" . ./internal/handshake/
ok  	github.com/pion/dtls/v4	0.160s
ok  	github.com/pion/dtls/v4/internal/handshake	0.694s
```

全量回归（无 FAIL）：

```
$ go test -count=1 ./...
ok  	github.com/pion/dtls/v4	17.791s
ok  	github.com/pion/dtls/v4/internal/handshake	1.678s
ok  	github.com/pion/dtls/v4/pkg/protocol/recordlayer	0.718s
... （其余包全部 ok，无 FAIL）
```

`go vet ./...` 干净。注：本机无 gcc，`-race` 无法启用（cgo 缺 C 编译器）；
本次改动只读既有连接状态、不新增共享可变数据，未引入新的并发原语。

---

## 8. 构造输入下双端实测错误串原文

构造输入：握手完成前向服务端注入一条 15 字节、内容类型 27、epoch 0 的明文
记录（13 字节固定头 `1b fe fd 00 00 <6字节seq> 00 02` + 2 字节负载 `00 01`）。

### 修复前（缺陷态，连续 3 次稳定复现）

```
record length=15 ct=27 epoch=[0 0]
SERVER_ERROR_TEXT: handshake failed: data length and declared length do not match
CLIENT_ERROR_TEXT: handshake failed: alert: Alert Fatal: DecodeError
```

- 服务端 `errors.Is(err, dtlserrors.ErrLengthMismatch) == true`。
- 客户端在传输先关闭的时序下也可能为
  `handshake failed: conn is closed`（`ErrConnClosed`）。两串均不指向混入记录。

### 修复后（`TestInjectedRRC27EpochZeroRecordBothEndsSucceed`，连跑 3 次）

```
client handshake error: <nil>
server handshake error: <nil>
errors.Is(clientErr, ErrLengthMismatch) == false
errors.Is(serverErr, ErrLengthMismatch) == false
```

双端握手均正常完成，无任何告警，无长度类错误串；混入记录仅在服务端产生一条
Debug 日志（含 `ErrUnauthenticatedRecordDiscarded` 文案），可观测但不影响连接。
