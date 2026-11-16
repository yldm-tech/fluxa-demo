# fluxa 签名契约

本文件是本仓库所有 demo 的实现依据，由 [`vectors.json`](./vectors.json) 锁定——那是由 fluxa 服务端真实签名代码生成的已知答案向量。实现与本文档冲突时，以向量为准。

English: [SIGNING.md](./SIGNING.md)

---

## 1. 商户 API 请求签名

每个 `/api/v1/*` 请求带三个头：

| Header | 值 |
| --- | --- |
| `X-Api-Key` | 你的 `key_id` |
| `X-Timestamp` | Unix 秒（服务端允许 ±5 分钟时钟偏移） |
| `X-Signature` | `hex(HMAC_SHA256(secret, canonical))`，小写 |

### canonical 是 5 行，用 `\n` 连接

```
METHOD
PATH
CANONICAL_QUERY
TIMESTAMP
SHA256_HEX(BODY)
```

- `METHOD`——转大写（`post` → `POST`）
- `PATH`——不含域名和 query，如 `/api/v1/charges`
- `CANONICAL_QUERY`——见下。**没有 query 时这一行是空字符串，但这一行仍然存在**， 即 canonical 含一个空的第三行
- `TIMESTAMP`——与 `X-Timestamp` 头逐字节一致
- `SHA256_HEX(BODY)`——请求体原始字节的 SHA-256，小写十六进制。空体是对空串求哈希 （恒为 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`）

> **最常见的错误：没有 query 时把第三行整行省掉。** 那会得到 4 行串，HMAC 完全不同，
> 服务端返回 `401 bad_signature`。这一行即使为空也是承重的。

无 query 的 POST 长这样（`⏎` 表示换行）：

```
POST⏎/api/v1/charges⏎⏎1750000000⏎74f74511aebc…
                      ↑ 这个空行必须在
```

### CANONICAL_QUERY

把原始 query 按 `&` 切成片段，按 **UTF-8 字节序**排序，再用 `&` 拼回：

| 原始 query | CANONICAL_QUERY |
| --- | --- |
| （无） | `` （空串） |
| `status=paid&limit=10` | `limit=10&status=paid` |
| `limit=10&status=paid` | `limit=10&status=paid` |
| `z=1&z=2&a=3` | `a=3&z=1&z=2` |

排序对象是整个 `key=value` 片段（不是只按 key），不做百分号解码，重复 key 全部保留。 这让签名与参数发送顺序无关，同时任何 query 参数都无法在保持签名有效的前提下被篡改。

两个真实存在的可移植性陷阱：

- **必须按 UTF-8 字节序排序。** 对 ASCII/百分号编码的 query（即全部真实流量），这与多数语言 的默认字符串排序一致；但对未编码的非 ASCII 字符会分叉，而且 **C# 的默认排序是 culture-sensitive**，即使全 ASCII 在某些 locale 下也是错的。各语言的正确比较器见 [`README.md`](./README.md)。
- **按 `&` 切分时必须保留尾部空片段。** Ruby 默认的 `split` 和 Java 单参数的 `String.split` 会丢弃它们，与服务端分叉；两者都要显式传 `-1`。

### 签名的字节必须与发送的字节一致

body 只序列化**一次**，然后签它、发它——**同一份字节**。不要签名后再序列化一次： 键顺序或空格的任何差异都会让签名失效。

---

## 2. Webhook 验签

订单状态变化时，fluxa 会向你配置的回调地址 POST 一个事件。

| Header | 值 |
| --- | --- |
| `X-Fluxa-Event` | 事件类型，见 §3.2 |
| `X-Fluxa-Event-Id` | 与正文 `event_id` 相同；以验签后的正文值为准 |
| `X-Fluxa-Timestamp` | Unix 秒 |
| `X-Fluxa-Signature` | `hex(HMAC_SHA256(webhook_secret, "<timestamp>.<原始body>"))` |
| `X-Fluxa-Encryption` | 仅在开启载荷加密时出现，值为 `A256GCM` |

验签：

```
expected = hex(HMAC_SHA256(webhook_secret, X-Fluxa-Timestamp + "." + rawBody))
reject unless constant_time_equals(expected, X-Fluxa-Signature)
```

规则：

- **必须用原始接收字节验签。** 反序列化再重新序列化会改变字节，签名就对不上。会自动解析 JSON 的框架（Express 的 `express.json()` 之类）会破坏这一点，除非你先拿到原始 body。
- 必须用**常量时间**比较。
- 校验 `X-Fluxa-Timestamp` 的新鲜度（±5 分钟是合理窗口）以限制重放。
- 投递是 **at-least-once**，按验签后的正文 `event_id` 去重，见 §3.1。
- 失败会按指数退避重试（最多 8 次）。尽快返回 `2xx`；其他状态码都视为失败。

### 加密信封（开启载荷加密时）

body 不再是明文事件 JSON，而是：

```json
{ "alg": "A256GCM", "data": "<base64( nonce[12] || ciphertext || gcm_tag[16] )>" }
```

**先验签、再解密**——签名覆盖的是实际发送的信封。

1. `key = SHA256(webhook_secret)`（32 字节，对 secret 的**原始字节**求哈希）
2. `blob = base64_decode(json.data)`
3. `nonce = blob[:12]`，`ciphertext_and_tag = blob[12:]`
4. `plaintext = AES_256_GCM_open(key, nonce, ciphertext_and_tag, aad=nil)`

tag 的传法各语言不同——这里是移植时的高频 bug：

| 语言 | tag 处理 |
| --- | --- |
| Go、Java、Rust | tag **留在密文尾部**，整体传 `blob[12:]`（Java 需 `GCMParameterSpec(128, nonce)`，tag 长度必须 128 位） |
| Node、Ruby、PHP、C# | tag **单独传**：tag 是 `blob[-16:]`，密文是 `blob[12:-16]` |
| Python | 标准库没有 AES —— `pip install cryptography`（仅加密 webhook 需要） |

AAD 为空。

> **Ruby 注意：** AES-256-GCM 在链接 **LibreSSL** 的 Ruby 上**完全不可用**——macOS 系统自带的
> ruby 正是这种。所有写法都失败（设/不设 `auth_data`、调换 `auth_tag` 顺序、显式 `iv_len`）。
> 这是 LibreSSL 的限制，与 Ruby 版本无关：同一份代码在 `ruby:2.6-slim`（Ruby 2.6 + OpenSSL）
> 上完全通过。用链接 OpenSSL 的 Ruby 即可，版本不限。签名、下单、明文 webhook 验签在系统 ruby
> 上都正常，只有加密信封受影响。

---

## 3. 事件体

```json
{
  "event_id": "whk_example_paid",
  "event": "payment.succeeded",
  "order_id": "ord_…",
  "merchant_order_id": "order-1",
  "amount": "9.99",
  "currency": "USD",
  "status": "paid",
  "channel": "mock",
  "channel_name": "Mock (test)",
  "is_test": true
}
```

| 字段 | 说明 |
| --- | --- |
| `event` | 事件类型，见 §3.2 |
| `event_id` | 不透明事件 ID；重试不变、不同事件不同 |
| `order_id` | fluxa 订单号 `ord_<ULID>` |
| `merchant_order_id` | 你下单时传的幂等键 |
| `amount` | **订单总额**——不是退款额 |
| `currency` | 币种 |
| `status` | `pending` / `paid` / `failed` / `refunded` / `partially_refunded` / `expired` / `canceled` |
| `channel` | 渠道 code |
| `channel_name` | 渠道展示名 |
| `is_test` | **`true` = 测试订单，无真实资金，切勿发货**。测试密钥的订单照样推 webhook，供你联调 |
| `refunded_amount` | **累计**已退总额；**仅在确有退款后出现**。见 §3.1 |

金额一律是**十进制字符串**。绝不要解析成浮点——服务端存 `numeric(38,18)` 并用 decimal 运算。把 `9.99` 解析成双精度不会当场看出问题——但最近的双精度值是 `9.99000000000000021…`，误差会累积：`9.99` 累加 100 次得到 `999.0000000000007` 而非 `999`。对账就会差出一分钱，而且谁也查不出来。

### 3.1 事件标识与累计退款

使用验签、解密后正文里的非空字符串 `event_id` 作为唯一事件键。`X-Fluxa-Event-Id` 携带相同值方便追踪，但头不在签名内，不能只信头。重试和手工重投保留相同 ID；不同事件即使订单、类型、金额完全相同也有不同 ID。示例对缺失或格式错误的正文 ID 返回 400，不会悄悄回退到会丢事件的组合键。旧的 `(event, order_id, refunded_amount)` 已不是当前契约。

ID 不代表顺序。1000 的订单先退 30、再退 20，会收到不同 ID、累计 `refunded_amount` 分别为 `30.00` 和 `50.00` 的两个事件。按十进制运算推进到 `max(已记录, refunded_amount)`：累加会多记退款，直接赋值会让迟到的 `30.00` 覆盖 `50.00`。对账只应用正增量，不把订单 `amount` 当作退款额。事件去重和累计状态更新必须在同一数据库事务内。

### 3.2 当前事件与乱序处理

| 事件 | 处理方式 |
| --- | --- |
| `payment.succeeded` | 精确金额订单只履约一次；`settle_on_received: true` 时按累计 `received_amount` 入账，不按报价 `amount` 入账。 |
| `payment.additional_received` | 按实收结算订单的追加到账。事务中将累计入账毛额推进到 `max(已记录, received_amount)`，只应用正增量，不再另加 `deposit_amount`。它可能先于 `payment.succeeded` 到达。 |
| `payment.failed` | 核对订单失败状态；迟到事件不可覆盖较新的已支付或已退款状态。 |
| `payment.refunded` | 按十进制 max 推进累计 `refunded_amount`；`reason` 区分 `refund` 与 `dispute`。 |
| `payment.pending` | 必须显式订阅。仅在订单仍待支付时展示 `payment_method`、`payment_expires_at`、`voucher`；不能据此发货。更新付款单会使用新的事件 ID。 |
| `payment.dispute_created` / `payment.dispute_closed` | 必须显式订阅。按 `dispute_id` 保存 `is_inquiry`、`escalated`、`outcome`、`corrected`；关闭事件可能先到，改判为 `won` 可覆盖原有 `lost`。事件本身不代表资金变动，扣款通过 `payment.refunded` 报告。 |
| `order.created` / `order.expired` / `order.canceled` | 必须显式订阅。记录创建；关闭后隐藏收银链接、嵌入式支付表单与收款地址。迟到的创建事件不可重新打开订单。 |
| `settlement.completed` | 商户结算到账凭证，带 `settlement_tx`、`settlement_address`、`chain`、`asset`、`fee`，`amount` 是到账净额；不能再次给顾客入账或发货。 |
| `subscription.charged` / `subscription.payment_failed` / `subscription.completed` | 更新订阅生命周期，不要重复支付事件已执行的履约。 |

空订阅列表包含普通支付、结算、订阅事件，但不包含上述需要显式订阅的事件。非空白名单必须列出所有需要的事件，按实收结算须包括 `payment.additional_received`。未知事件记录后应答，不执行履约；非支付事件可能没有订单字段。

支付事件的可选字段包括 `paid_at`，按实收结算的 `settle_on_received`、`min_received_amount`、`received_amount`，追加到账的 `deposit_id`、`tx_hash`、`deposit_amount`，以及已结算正式订单的 `fee` / `net` 快照。快照不能累加，直清订单退款后 `net` 可能为负。退款会减少手续费或净额，不能对 `fee` / `net` 取 max；乱序对账时查询当前订单。

### 3.3 生产处理

接收器只打印业务动作，去重使用本地演示存储（PHP 使用文件标记），不是持久化账本。生产顺序为：验签 → 解密 → 校验 `event_id` → 开启数据库事务 → 插入事件唯一键并应用订单状态/累计金额增量 → 提交 → 返回 2xx。已提交的重复 ID 直接返回 2xx。失败时同时回滚事件标记和业务写入，返回失败以便重试；异步任务应先持久化事件再应答，不能先永久标记已处理再执行可能失败的业务。

所有真实资金变动或履约前检查 `is_test`。浏览器跳转成功页不代表付款成功，必须以验签事件或签名查询订单为准。事件 ID 是不透明字符串，不表达时间或顺序。
