# fluxa 签名契约

本文件是本仓库所有 demo 的实现依据，由 [`vectors.json`](./vectors.json) 锁定——那是由 fluxa
服务端真实签名代码生成的已知答案向量。实现与本文档冲突时，以向量为准。

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
- `CANONICAL_QUERY`——见下。**没有 query 时这一行是空字符串，但这一行仍然存在**，
  即 canonical 含一个空的第三行
- `TIMESTAMP`——与 `X-Timestamp` 头逐字节一致
- `SHA256_HEX(BODY)`——请求体原始字节的 SHA-256，小写十六进制。空体是对空串求哈希
  （恒为 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`）

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

排序对象是整个 `key=value` 片段（不是只按 key），不做百分号解码，重复 key 全部保留。
这让签名与参数发送顺序无关，同时任何 query 参数都无法在保持签名有效的前提下被篡改。

两个真实存在的可移植性陷阱：

- **必须按 UTF-8 字节序排序。** 对 ASCII/百分号编码的 query（即全部真实流量），这与多数语言
  的默认字符串排序一致；但对未编码的非 ASCII 字符会分叉，而且 **C# 的默认排序是
  culture-sensitive**，即使全 ASCII 在某些 locale 下也是错的。各语言的正确比较器见
  [`README.md`](./README.md)。
- **按 `&` 切分时必须保留尾部空片段。** Ruby 默认的 `split` 和 Java 单参数的 `String.split`
  会丢弃它们，与服务端分叉；两者都要显式传 `-1`。

### 签名的字节必须与发送的字节一致

body 只序列化**一次**，然后签它、发它——**同一份字节**。不要签名后再序列化一次：
键顺序或空格的任何差异都会让签名失效。

---

## 2. Webhook 验签

订单状态变化时，fluxa 会向你配置的回调地址 POST 一个事件。

| Header | 值 |
| --- | --- |
| `X-Fluxa-Event` | `payment.succeeded` / `payment.failed` / `payment.refunded` |
| `X-Fluxa-Timestamp` | Unix 秒 |
| `X-Fluxa-Signature` | `hex(HMAC_SHA256(webhook_secret, "<timestamp>.<原始body>"))` |
| `X-Fluxa-Encryption` | 仅在开启载荷加密时出现，值为 `A256GCM` |

验签：

```
expected = hex(HMAC_SHA256(webhook_secret, X-Fluxa-Timestamp + "." + rawBody))
reject unless constant_time_equals(expected, X-Fluxa-Signature)
```

规则：

- **必须用原始接收字节验签。** 反序列化再重新序列化会改变字节，签名就对不上。会自动解析
  JSON 的框架（Express 的 `express.json()` 之类）会破坏这一点，除非你先拿到原始 body。
- 必须用**常量时间**比较。
- 校验 `X-Fluxa-Timestamp` 的新鲜度（±5 分钟是合理窗口）以限制重放。
- 投递是 **at-least-once**——同一事件可能到达多次，必须幂等处理。
  **幂等键用 `(event, order_id, refunded_amount)`，不要只用 `(event, order_id)`**——
  后者不唯一，会丢掉部分退款，见 §3.1。
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
  "event": "payment.succeeded",
  "order_id": "ord_…",
  "merchant_order_id": "order-1",
  "amount": "9.99",
  "currency": "USD",
  "status": "paid",
  "channel": "mock",
  "channel_name": "Mock (test)",
  "is_test": false,
  "refunded_amount": "0"
}
```

| 字段 | 说明 |
| --- | --- |
| `event` | `payment.succeeded` / `payment.failed` / `payment.refunded` |
| `order_id` | fluxa 订单号 `ord_<ULID>` |
| `merchant_order_id` | 你下单时传的幂等键 |
| `amount` | **订单总额**——不是退款额 |
| `currency` | 币种 |
| `status` | `paid` / `failed` / `refunded` / **`partially_refunded`** |
| `channel` | 渠道 code |
| `channel_name` | 渠道展示名 |
| `is_test` | **`true` = 测试订单，无真实资金，切勿发货**。测试密钥的订单照样推 webhook，供你联调 |
| `refunded_amount` | **累计**已退总额；**仅在确有退款后出现**。见 §3.1 |

金额一律是**十进制字符串**。绝不要解析成浮点——服务端存 `numeric(38,18)` 并用 decimal
运算。把 `9.99` 解析成双精度不会当场看出问题——但最近的双精度值是 `9.99000000000000021…`，误差会累积：`9.99` 累加 100 次得到 `999.0000000000007` 而非 `999`。对账就会差出一分钱，而且谁也查不出来。

### 3.1 部分退款——最容易赔钱的地方

一笔订单可以被**多次部分退款**，每次都推送一个 `payment.refunded`。因此：

> **`(event, order_id)` 不是唯一的。** 用它去重，第二笔部分退款会被当成「重复」丢弃、返回
> `2xx`，fluxa 认为投递成功、永不重试。客户少退了钱，而整条链路没有任何报错。

1000 的订单先退 30、再退 20，你会收到两个事件：

| 第几次 | `amount`（订单总额） | `refunded_amount`（累计） | `status` |
| --- | --- | --- | --- |
| 第 1 次 | `1000.00` | `30.00` | `partially_refunded` |
| 第 2 次 | `1000.00` | `50.00` | `partially_refunded` |

两条规则：

1. **幂等键带上 `refunded_amount`**：`(event, order_id, refunded_amount)`。这些值是累计的且
   严格递增，所以该键能把「同一事件重投」（该字段相同 → 去重）和「新的一笔部分退款」
   （递增 → 放行）区分开。数据库唯一索引也按这三列建。
2. **把你侧的已退总额推进到 `max(已记录, refunded_amount)`。** 既不要累加，也不要直接赋值：
   - **累加**：重投时会多退。
   - **直接赋值**：乱序时会回退。at-least-once **不保证顺序**，同一订单的投递之间也不保证
     串行——失败的投递会退避后重试，所以携带 `30` 的事件可能**晚于**携带 `50` 的到达。
     迟到的 `30` 不是重复（键不同，会被正确处理），直接赋值就会把总额从 50 退回 30。
   - **取 max**：既幂等（重投）又对乱序安全，所以这是唯一正确的做法。

   比较时按**十进制**比，不要用浮点，也不要用字符串——字典序下 `"9.90" > "10.00"` 为真。

   另外不要用 `amount` 算退款：那会把「1000 的订单退了 1」读成「退了 1000」。

没有独立的投递 ID 头可用（fluxa 只发 `X-Fluxa-Event`、`X-Fluxa-Timestamp`、
`X-Fluxa-Signature`、`X-Fluxa-Encryption`），所以上面的累计值语义是唯一正确的做法。
