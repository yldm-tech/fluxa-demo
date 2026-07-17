# fluxa 支付对接 demo

[fluxa](https://pay.fluxa.cash) 商户 API 的多语言接入示例，共 8 种语言。
把 `.env.example` 复制成 `.env`，填三个密钥，就能跑。

**English: [README.md](README.md)** · 用 AI 接入？把 [AGENTS.md](AGENTS.md) 丢给它。

每份 demo 都做同样三件事：

1. **签名**调用商户 API（HMAC-SHA256）
2. **创建收款**并按付款指引引导用户
3. **接收 webhook**：验签 → 解密（可选）→ 幂等处理

---

## 快速开始

```bash
cp .env.example .env
$EDITOR .env    # 填 FLUXA_KEY_ID、FLUXA_SECRET、FLUXA_WEBHOOK_SECRET
```

这三个值从商户门户拿：**https://pay.fluxa.cash/portal** → Developers → API Keys → New Key。
建议先选 **Test** 模式：测试订单不动真钱，但**照样推 webhook**，整条链路都能安全跑通。
secret 只显示一次。

然后挑一种语言：

| 语言 | 下单 | 收 webhook | 跑测试 | 依赖 |
| --- | --- | --- | --- | --- |
| **Node.js** | `cd node && npm run charge` | `npm run webhook` | `npm test` | 无（Node ≥18） |
| **Python** | `cd python && python3 src/charge.py` | `python3 src/webhook.py` | `python3 -m unittest discover -s test` | 无（Python ≥3.9）※ |
| **Go** | `cd go && go run ./cmd/charge` | `go run ./cmd/webhook` | `go test ./...` | 无（Go ≥1.21） |
| **Java** | `cd java && mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo` | `… -Dexec.mainClass=cash.fluxa.demo.WebhookDemo` | `mvn test` | Maven + Jackson（JDK 17） |
| **PHP** | `cd php && php src/charge.php` | `php -S 0.0.0.0:9000 src/webhook.php` | `php test/vectors_test.php` | 无（PHP ≥8.1） |
| **Ruby** | `cd ruby && ruby lib/charge.rb` | `ruby lib/webhook.rb` | `ruby test/vectors_test.rb` | 无 ※ |
| **Rust** | `cd rust && cargo run --bin charge` | `cargo run --bin webhook` | `cargo test` | 少量 crate（Rust 1.85+） |
| **C# / .NET** | `cd dotnet && dotnet run --project FluxaDemo -- charge` | `dotnet run --project FluxaDemo -- webhook` | `dotnet test` | 无（.NET 8） |

※ **仅加密 webhook 需要**（`WEBHOOK_ENCRYPTION`，默认关闭）。签名、下单、明文回调都不受影响：
> - **Python** 需 `pip install cryptography`——标准库没有 AES。
> - **Ruby** 需链接 **OpenSSL** 的 Ruby（版本不限）。macOS 系统自带的 ruby 链接的是
>   **LibreSSL**，它完全不支持 AES-256-GCM。这与 Ruby 版本无关：同一份代码在
>   `ruby:2.6-slim`（2.6 + OpenSSL）上全过。用 rbenv/homebrew 装的 ruby 或 `ruby:3.3` 镜像即可。

各语言目录下有自己的 README，含详细说明和「本机没装该运行时」时的 Docker 跑法。

一键复验全部语言——不需要 `.env`，也不需要跑着的服务，本机缺的运行时自动用 Docker 补：

```bash
./verify-all.sh            # 全部
./verify-all.sh node go    # 只跑指定的
```

---

## 签名契约

完整规范：**[`spec/SIGNING.md`](spec/SIGNING.md)**。已知答案向量：**[`spec/vectors.json`](spec/vectors.json)**，
由 fluxa 服务端真实代码生成。

请求带三个头 `X-Api-Key`、`X-Timestamp`、`X-Signature`，其中

```
X-Signature = hex(HMAC_SHA256(secret, canonical))
```

`canonical` 是 **5 行**，用 `\n` 连接：

```
METHOD
PATH
CANONICAL_QUERY      ← 没有 query 时是空字符串，但这一行必须在
TIMESTAMP
SHA256_HEX(BODY)
```

> **最费时间的两个错误**
>
> 1. **无 query 时把那个空行省掉**。变成 4 行后 HMAC 完全不同，**所有**请求都会
>    `401 bad_signature`，不只是带 query 的。
> 2. **签名的字节和发送的字节不是同一份**。body 只序列化一次，签它、发它。
>    序列化两次会改变键顺序或空格，签名就废了。

### Webhook 验签

```
X-Fluxa-Signature = hex(HMAC_SHA256(webhook_secret, "<X-Fluxa-Timestamp>.<原始body>"))
```

必须用**原始接收字节**验签（反序列化再序列化的结果对不上），用常量时间比较，并校验时间戳新鲜度。
开启加密时 body 是 AES-256-GCM 信封——**先验签、再解密**，密钥是 `SHA256(webhook_secret)`。

> **部分退款做错会赔钱。** 一笔订单可以被多次部分退款，每次都推一个 `payment.refunded`。
> 两个坑，都是静默的：
>
> 1. `(event, order_id)` **不是**唯一的事件标识。用它去重，第二笔部分退款会被当成「重复」
>    丢弃并返回 `2xx`——fluxa 认为投递成功、永不重试。幂等键要用
>    `(event, order_id, refunded_amount)`。
> 2. `refunded_amount` 是**累计**值，而投递**无序**——携带 `30` 的重试事件可能晚于携带 `50` 的
>    到达。所以要把已退总额推进到 `max(已记录, refunded_amount)`：累加会在重投时多退，
>    直接赋值会把 50 退回 30。
>
> 详细示例见 [`spec/SIGNING.md` §3.1](spec/SIGNING.md)。

---

## 为什么每种语言都带一个 vectors 测试

跨语言移植 HMAC 最典型的失败是**静默不一致**：代码能跑、签名也算得出来，直到服务端拒绝才发现。
常见的坑：

- 无 query 时漏掉 canonical 的空行（4 行 vs 5 行）
- 用语言默认比较器排序 query——C# 默认是 **culture-sensitive**、JS 和 Java 是 **UTF-16**，
  而服务端按 **UTF-8 字节序**
- 签名一份字节、发送另一份（序列化了两次）
- 把金额解析成浮点。`9.99` 单看没问题，但误差会累积——累加 100 次得到 `999.0000000000007` 而非 `999`
- webhook 按 `(event, order_id)` 去重，丢掉部分退款

`spec/vectors.json` 由 fluxa 真实签名代码生成，每种语言的测试都逐字节复现它。
**这就是判定移植正确的唯一标准**——不需要跑着的服务器，也不依赖任何人对文档的理解。

这些测试做过变异检验：把 canonical 改成 4 行、或换成 UTF-16 比较器，它们会立刻失败。
详见 [`spec/README.md`](spec/README.md)。

---

## 跑通完整流程

```bash
# 1. 下单
cd node && npm run charge

# 2. 打开输出里的 redirect_url。mock 渠道的收银台页面有「模拟支付成功」按钮，
#    点了订单就变 paid 并触发 webhook。

# 3. 收 webhook —— 先在门户里登记你的回调地址
#    （Portal → Developers → Webhooks）
npm run webhook
```

本地接收服务公网不可达，用内网穿透（ngrok、Cloudflare Tunnel）拿一个公网地址登记为回调地址。

### 排障

**`401 bad_signature`** —— canonical 串不对。检查那个空的第三行、检查签名的字节是否与发送的一致、
检查 `X-Timestamp` 是否与签名时用的一致。先跑本语言的测试：向量过了就说明签名实现没问题，
问题在别处。

**`400 channel_environment_mismatch`** —— `FLUXA_CHANNEL` 和密钥模式不匹配。Test 密钥要配
test 环境的渠道（如 `mock`），Live 密钥要配 live 的。**这不是签名问题**。
用签名过的 `GET /api/v1/channels` 看你的账号能用哪些。

**`401 replayed_request`** —— 验证过的签名在时钟偏移窗口内一次性使用。同一秒发两个完全相同的
请求会算出相同签名。换个时间戳或改一下 body。

**收不到 webhook** —— 确认回调地址公网可达且已在门户登记，且同一时间只有一个语言的接收端
占用 `WEBHOOK_PORT`。

**在 Docker 里跑 demo** —— 容器里的 `localhost` 是容器自己。指向托管 API：
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`。

---

## 目录

```
.env.example        所有语言共用的唯一配置文件
AGENTS.md           给 AI 编码 agent 的接入契约
spec/
  SIGNING.md        签名契约
  vectors.json      由 fluxa 真实签名代码生成的已知答案向量
  README.md         向量覆盖了什么、为什么
verify-all.sh       跑全部语言的向量测试
node/ python/ go/ java/ php/ ruby/ rust/ dotnet/
```

## 链接

- 商户门户：https://pay.fluxa.cash/portal
- 文档：https://docs.fluxa.cash

## 授权

[MIT](LICENSE)——这里的代码随便抄进你自己的项目。
