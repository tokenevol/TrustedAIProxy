# TAP 客户验证指南：可信 AI HTTPS 响应证明

文档版本：1.8

签名协议版本：`trusted-ai-proxy-v1`

## 1. 客户验证的信任链

本服务运行在 Google Confidential Space 中。客户通过两层验证建立信任：

```text
Google Cloud Attestation
        │ 证明硬件、Confidential Space 和容器镜像
        ▼
经过证明绑定的 Ed25519 公钥
        │ 签名具体 HTTPS 交互中声明的 profile 语义
        ▼
非流式：api.openai.com + 上游证书指纹 + request path + model/request messages/response messages
流式：api.openai.com + 上游证书指纹 + request path + model/request messages/stream + response metadata + challenge
```

验证全部通过后，可以证明：客户批准的容器镜像运行在符合策略的 Google 机密计算环境中；该镜像通过正常的 HTTPS 证书链和域名校验连接到 `api.openai.com`，并使用经过 Google 证明绑定的 Ed25519 密钥，对 profile 声明的字段进行了签名。`llm-conversation-text-v1` 覆盖非流式请求和响应文本；`llm-request-upstream-v1` 只覆盖流式请求及上游响应 metadata，不覆盖流式响应 body。

这不表示上游 AI Provider 对这些文本进行了数字签名。最终证明由客户批准的可信 workload 生成，而不是由上游 Provider 直接生成。

## 2. MITM 代理不是客户接入面

MITM 代理及其 CA 只在服务内部使用：

```text
客户 ──正常 HTTPS──> 客户服务接口
                         │
                         ▼
                   内部业务模块
                         │ HTTP_PROXY / HTTPS_PROXY
                         ▼
                   TAP ──正常 HTTPS──> api.openai.com
```

因此客户：

- 不需要配置 `HTTP_PROXY` 或 `HTTPS_PROXY`；
- 不需要下载、安装或信任 MITM CA；
- 不需要验证 MITM CA 的生命周期；
- 只需要验证 Google attestation、绑定的 Ed25519 公钥和每条业务响应所声明 profile 的签名。

内部业务模块必须把证明 headers 和可重建对应 profile 语义的请求、响应交付给客户。中间网关可以转换协议外壳，但不能修改已签名字段。对于 `llm-request-upstream-v1`，中间网关仍然可以修改流式响应 body 而不破坏签名，因此客户必须把该 body 视为未证明内容。

## 3. 客户需要预先配置的信息

以下信息必须通过合同、客户门户或其他可信带外渠道提供，不能相信待验证响应中自报的值：

| 项目 | 期望值示例 |
|---|---|
| Google attestation issuer | `https://confidentialcomputing.googleapis.com` |
| Attestation audience | `tap/customer/v1` |
| 批准的容器镜像 digest | `sha256:...` |
| 批准的 GCP project ID / project number | 由服务方提供 |
| 批准的 workload service account | 由服务方提供 |
| 允许的硬件类型 | 例如 `GCP_AMD_SEV` 或 `GCP_INTEL_TDX` |
| 目标上游 API 域名 | `api.openai.com` |
| 响应签名算法 | `ed25519` |
| 签名协议版本 | `trusted-ai-proxy-v1` |
| 签名语义 profile | 非流式 `llm-conversation-text-v1`；流式请求 `llm-request-upstream-v1` |
| 请求 path 与协议提取器 | 由服务方提供，例如 `/v1/chat/completions` 对应 `openai-chat-conversation-v1` |

客户应把这些值固化为本地验证策略。

若客户策略要求硬件级测量根，可以要求 `GCP_INTEL_TDX`。实际可用机型和区域以 [Google Confidential VM supported configurations](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations) 为准。

## 4. 第一阶段：验证运行环境和内容签名公钥

此阶段通常在首次连接、workload 重启、Ed25519 公钥变化或客户会话建立时执行一次，不需要为每条 OpenAI 响应请求 Google token。每个 TAP 进程在内存中生成独立的 Ed25519 密钥；它先取得一次使用服务内部随机 nonce 的 startup workload attestation，成功后才开放监听端口。该启动证明只用于 fail-closed 门禁，不能代替本阶段由客户 challenge 绑定的证明。

### 4.1 生成一次性 Google proof challenge

challenge 必须为 10–74 个 URL-safe ASCII 字符，并且每次不同：

```sh
NONCE=$(openssl rand -hex 16)
```

客户必须在本地记录该 challenge，不能接受服务端代为生成的 challenge。

### 4.2 获取证明包

服务方应通过客户服务接口暴露证明端点，例如：

```sh
curl --fail --silent --show-error \
  "https://SERVICE_HOST/.well-known/confidential-attestation?nonce=${NONCE}" \
  -o confidential-attestation.json
```

证明包结构如下：

```json
{
  "token_type": "OIDC",
  "attestation_token": "GOOGLE_SIGNED_JWT",
  "audience": "tap/customer/v1",
  "key_id": "ed25519-<public-key-digest>",
  "challenge_nonce": "CUSTOMER_CHALLENGE",
  "proof_ref": "proof-BASE64URL_PUBLIC_KEY_HASH",
  "expires_at": 1700003600,
  "attestation_key": {
    "algorithm": "ed25519",
    "public_key": "BASE64URL_RAW_PUBLIC_KEY",
    "binding_nonce": "BASE64URL_SHA256_BINDING"
  }
}
```

客户应按 `proof_ref` 缓存已经验证的 proof，直到 `expires_at` 或公钥轮换；后续业务响应不再重复传输 `attestation_token`。每个进程启动都会生成新的公钥、`key_id` 和 `proof_ref`，同一实例重启后也必须视为新的签名身份。

推荐采用响应优先流程：客户先调用业务接口，从响应头读取 `X-Attestation-Proof-Ref`。如果本地还没有该引用对应的有效证明，则生成新的 challenge，并向同一服务域名请求：

```text
/.well-known/confidential-attestation?nonce=NEW_CHALLENGE&proof_ref=X_ATTESTATION_PROOF_REF
```

服务端启用 PostgreSQL 路由后，负载均衡器可以把这个请求交给任意副本。接收方会根据 `proof_ref` 找到在线 owner，由 owner 为这个新 challenge 签发证明，再通过共享数据库返回结果。客户必须确认返回包的 `proof_ref` 精确等于业务响应头中的值，并照常验证 challenge、公钥绑定和 Google token 中的实例策略。未启用 PostgreSQL 时服务端没有跨副本实时路由能力，客户必须命中 owner 或自行保存已经取得的证明包。

仓库提供的验证脚本可以执行这一步，但所有部署策略值都必须来自客户预先批准的带外配置，不能使用脚本中的示例占位值。多副本名称必须全部列入客户自己的允许策略：

```sh
python3 docs/get_attested_public_key.py \
  --attestation-url "https://SERVICE_HOST/.well-known/confidential-attestation" \
  --audience tap/customer/v1 \
  --proof-ref "$PROOF_REF" \
  --project-id APPROVED_PROJECT_ID \
  --project-number APPROVED_PROJECT_NUMBER \
  --zone APPROVED_ZONE \
  --allowed-instance-name tap-01 \
  --allowed-instance-name tap-02 \
  --service-account APPROVED_SERVICE_ACCOUNT \
  --image-digest "sha256:APPROVED_IMAGE_DIGEST" \
  --image-reference "APPROVED_IMAGE_REFERENCE@sha256:APPROVED_IMAGE_DIGEST" \
  --secret-version "projects/PROJECT_ID/secrets/tap-pg-dsn/versions/1" \
  --output-json
```

`--secret-version` 必须是固定编号版本，不能使用 `latest`。如果批准的部署明确不使用 PostgreSQL，应改传 `--without-postgres`。仍处于旧环境变量迁移期的部署可以显式传 `--secret-env-name TRUSTED_PROXY_PG_DSN_SECRET_VERSION`；新部署应使用默认的 `TAP_PG_DSN_SECRET_VERSION`。

启用 PostgreSQL 持久化后，如果客户需要重新取得一个已经签发的 proof，必须同时提交该 proof 的 `proof_ref` 和签发时使用的原始 challenge：

```text
/.well-known/confidential-attestation?nonce=ORIGINAL_CHALLENGE&proof_ref=PROOF_REF
```

代理会按 `(proof_ref, challenge_nonce)` 精确查询。数据库中的历史 proof 不会被刷新或覆盖，返回结果可能已经超过 `expires_at`；客户不能把历史记录当作新的实时证明。未知 `proof_ref` 返回 `404`，owner 不在线返回 `410`，路由签发超时或临时失败返回 `503`。持久化也不能为已经销毁且未针对该 challenge 签发过 proof 的副本事后生成证明。

证明包在 Google token 验证完成前完全不可信，不能提前接受其中的 Ed25519 公钥。

### 4.3 验证 Google OIDC token

1. 读取 Google 官方 OIDC discovery：

   ```text
   https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
   ```

2. 确认 discovery 的 `issuer` 精确等于 `https://confidentialcomputing.googleapis.com`。
3. 从 discovery 的 `jwks_uri` 获取 Google 验签公钥。
4. 根据 JWT header 的 `kid` 选择公钥，并只接受客户策略允许的签名算法。
5. 验证 JWT 签名后才能读取和使用 claims。

Google 会轮换 JWKS。客户可以缓存公钥，但遇到未知 `kid` 时必须刷新 JWKS，不能关闭签名验证。

至少检查以下 claims：

- `iss`、`aud` 和 token 有效时间符合预配置策略；
- `swname` 精确等于 `CONFIDENTIAL_SPACE`；
- `dbgstat` 精确等于 `disabled-since-boot`；
- `secboot` 为 `true`；
- `hwmodel` 位于客户允许列表；
- `submods.container.image_digest` 精确等于客户批准的不可变镜像 digest；
- `image_reference`、`args`、`cmd_override` 和 `env_override` 符合客户策略；
- GCP project、实例身份和 `google_service_accounts` 符合客户批准的运营方；
- Confidential Space support attributes 满足客户策略；
- `eat_nonce` 包含客户 challenge 和下面定义的公钥绑定值。

任何一项不符合都必须终止验证。

当前仓库 Dockerfile 会把仓库内的 Demo MITM CA 证书及其私钥复制进镜像，但不会包含或持久化 Ed25519 签名私钥。由该 Dockerfile 直接构建的镜像只能用于开发验证，不能作为生产批准镜像。生产构建必须先改为通过受控的 Secret Manager/KMS bootstrap 提供专用 MITM CA，再由客户批准新的不可变 digest。

签名规则优先从进程工作目录的相对路径 `signing-rules.json` 加载；仅当该文件不存在时，才回退到镜像内的 `/etc/tap/signing-rules.json`，且不接受 CLI 路径覆盖。相对文件存在但内容非法时必须 fail closed，不能回退。生产容器的 `/data` 工作目录不得注入同名规则文件；规则变化必须构建并重新批准新的不可变镜像 digest，客户对 attestation 中容器参数和挂载的允许策略也不得接受额外规则来源。

### 4.4 验证 Ed25519 公钥绑定

将 `attestation_key.public_key` 按无 padding 的 base64url 解码，结果必须恰好为 32 字节。然后重新计算：

```text
key_binding = base64url_no_padding(
  SHA256(
    UTF8("attestation-ed25519-public-key-v1") ||
    0x00 ||
    raw_32_byte_ed25519_public_key
  )
)
```

必须同时确认：

- `challenge_nonce` 等于客户刚生成的 challenge；
- `attestation_key.algorithm` 等于 `ed25519`；
- `attestation_key.binding_nonce` 等于重新计算的 `key_binding`；
- Google token 的 `eat_nonce` 包含 challenge 和 `key_binding`。

完成以上检查后，客户才可以把该 Ed25519 公钥用于验证业务响应。

## 5. 第二阶段：验证每一条业务响应

客户通过服务方提供的正常 HTTPS API 发起请求，不直接连接内部代理。服务方必须通过可信带外渠道提供每个请求 path 对应的协议提取器。提取器把不同上游格式归一成 `model` 和请求、响应各自的有序 `messages` 数组。每条消息固定为 `{"role":"...","text":"..."}`。当前版本只支持纯文本请求消息；图片、工具调用等无法安全归一化的消息不会生成证明 headers。响应中的非文本 output item 或内容块不属于本 profile，只按顺序提取其中的文本消息。任何失败都不能静默降级为已证明响应。

服务方必须原样透传证明 headers。中间层可以转换请求或响应的协议外壳，但客户重建出的 profile 字段必须与代理签名时的归一化结果完全一致。当前版本不签名 SSE、AWS EventStream 等流式响应 body；符合 5.5 节条件的 SSE 请求可以获得独立的 request-upstream attestation。

规范化不会把 `developer` 自动等同于 `system`，也不会合并相邻消息。若内部转换层新增了客户不可见的 system prompt，服务方必须向客户提供对应的规范化消息，否则客户无法重建和验证本 profile 的签名载荷。

### 5.1 必需 headers

```text
X-Attestation-Algorithm: ed25519
X-Attestation-Profile: llm-conversation-text-v1
X-Attestation-Key-Id: ed25519-<public-key-digest>
X-Attestation-Domain: api.openai.com
X-Attestation-Path: /v1/chat/completions
X-Attestation-Model: <实际上游模型>
X-Attestation-Certificate-SHA256: <64位小写hex>
X-Attestation-Timestamp: <Unix秒>
X-Attestation-Nonce: <base64url>
X-Attestation-Signed-Fields: tls_certificate_sha256,domain,request.path,request.body.model,request.body.messages,response.body.messages
X-Attestation-Signature: <base64url Ed25519 signature>
X-Attestation-Proof-Ref: proof-<base64url public-key hash>
```

缺少任何必需 header 都应视为未证明响应，不能静默降级。

验签方应使用 `X-Attestation-Path` 和 `X-Attestation-Model` 重建签名载荷，以兼容内部调用链对路径和模型名的改写。Ed25519 验签成功后，这两个值才能被视为代理实际观察到的 path/model。

`X-Attestation-Key-Id` 只是密钥轮换标签。真正的信任依据是上一阶段经过 Google token 绑定的 Ed25519 公钥，不能只根据 key ID 信任新公钥。

`X-Attestation-Proof-Ref` 只是 proof 缓存索引，不是信任根。客户必须使用该引用找到已验证的 proof，并确认 proof 中的公钥与用于验签的公钥一致。

`X-Attestation-Key-Id` 始终由当前进程公钥的摘要生成，不接受人工覆盖；客户仍不能只根据 key ID 信任公钥。

### 5.2 检查固定字段和防重放信息

- algorithm 必须为 `ed25519`；
- domain 必须精确匹配本地策略中的 `api.openai.com`；
- path header 必须用来重建签名载荷；路由准入策略应在验签成功后单独执行；
- model header 存在时必须用它重建签名载荷；模型准入策略应在验签成功后单独执行；
- profile 必须为本地策略允许的 `llm-conversation-text-v1`；
- signed-fields 必须精确等于 `llm-conversation-text-v1` 定义的字段及顺序；
- timestamp 不能晚于当前时间 30 秒以上，也不能超过客户设置的最大有效窗口；
- nonce 必须是在有效窗口内从未消费过的值。

验签成功后再把 nonce 写入短期已消费缓存。

仓库中的 `docs/verify_response.py` 是 OpenAI Chat Completions 单用户文本请求的参考客户端。它会把命令行传入的 model 和允许的上游 path 作为本地策略，并在签名验证成功后把 nonce 原子写入持久化 SQLite 缓存。参考脚本不会自动删除已消费 nonce；生产系统只能在记录已经超过自身允许的最大重放窗口后进行维护清理：

```sh
python3 docs/verify_response.py \
  --base-url "https://SERVICE_HOST/v1" \
  --model APPROVED_MODEL \
  --prompt "你好" \
  --expected-domain api.openai.com \
  --expected-path /v1/chat/completions \
  --nonce-cache "$HOME/.cache/trusted-ai-proxy/consumed-nonces.sqlite3"
```

`--base-url` 是客户访问的服务地址，`--expected-domain` 和 `--expected-path` 是 TAP 实际上游的带外允许策略，两者不一定属于同一域名。其他协议或多消息请求需要按照对应提取器重建完整消息数组，不能套用这个单消息示例。

### 5.3 重建签名载荷

签名载荷使用 [RFC 8785 JSON Canonicalization Scheme（JCS）](https://www.rfc-editor.org/rfc/rfc8785.html) 生成，是无缩进、无尾部换行的 UTF-8 JSON。以下是规范化后的完整示例：

```json
{"domain":"api.openai.com","key_id":"HEADER_KEY_ID","nonce":"HEADER_NONCE","profile":"llm-conversation-text-v1","request_fields":[{"name":"model","value":"ACTUAL_MODEL"},{"name":"messages","value":[{"role":"system","text":"SYSTEM_TEXT"},{"role":"user","text":"USER_TEXT"}]}],"request_path":"/v1/chat/completions","response_fields":[{"name":"messages","value":[{"role":"assistant","text":"OUTPUT_TEXT"}]}],"timestamp":1700000000,"tls_certificate_sha256":"LOWERCASE_HEX","version":"trusted-ai-proxy-v1"}
```

其中：

- 验签方先按示例中的字段名和 JSON 类型构建 Claims 对象，再对整个对象执行 RFC 8785 JCS；不依赖编程语言对象或 map 的插入顺序；
- `request_path` 是不含 query string 的 URL path；
- `request_fields` 固定为 `model`、`messages`，`response_fields` 固定为 `messages`；这些是稳定语义字段名，不是配置路径表达式；
- 每条规范化消息保留 `role`、消息顺序和消息边界；同一消息内的多个文本块按顺序拼入一个 `text` 字符串；
- 字段值保留 JSON 类型。所有对象属性递归按 UTF-16 code unit 排序，数组元素顺序保持不变；
- 字符串和数字必须按 JCS 规定的 ECMAScript 规则序列化；不能用普通的 `json.dumps(sort_keys=True)` 或类似方法代替 JCS；
- 输入必须符合 I-JSON：对象不能有重复属性名，字符串必须是有效 Unicode，数字按 IEEE 754 双精度语义处理；整数字面量必须位于 `[-(2^53-1), 2^53-1]`，需要保留更高精度的数值应作为 JSON 字符串传递；
- domain 使用客户本地策略值，不能直接信任 header；
- domain 和证书指纹转换为小写；
- timestamp 是 JSON 整数；

例如 Python 验签程序可以使用符合 RFC 8785 的实现，在重建 `claims` 后生成待验签字节：

```python
import rfc8785

payload = rfc8785.dumps(claims)
```

`llm-conversation-text-v1` 不覆盖 HTTP method、query string、状态码和未配置的 JSON 字段。客户不能把未列入 `X-Attestation-Signed-Fields` 的内容当作已证明数据。

### 5.4 执行 Ed25519 验签

1. 将 `X-Attestation-Signature` 按无 padding 的 base64url 解码，结果应为 64 字节；
2. 使用第一阶段验证并绑定的 32 字节 Ed25519 公钥；
3. 对重建的 UTF-8 payload 执行 Ed25519 verify；
4. 所有策略检查和签名检查成功后，才接受配置的响应字段。

### 5.5 验证流式请求的上游证明

`llm-request-upstream-v1` 是 request-upstream attestation，不是流式响应内容签名。客户必须为每次业务请求生成新的 10–74 位 URL-safe ASCII challenge，并由服务方把它作为内部上游请求 header 传递给 TAP：

```text
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
```

TAP 在转发给模型厂商之前移除该 header。缺失、重复或非法 challenge、请求 JSON 的 `stream` 不严格等于布尔值 `true`、请求字段不能完整提取，或者上游 TLS 验证无效时，TAP 必须正常透传但不生成证明 headers。

对于支持的 SSE 路径，客户必须取得并检查以下 headers：

```text
X-Attestation-Algorithm: ed25519
X-Attestation-Profile: llm-request-upstream-v1
X-Attestation-Key-Id: ed25519-<public-key-digest>
X-Attestation-Domain: api.openai.com
X-Attestation-Path: /v1/chat/completions
X-Attestation-Model: <实际上游模型>
X-Attestation-Certificate-SHA256: <64位小写hex>
X-Attestation-Timestamp: <Unix秒>
X-Attestation-Nonce: <base64url>
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
X-Attestation-Response-Status: 200
X-Attestation-Response-Content-Type: text/event-stream
X-Attestation-Signed-Fields: tls_certificate_sha256,domain,request.path,request.body.model,request.body.messages,request.body.stream,response.status,response.content_type,challenge
X-Attestation-Signature: <base64url Ed25519 signature>
X-Attestation-Proof-Ref: proof-<base64url public-key hash>
```

客户必须确认回显 challenge 与本次请求完全相同，响应状态码和去除参数后的规范化 Content-Type 与实际响应一致，并使用本地允许策略检查 domain、path 和 model。`request_fields` 固定为 `model`、`messages`、`stream`，其中 `stream` 必须是 JSON 布尔值 `true`；`response_fields` 固定为空数组。完整 JCS payload 形状为：

```json
{"challenge":"CUSTOMER_UNIQUE_CHALLENGE","domain":"api.openai.com","key_id":"HEADER_KEY_ID","nonce":"HEADER_NONCE","profile":"llm-request-upstream-v1","request_fields":[{"name":"model","value":"ACTUAL_MODEL"},{"name":"messages","value":[{"role":"user","text":"PROMPT"}]},{"name":"stream","value":true}],"request_path":"/v1/chat/completions","response_content_type":"text/event-stream","response_fields":[],"response_status":200,"timestamp":1700000000,"tls_certificate_sha256":"LOWERCASE_HEX","version":"trusted-ai-proxy-v1"}
```

验签成功只证明受信 workload 观察到这些请求字段，并在已验证的上游 TLS 连接上收到相应 response metadata。它不证明任何 SSE event、响应文本、事件顺序或终止状态。服务方能够丢弃真实上游 body 并替换整个流而不导致该 profile 验签失败；客户界面和审计记录必须明确标注“请求及上游已证明，响应 body 未证明”。

本地参考客户端可以在读取 SSE body 前完成该 profile 的验签：

```sh
go run ./cmd/tap-verify \
  -stream \
  -challenge "$(openssl rand -hex 16)" \
  -public-key 'BASE64URL_PUBLIC_KEY' \
  -expected-domain api.openai.com \
  https://api.openai.com/v1/chat/completions
```

## 6. 上游证书指纹的含义

`X-Attestation-Certificate-SHA256` 是可信 workload 与 OpenAI 建立 HTTPS 连接时观察到的上游叶子证书 DER SHA-256，并已包含在 Ed25519 签名中。

它不能单独证明内容来自 OpenAI：OpenAI 或 CDN 可能合法轮换证书，不同区域也可能使用不同叶子证书。客户主要依赖的是批准的代码执行系统信任链校验、SNI/hostname 校验，以及对签名中 `domain` 的本地策略校验。代理本身不限制上游域名。

若客户要求 certificate pinning，应通过可信渠道维护允许的指纹集合，并准备证书轮换和紧急更新流程。

## 7. 必须拒绝的情况

出现以下任一情况时必须拒绝证明或响应：

- Google token 的签名、issuer、audience 或时间校验失败；
- Google proof challenge 或业务请求 challenge 不匹配、格式无效或已经使用；
- Ed25519 公钥绑定不匹配；
- 镜像 digest、GCP 项目、服务账号、debug 状态或硬件策略不符合预配置值；
- Ed25519 公钥变化后未重新完成 Google attestation；
- 响应缺少必需证明 headers；
- domain、profile 或 signed-fields 不符合本地策略；
- timestamp 超窗或 nonce 重复；
- 请求 path 不符合本地策略；conversation text profile 的请求/响应 body 不是有效 JSON，或 request-upstream profile 的请求 body 不是有效 JSON；
- Ed25519 签名验证失败。

不要采用“验证失败时继续使用响应”的降级策略。

## 8. 生命周期

以下事件发生时应重新执行环境和公钥证明：

- workload 重启或 Ed25519 公钥变化；
- Google attestation token 已过期；
- 客户会话超过自身设定的证明有效期；
- 批准的镜像 digest、GCP 项目或硬件策略发生变化；
- 客户怀疑密钥、网络或运行环境受到影响。

MITM CA 的生成、分发和轮换属于服务方内部运维，不触发客户侧证书更新，也不属于客户验证协议。

进程退出会销毁其临时 Ed25519 私钥。已经持久化的 challenge-bound proof 和对应公钥仍可用于历史验证，但任何副本都不能为已销毁的 `proof_ref` 签发新的 challenge。客户收到未知 `proof_ref` 后应尽快取得并保存证明包。

## 9. 官方参考资料

- [Google Cloud Attestation](https://docs.cloud.google.com/confidential-computing/docs/attestation)
- [Confidential Space attestation token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [访问外部资源及验证 attestation token](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)
- [Confidential VM remote attestation overview](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation-overview)
