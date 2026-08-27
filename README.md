# TrustedAIProxy

> 面向 New API、One API 等 AI 中转站的可信代理签名服务——用可验证的密码学证据，证明你的 API 没有掺假！

用户通过中转站调用大模型时，HTTPS 只能证明“用户连接到了中转站”，无法证明中转站是否换了模型、修改了提示词，或改写了模型回复。

TrustedAIProxy 部署在中转站与模型厂商之间。它记录自己实际看到的上游域名、模型、请求文本和响应文本，并用运行在 Google Confidential Space 中的密钥签名。用户验证签名和运行环境证明后，就能判断自己发送和收到的内容是否与可信代理看到的一致。

可以把它理解成安装在中转站出口处的“电子封条”：请求和回复只要被改过，用户验签时就会发现。

面向最终用户的完整验签流程见：[客户验证指南](docs/customer-verification-guide.md)。

## 它解决什么问题？

假设用户向中转站发送：

```text
模型：gpt-example
问题：北京今天天气怎么样？
```

普通中转只能要求用户“相信平台没有修改请求和回复”。接入 TrustedAIProxy 后，用户可以自行验证：

- 请求最终发给了哪个上游域名；
- 使用了哪个模型和 API 路径；
- 中转站有没有增加、删除、调换或修改文本消息；
- 返回给用户的文本是否与可信代理从上游收到的一致；
- 签名是否来自经过批准的 Confidential Space 镜像，而不是中转站临时伪造的程序。

一句话概括：**中转站负责转发，TrustedAIProxy 负责留下可验证的“原始收发凭证”。**

## 工作原理

```text
用户
  │ 发送请求、接收响应和证明 headers
  ▼
New API / One API 等中转站
  │ HTTP_PROXY / HTTPS_PROXY
  ▼
TrustedAIProxy（Confidential Space）
  │ 观察并签名请求与响应
  ▼
OpenAI / Anthropic / Azure OpenAI / AWS Bedrock 等上游
```

一次请求大致经过四步：

1. 中转站把上游请求交给 TrustedAIProxy。
2. TrustedAIProxy 正常校验上游 HTTPS 证书，并转发请求。
3. 上游返回结果后，TrustedAIProxy 对关键内容生成 Ed25519 签名，并把证明放进响应 headers。
4. 中转站把原始业务内容和证明 headers 一起返回给用户；用户独立验签。

客户不需要连接代理、不需要安装 MITM CA，也不需要相信中转站提供的公钥。每个 TAP 进程启动时在内存中生成独立的 Ed25519 密钥，并在开放监听端口前取得与该公钥绑定的 Google Confidential Space attestation；失败则终止启动。客户信任的是由 Google attestation 绑定到已批准镜像的临时签名公钥。

## 能证明什么，不能证明什么？

非流式 `llm-conversation-text-v1` 签名覆盖：

- 上游 HTTPS 叶子证书 SHA-256 指纹；
- 上游域名和请求 URL path；
- 实际模型；
- 请求和响应中的纯文本消息，包括角色、顺序、消息边界和文本；
- 时间戳和防重放 nonce。

当前不覆盖：

- 图片、文件、音频、工具定义、工具调用、推理过程、引用和 usage；
- HTTP method、query string、状态码和未纳入该签名 profile 的其他字段；
- SSE、AWS EventStream 等流式响应 body；
- 模型厂商内部如何生成答案，以及中转站的计费、可用性等业务行为。

对于带有合法 `X-Attestation-Challenge` 且请求 JSON 中 `stream` 为 `true` 的 SSE 请求，TAP 可以在首个响应 body 字节之前生成 `llm-request-upstream-v1` 证明。它覆盖上游域名、证书、请求 path、规范化的 `model`/`messages`、`stream:true`、响应状态码、规范化 Content-Type 和客户 challenge，但**不覆盖任何流式响应事件或文本**。中转站可以修改或替换整个流而不导致该 profile 验签失败，客户不能把它解释为响应内容证明。

因此，“没有掺假”准确地说是：**用户能够验证受签名保护的请求与响应内容，没有在 TrustedAIProxy 前后被静默篡改。** 不在签名范围内的字段不能据此得到证明。

## 支持的接口

| 接口类型 | 提取器 |
| --- | --- |
| OpenAI Chat Completions | `openai-chat-conversation-v1` |
| OpenAI Responses | `openai-responses-conversation-v1` |
| Anthropic Messages | `anthropic-messages-conversation-v1` |
| AWS Bedrock Invoke | `bedrock-invoke-conversation-v1` |
| AWS Bedrock Converse | `bedrock-converse-conversation-v1` |

Azure OpenAI 等把模型或 deployment 放在 URL path 中的兼容接口也可以配置。不同协议会被归一化成统一的 `llm-conversation-text-v1` 格式，以便用户重建同一份签名载荷。OpenAI Chat Completions、OpenAI Responses 和 Anthropic Messages 的 `stream:true` JSON 请求也可以生成 `llm-request-upstream-v1`；当前 Bedrock 流式路径仍只透传、不签名。

这些接口规则已经随项目内置并由服务维护方统一更新。运行时优先从当前工作目录读取相对路径 `signing-rules.json`，文件不存在时再读取镜像内固定路径 `/etc/tap/signing-rules.json`，不接受 CLI 路径覆盖。从仓库根目录本地运行时可以直接使用仓库文件；若相对路径文件存在但内容非法，TAP 会直接失败，不会静默降级到固定路径。规则变化必须进入新镜像并产生新的不可变 digest。

## 构建与运行

### 1. 本地检查

本地可以运行完整测试：

```sh
go test ./...
python3 -B -m unittest discover -s docs -p 'test_*.py'
go vet ./...
```

`tap` 运行时必须连接 Confidential Space launcher。它会在内存中生成新的 Ed25519 密钥，并在监听前请求一次启动 attestation；普通本地环境没有 launcher，因此会按设计启动失败。测试通过 fake token provider 覆盖这条流程，不提供跳过 attestation 的运行参数。

### 2. 在 Confidential Space 中启动

使用本仓库的部署模板，并始终指定不可变镜像 digest：

```sh
cp deploy/confidential-space.example.sh deploy/confidential-space.sh
# 设置 IMAGE、项目、区域、实例和 service account
bash deploy/confidential-space.sh
```

每次进程启动都会生成新的 `key_id` 和 `proof_ref`；私钥不读取、不写入任何 PEM 文件。启动 attestation 使用服务内部随机 nonce，只充当 fail-closed 门禁，不能代替客户自己的 proof challenge。

### 3. 让中转站的上游流量经过代理

在 New API、One API 或其他中转服务的运行环境中设置：

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY=127.0.0.1,localhost
```

还需要把 TrustedAIProxy 的内部 CA 证书加入中转服务的系统或应用 trust store。不要关闭 TLS 校验。不同中转项目可能使用自定义 HTTP client，部署后应确认真实上游请求确实经过代理。

推荐把 TrustedAIProxy 作为 sidecar 或独立的内部服务运行，只允许中转站访问其代理端口。

### 4. 检查签名结果

文本请求和响应成功解析后，响应会包含：

```text
X-Attestation-Algorithm: ed25519
X-Attestation-Profile: llm-conversation-text-v1
X-Attestation-Key-Id: ed25519-...
X-Attestation-Domain: api.example.com
X-Attestation-Path: /v1/chat/completions
X-Attestation-Model: model-name
X-Attestation-Certificate-SHA256: ...
X-Attestation-Timestamp: ...
X-Attestation-Nonce: ...
X-Attestation-Signed-Fields: ...
X-Attestation-Signature: ...
X-Attestation-Proof-Ref: proof-...
```

中转站必须把这些 headers 原样返回给用户。响应 body 不会被 TrustedAIProxy 修改，输入和输出消息也不会复制到 headers 中。

流式请求必须由客户生成 10–74 位 URL-safe ASCII challenge，由中转站在上游请求中传递：

```text
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
```

TAP 会在发送给模型厂商前移除该内部 header。若上游返回 SSE，响应 headers 使用 `llm-request-upstream-v1`，并额外包含：

```text
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
X-Attestation-Response-Status: 200
X-Attestation-Response-Content-Type: text/event-stream
```

缺失、重复或非法 challenge 时，流仍会正常透传，但不会生成证明 headers。

内部诊断可以读取当前进程的公钥：

```sh
curl http://127.0.0.1:8080/.well-known/http-attestation-key
```

仓库统一使用 Python 参考客户端完成端到端验签。它通过正常的客户服务地址发起 OpenAI Chat Completions 请求，并在验签成功后把 nonce 写入本地 SQLite 防重放缓存：

```sh
OPENAI_API_KEY='API_KEY' \
ATTESTATION_PUBLIC_KEY='BASE64URL_PUBLIC_KEY' \
python3 docs/verify_response.py \
  --base-url 'https://SERVICE_HOST/v1' \
  --model APPROVED_MODEL \
  --expected-domain api.example.com \
  --expected-path /v1/chat/completions \
  --prompt hello
```

流式 request-upstream profile 的诊断方式：

```sh
OPENAI_API_KEY='API_KEY' \
ATTESTATION_PUBLIC_KEY='BASE64URL_PUBLIC_KEY' \
python3 docs/verify_response.py \
  --stream \
  --challenge "$(openssl rand -hex 16)" \
  --base-url 'https://SERVICE_HOST/v1' \
  --model APPROVED_MODEL \
  --expected-domain api.example.com \
  --expected-path /v1/chat/completions \
  --prompt hello
```

该命令在读取 SSE body 前验证 request-upstream 签名，并明确输出 `response_body=unverified`。

## 用户如何验证？

签名公钥本身也需要证明来源，否则中转站完全可以自己生成一把密钥。TrustedAIProxy 使用 Google Confidential Space attestation 解决这个问题。

用户先生成一次性 challenge，再通过中转站提供的客户接口取得证明包：

```sh
NONCE=$(openssl rand -hex 16)
curl "https://SERVICE_HOST/.well-known/confidential-attestation?nonce=${NONCE}"
```

用户需要验证：

1. Google attestation token 的签名、issuer、audience 和有效时间；
2. token 是否绑定了本次 challenge 和 Ed25519 公钥；
3. workload 是否运行在批准的 Confidential Space 环境和镜像 digest 中；
4. 每条 API 响应的内容签名、时间戳和 nonce。

Google attestation 不需要每次请求都调用。用户可以按 workload 启动周期或会话验证一次环境证明，再通过 `X-Attestation-Proof-Ref` 关联每条业务响应。

参考实现和更完整的验证策略见：[客户验证指南](docs/customer-verification-guide.md) 与 [`docs/get_attested_public_key.py`](docs/get_attested_public_key.py)。

## 多副本与证明持久化

默认情况下，服务不连接数据库，也不保留历史证明。多副本生产部署建议使用 PostgreSQL：每个运行中的进程注册自己的 `proof_ref`，任意副本都能把新的证明请求路由到仍持有对应内存私钥的 owner，负载均衡器不需要会话亲和。

进程退出后，其临时私钥不可恢复。PostgreSQL 可以保存已经针对特定客户 challenge 签发的历史 proof，但不能为已退出进程补签一个新的 challenge。客户应在收到未知 `proof_ref` 的业务响应后尽快获取并保存证明包。

本地可以直接设置 DSN：

```sh
export TAP_PG_DSN='postgres://tap:PASSWORD@postgres.internal:5432/tap?sslmode=verify-full'
```

Confidential Space 生产环境应把完整 DSN 存入 Secret Manager，只传入固定版本的资源名：

```sh
export TAP_PG_DSN_SECRET_VERSION='projects/PROJECT_ID/secrets/tap-pg-dsn/versions/1'
```

不要使用 `latest`，也不要把数据库密码写入镜像、Git、实例 metadata 或命令行。程序会自动创建或迁移 `attestation_proofs`、`attestation_replicas` 和 `attestation_requests` 表。

## 镜像构建与发布

GitHub Actions workflow 位于 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)。在分支上手动触发后，它会运行测试和 `go vet`，然后使用 `GITHUB_TOKEN` 把镜像发布到：

```text
ghcr.io/tokenevol/trustedaiproxy
```

无需配置 GCP Artifact Registry 凭据。每次发布使用 `<分支名>-<短 commit hash>` tag，并在 workflow Summary 中输出不可变的 `image@sha256:...` 引用。

首次发布后，需要把 GHCR package 可见性设置为 **Public**，Confidential Space 才能匿名拉取。公开镜像中绝不能包含生产 secret。

本地构建和推送：

```sh
docker build -t ghcr.io/OWNER/REPOSITORY:VERSION .
docker push ghcr.io/OWNER/REPOSITORY:VERSION
```

部署时必须使用不可变 digest，不能使用 `latest`：

```sh
cp deploy/confidential-space.example.sh deploy/confidential-space.sh
# 把 IMAGE 改成 ghcr.io/OWNER/REPOSITORY@sha256:...
bash deploy/confidential-space.sh
```

## 网站与 GitHub Pages

产品网站位于 [`website/`](website/)，是无需构建步骤的静态站点。[`.github/workflows/pages.yml`](.github/workflows/pages.yml) 会在 `main` 分支的站点文件或 Pages workflow 发生变化时自动发布，也可以从 GitHub Actions 页面手动触发。

首次部署前，在仓库 **Settings → Pages → Build and deployment → Source** 中选择 **GitHub Actions**。网站目录已经由 `.dockerignore` 排除，因此网站文件和网站内容变更都不会进入或使 Go 镜像的 Docker 构建层失效。

## 生产安全要求

- TrustedAIProxy 会解密中转站发往上游的 HTTPS 流量，代理端口必须限制在内部网络，不能暴露给用户或互联网。
- 最终用户不应安装或信任内部 MITM CA；它只服务于中转站到代理之间的内部链路。
- 生产环境应使用离线 Root CA 签发专用 Intermediate CA。Root 私钥不得进入运行环境。
- 不要把 MITM CA 私钥或其他 secret 放进公开镜像。当前仓库中的示例 CA 仅供开发演示，不能用于生产。
- Ed25519 私钥由每个进程在内存中临时生成，从不从文件或 Secret Manager 加载，也不写入磁盘；进程退出后密钥身份随之终止。生产运行环境应禁用 core dump、heap dump 和未受控的调试端点。
- TAP 在开放监听端口前必须成功取得一次与临时公钥绑定的 startup workload attestation；这只是启动门禁，客户仍须使用自己的 challenge 获取并验证 Google proof。
- 上游 TLS 始终使用系统根证书和 hostname 正常校验，不能设置 `InsecureSkipVerify`。
- 命中已配置 path、格式正确且能完整提取文本的非流式 JSON 请求可以获得 conversation text attestation。`stream:true` SSE 请求只有在携带唯一合法 challenge 且请求字段、响应 TLS 和响应 metadata 全部有效时才获得 request-upstream attestation；其他请求正常转发但不添加证明 headers。
- 时间戳只能限制重放窗口；严格防重放还需要验签方缓存已经使用过的 nonce。

## 许可证

Copyright 2026 TokenEvol Inc.

本项目采用 [PolyForm Noncommercial License 1.0.0](LICENSE)，仅允许该许可证定义的非商业用途。任何商业用途均须事先取得版权所有者的单独书面授权；如需商业授权或技术咨询服务，请联系 [business@tokenevol.com](mailto:business@tokenevol.com)。

本项目是 source-available 软件，并非 OSI 定义的开源软件。完整且具有约束力的条款以 [LICENSE](LICENSE) 为准；本节仅为便于理解的摘要，不替代许可证正文。
