# TrustedAIProxy website

静态产品站点，包含：

- `index.html`：主页、技术原理、验证流程、优势与证明边界；
- `deploy.html`：Google Confidential Space 部署指南；
- `user-guide.html`：最终用户使用与独立验签指南。

## 本地预览

```sh
python3 -m http.server 4173 --directory website
```

打开 <http://127.0.0.1:4173/>。

站点不依赖 Node.js 或外部 CDN，可以直接部署到任意静态托管服务。主视觉原图和 Web 优化版本位于 `assets/trust-boundary-hero.png` 与 `assets/trust-boundary-hero.webp`。

## 内容边界

主页和文档按当前仓库的 `trusted-ai-proxy-v1`、`llm-conversation-text-v1` 与 `llm-request-upstream-v1` 语义编写。协议或部署行为变化时，应同步更新：

- `README.md`；
- `docs/customer-verification-guide.md`；
- `website/index.html`；
- `website/deploy.html`；
- `website/user-guide.html`。
