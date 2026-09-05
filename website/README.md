# TrustedAIProxy website

A static product website with English as the default language:

| Page | English | Simplified Chinese |
| --- | --- | --- |
| Home, architecture, verification, and proof scope | `index.html` | `zh/index.html` |
| Google Confidential Space deployment | `deploy.html` | `zh/deploy.html` |
| End-user verification | `user-guide.html` | `zh/user-guide.html` |

The header language switch opens the equivalent page. All internal navigation stays in the selected language. Language links work without JavaScript; when JavaScript is available, switching also preserves the current section anchor. Locale URLs are explicit and shareable; there is no browser-language redirect or local-storage dependency.

## Local preview

```sh
python3 -m http.server 4173 --directory website
```

Open <http://127.0.0.1:4173/> for English or <http://127.0.0.1:4173/zh/> for Chinese.

The site needs no build step, Node.js runtime, or external CDN. Deploy the entire directory to any static host. The original hero image and web-optimized version are `assets/trust-boundary-hero.png` and `assets/trust-boundary-hero.webp`.

## Maintaining both languages

Keep section IDs and code examples aligned across each page pair. Update page titles, descriptions, accessibility labels, and navigation alongside visible text. Shared interaction text (menu labels, profile descriptions, and clipboard feedback) is localized in `assets/site.js` using the document's `lang` attribute. Shared CSS and JavaScript are referenced with `../assets/` from Chinese pages.

The content follows the repository's current `trusted-ai-proxy-v1`, `llm-conversation-text-v1`, and `llm-request-upstream-v1` semantics. When protocol or deployment behavior changes, update:

- `README.md` and `README.zh-CN.md`;
- `docs/customer-verification-guide.md`;
- Both language versions of `index.html`, `deploy.html`, and `user-guide.html`.

The streaming profile authenticates only the request and upstream response metadata. Both languages must explicitly state that the streaming response body remains unverified.
