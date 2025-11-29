# CFWPPG
Cloudflare Worker Proxy Protected Gateway
# 反代认证 Worker 使用说明

> 本说明适用于完整 `worker.js`，实现 **密码认证 + 反向代理到 `www.example.com`**。

---

## 目录

1. 功能概览  
2. 架构与工作原理  
3. 快速开始  
4. 环境变量与绑定项  
5. 部署到 Cloudflare Workers  
6. 路由与 BASE_PATH 说明  
7. HTTPS 与 Cookie 行为  
8. 测试与验证  
9. 常见问题与排障  
10. 安全建议  
11. 二次定制  
12. 示例请求流程  
13. 变更记录  

---

## 1. 功能概览

- **密码认证页面**：未认证时显示登录页，输入正确密码后提示“密码正确，正在反代网站……”并跳转。
- **错误次数限制与封禁**：连续输错达到阈值自动封禁 IP。
- **反向代理**：认证成功后，所有请求直接改 `hostname` 为 `www.example.com` 并 `fetch` 上游。
- **重定向重写**：将上游响应头中的 `Location` 重写到本域。
- **安全头**：统一加安全响应头。
- **Cookie 智能 Secure**：HTTPS 下加 Secure，HTTP 调试时不加。
- **会话签名简化**：不再绑定 IP，减少误判。

---

## 2. 架构与工作原理

1. 请求进入 → 检查 Cookie 是否已认证。
2. 未认证 → 返回登录页。
3. 登录 API → 验证密码，签发 `AUTH_SESSION`，返回 `{ok:true}`。
4. 前端提示成功 → 延迟 600ms → 跳转。
5. 已认证 → 修改请求 URL 的 `hostname` → fetch 上游 → 重写响应头 → 返回。

---

## 3. 快速开始

1. 上传完整 `worker.js` 到 Cloudflare Workers。
2. 配置环境变量与 KV 绑定。
3. 设置路由（全站或前缀）。
4. 访问 Worker 域名测试：未认证显示登录页，认证后反代成功。

---

## 4. 环境变量与绑定项

| 变量名 | 默认值 | 说明 |
|---|---|---|
| `TARGET_HOST` | `www.example.com` | 上游目标域名 |
| `MAX_FAILS` | `3` | 最大错误次数 |
| `FAIL_TTL` | `900` | 错误计数 TTL（秒） |
| `BAN_TTL` | `3600` | 封禁 TTL（秒） |
| `SESSION_TTL` | `86400` | 会话有效期（秒） |
| `REALM` | `Protected Gateway` | 登录页标题 |
| `BASE_PATH` | `""` | Worker 前缀，如 `/proxy` |
| `AUTH_PASSWORD` | 无 | 访问密码（Secret） |
| `COOKIE_SECRET` | 无 | 签名秘钥（Secret） |

**KV 绑定**：`AUTH_STORE` 用于错误计数与封禁。

---

## 5. 部署到 Cloudflare Workers

- **Dashboard**：创建 Worker → 替换代码 → 保存部署。
- **Wrangler**：
```bash
wrangler init my-auth-proxy
wrangler secret put AUTH_PASSWORD
wrangler secret put COOKIE_SECRET
wrangler deploy
```

---

## 6. 路由与 BASE_PATH

- **全站绑定**：`BASE_PATH=""`，登录页 `/login`，API `/__auth`。
- **前缀绑定**：如 `/proxy/*`，则 `BASE_PATH="/proxy"`，登录页 `/proxy/login`。

---

## 7. HTTPS 与 Cookie 行为

- HTTPS 下 Cookie 加 `Secure`；HTTP 调试时不加。
- 生产环境必须启用 HTTPS，避免跨域名跳转。

---

## 8. 测试与验证

- 访问登录页 → 输入密码 → 提示成功 → 跳转。
- DevTools 检查请求是否带 `AUTH_SESSION` Cookie。
- 错误次数达到阈值后封禁。

---

## 9. 常见问题

- **认证后仍回登录页**：检查 HTTPS、BASE_PATH、Cookie 是否发送。
- **跳到上游域名**：需要 HTML 内容重写，可扩展。

---

## 10. 安全建议

- 使用强随机 `COOKIE_SECRET`。
- 启用 HTTPS。
- 可加验证码或速率限制。

---

## 11. 二次定制

- 修改提示文案与延迟：
```js
msg.textContent = "密码正确，正在反代网站……";
await new Promise(r => setTimeout(r, 600));
```
- 跳转路径：`location.href = ROOT + "home";`

---

## 12. 示例请求流程

1. 用户访问 `/` → 登录页。
2. 输入密码 → 调用 `/__auth` → 返回 `{ok:true}`。
3. 前端提示成功 → 跳转。
4. 后续请求 → 改 `hostname` → fetch 上游 → 返回。

---

## 13. 变更记录

- 新增成功提示与延迟。
- 修复 IP 绑定问题。
- 智能设置 Cookie Secure。
