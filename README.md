# Cloudflare 可视化邮箱 Worker

AI写的自用，能用但不适合继续优化。
一个可直接部署到 Cloudflare Workers 的邮件接收可视化页面：

- 使用 Cloudflare Email Routing + Email Worker 接收邮件
- 邮件存入 KV（包含主题、发件人、时间、正文）
- 提供收件箱列表、详情查看、删除、清空
- 带动态粒子背景和移动端适配

## 1. 前置准备

- Node.js 18+
- Cloudflare 账号
- 域名已接入 Cloudflare（用于 Email Routing）

## 2. 安装依赖

```bash
npm install
```

## 2.1 仓库发布模板

本项目仓库中提供 [wrangler.toml.example](wrangler.toml.example) 模板，真实的 `wrangler.toml` 属于本地个人配置（包含 Cloudflare Namespace ID），默认不上传。

使用方式：

```powershell
Copy-Item wrangler.toml.example wrangler.toml
```

然后把你自己的 Cloudflare 资源 ID 填到本地 `wrangler.toml`。

## 3. 创建 KV Namespace

```bash
npx wrangler kv namespace create MAIL_KV
npx wrangler kv namespace create MAIL_KV --preview
```

把输出里的 `id` 和 `preview_id` 分别填入你本地的 `wrangler.toml` 的 `MAIL_KV` 与 `AUTH_KV`。

建议：`AUTH_KV` 使用独立命名空间，不要与 `MAIL_KV` 复用，便于权限隔离和后续扩容。

## 4. 设置 Dashboard Token（可选但推荐）

```bash
npx wrangler secret put DASHBOARD_TOKEN
```

页面访问 API 时会校验 `Authorization: Bearer <token>`。

## 5. 本地调试

```bash
npm run dev
```

打开本地地址，输入 Token 即可查看收件箱页面。

## 6. 部署

```bash
npm run deploy
```

如果本机网络或证书链导致 Wrangler 报 TLS 证书错误（例如 `UNABLE_TO_VERIFY_LEAF_SIGNATURE`），可先设置环境变量再执行 Wrangler：

```powershell
$env:NODE_TLS_REJECT_UNAUTHORIZED="0"
npm run deploy
```

同一终端里运行的其他 Wrangler 命令（如 `wrangler tail`）也需要先设置这个变量。

> 安全提示：`NODE_TLS_REJECT_UNAUTHORIZED=0` 会关闭 TLS 证书校验，仅建议用于临时排障。

## 7. 配置 Cloudflare 邮件路由

在 Cloudflare Dashboard 的 Email Routing 中：

1. 启用 Email Routing。
2. 新建 Route（例如 `inbox@yourdomain.com`）。
3. Action 选择 `Send to Worker`，绑定本 Worker。

之后给该地址发邮件，邮件会被 Worker 收到并写入 KV，在页面中可视化查看。

## 8. API 说明

### 8.1 认证与多租户

- `POST /api/auth/register` 注册并创建租户（首个用户为 `owner`）
- `POST /api/auth/login` 登录（写入 HttpOnly 会话 Cookie）
- `POST /api/auth/logout` 退出登录
- `GET /api/auth/me` 当前用户与租户信息
- `GET /api/auth/tenants` 当前用户可访问租户列表
- `POST /api/auth/switch-tenant` 切换当前租户

注册示例：

```bash
curl -X POST https://<your-worker>.workers.dev/api/auth/register \
	-H "content-type: application/json" \
	-d '{"email":"owner@example.com","password":"Passw0rd!","tenantName":"Acme Team"}'
```

### 8.2 邮箱路由管理（owner/admin）

- `GET /api/mailboxes` 查看当前租户绑定的收件地址
- `POST /api/mailboxes` 绑定收件地址到当前租户
- `DELETE /api/mailboxes/:address` 解绑收件地址

创建路由示例：

```bash
curl -X POST https://<your-worker>.workers.dev/api/mailboxes \
	-H "content-type: application/json" \
	-H "cookie: cf_mv_sid=<session-id>" \
	-d '{"address":"inbox@yourdomain.com"}'
```

### 8.3 邮件接口

- `GET /api/health` 健康检查
- `GET /api/messages` 邮件列表
- `GET /api/messages/:id` 邮件详情
- `DELETE /api/messages/:id` 删除邮件
- `POST /api/clear` 清空全部邮件

说明：

- 会话模式下，邮件按租户隔离存储（`tenant_id`）。
- 兼容旧版 `DASHBOARD_TOKEN` 调用模式（读取 `mail:legacy:` 前缀）。

## 9. 故障排查

- 出现 Cloudflare 页面 `Error 1101 Worker threw exception` 时，先重新部署一次并确认最新版本已生效。
- 使用以下命令检查线上健康状态：

```powershell
$env:NODE_TLS_REJECT_UNAUTHORIZED="0"
Invoke-WebRequest -UseBasicParsing https://<your-worker>.workers.dev/api/health
```

- 返回 `{"ok": true}` 表示 Worker 已正常运行；若仍报错，再查看 `wrangler tail` 日志定位具体异常。

> 注意：当前实现是轻量 MIME 解析，复杂富文本和附件未做深度解析；如果你需要附件预览或 HTML 正文渲染，我可以继续帮你升级。
