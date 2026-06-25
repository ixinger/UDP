# Cloudflare Worker 单文件版

`worker.js` 可以直接复制到 Cloudflare Workers 在线编辑器中使用。

## 必填 Secret

```text
PROXY_PASSWORD=你的强密码
```

建议使用 24 位以上随机字符串，不要把 Worker 裸开放成无密码公共代理。

## 推荐 Secret：GitHub Token

如果页面提示：

```text
GitHub API rate limit reached. Add Worker Secret GITHUB_TOKEN...
```

意思是 Worker 匿名调用 GitHub API 被限流了。解决办法：

1. 去 GitHub 创建一个 Personal Access Token。
2. 推荐使用 fine-grained token。
3. 权限只给公开仓库读取即可，通常 public repository metadata/read-only 就够。
4. 在 Cloudflare Worker 页面进入 `Settings` → `Variables and Secrets`。
5. 添加 Secret：

```text
Name: GITHUB_TOKEN
Value: 你的 GitHub token
```

`GITHUB_TOKEN` 只给 Worker 后台请求 GitHub API 使用，不是在代理页面登录 GitHub。不要在代理页面输入 GitHub 密码、Token 或 2FA 验证码。

## GitHub Lite

入口页：

```text
https://your-worker.workers.dev/gh
```

轻量仓库页：

```text
https://your-worker.workers.dev/gh/user/repo
```

轻量仓库页不再代理 GitHub 原网页，而是展示：

- README：内置轻量 Markdown 渲染，支持标题、链接、图片、列表、引用、代码块。
- Code：文件列表和目录浏览。
- Releases：优先用 GitHub API，API 限流时尝试从 Releases HTML 兜底解析。
- Raw：生成 `/raw/user/repo/branch/path` 文件代理链接。

页面右下角有浅色/深色切换按钮，偏好会保存在浏览器 `localStorage`。

## Raw 文件代理

短路径：

```text
https://your-worker.workers.dev/raw/user/repo/branch/path/to/file.sh
```

curl 示例：

```bash
curl -fsSL -H "X-Proxy-Password: 你的密码" "https://your-worker.workers.dev/raw/user/repo/main/install.sh" | sh
```

不方便加 Header 时：

```bash
curl -fsSL "https://your-worker.workers.dev/raw/user/repo/main/install.sh?token=你的密码" | sh
```

## 安装命令加速

首页新增“安装命令加速”工具，适合把安装脚本和普通文件下载命令改成代理地址。

例如粘贴：

```bash
curl -fsSL https://get.docker.com | sh
```

会生成类似：

```bash
curl -fsSL 'https://your-worker.workers.dev/https://get.docker.com?token=你的密码' | sh
```

适合：

- `curl` / `wget` 下载的安装脚本。
- GitHub Raw 文件。
- GitHub Release 资产。
- 普通公开 HTTP/HTTPS 文件。

不适合：

- 完整代理 `docker pull` 镜像。
- 大型 Docker Registry 镜像站。
- 需要登录态、Cookie 或复杂认证的网站。

Docker 镜像拉取不是单个文件下载，它涉及 Registry API、认证、manifest、blob 分层、Range 和重定向。Worker 可以做小规模脚本/文件中转，但不建议当完整镜像站使用。

## 可选变量

```text
GITHUB_PROXY_ENABLED=true
ALLOW_PRIVATE_IPS=false
ALLOWED_HOSTS=
EXTRA_BLOCKED_HOSTS=
```

说明：

- `GITHUB_PROXY_ENABLED=true`：开启 GitHub Lite、Raw、Release 链接代理。
- `ALLOW_PRIVATE_IPS=false`：默认阻止内网地址，建议保持不变。
- `ALLOWED_HOSTS=`：空值代表允许所有公网域名；填值则启用白名单。
- `EXTRA_BLOCKED_HOSTS=`：额外阻止指定域名。

安全提醒：只建议浏览公开仓库和下载公开文件。不要在代理页面登录 GitHub，不要输入 GitHub 密码、Token 或 2FA 验证码。
