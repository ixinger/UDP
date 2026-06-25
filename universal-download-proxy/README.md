# Universal Download Proxy

一个带密码验证的通用下载代理项目，包含两个版本：

- `cloudflare-worker/worker.js`：单文件 Cloudflare Worker，可直接粘贴到网页编辑器。
- `vps-web/`：VPS 上运行的 Web 版，带登录页面、Cookie 会话、命令行 token/header 调用。

两个版本都不做文件存储，响应会从上游流式转发给客户端。

## 适用场景

- GitHub release、raw 文件、压缩包下载。
- 其它公开 HTTP/HTTPS 文件下载。
- `curl` / `wget` 安装脚本代理转换，例如把安装命令里的 URL 自动改成 Worker 代理地址。
- 自用下载跳板，需要密码保护，避免裸开放代理被滥用。

## 安全策略

默认策略：

- 需要密码。
- 只支持 `http://` 和 `https://`。
- 阻止 `localhost`、`.local`、常见内网 IP、链路本地地址、多播地址。
- 跳转会被重新校验，避免通过重定向绕到内网地址。
- VPS 版会校验 DNS 解析结果，并使用同一个已校验地址建立上游连接，降低 DNS rebinding 风险。
- 不转发 `Cookie`、代理自身的 `Authorization`、`X-Proxy-Password`、`X-Forwarded-*` 等敏感头。
- 默认不限公网域名；如果你想更严格，可以配置 `ALLOWED_HOSTS` 白名单。

注意：通用代理天然有滥用风险，务必设置强密码，并建议使用 VPS 版加 Nginx HTTPS。

## 目录结构

```text
universal-download-proxy/
├─ cloudflare-worker/
│  └─ worker.js
├─ vps-web/
│  ├─ server.js
│  ├─ package.json
│  ├─ .env.example
│  └─ ecosystem.config.cjs
└─ README.md
```

## 方案一：Cloudflare Worker 单文件版

### 1. 创建 Worker

1. 登录 Cloudflare Dashboard。
2. 进入 `Workers & Pages`。
3. 点击 `Create`。
4. 选择 `Create Worker`。
5. 进入编辑器后，把默认代码全部删除。
6. 打开本项目的 `cloudflare-worker/worker.js`，复制全部内容粘贴进去。
7. 点击 `Deploy`。

### 2. 设置密码变量

在 Worker 页面：

1. 进入 `Settings`。
2. 找到 `Variables and Secrets`。
3. 添加 Secret：

```text
Name: PROXY_PASSWORD
Value: 一串足够长的随机密码
```

建议用 24 位以上随机字符串，不要用简单口令。

### 3. 可选变量

```text
GITHUB_PROXY_ENABLED=true
GITHUB_TOKEN=
ALLOW_PRIVATE_IPS=false
ALLOWED_HOSTS=
EXTRA_BLOCKED_HOSTS=
```

说明：

- `GITHUB_PROXY_ENABLED=true`：开启 GitHub Lite、Raw、Release 链接代理。
- `GITHUB_TOKEN=`：可选，GitHub API 限流时建议添加 Worker Secret，提高 README、Code、Releases 获取成功率。公开仓库 metadata/read-only 权限即可。
- `ALLOW_PRIVATE_IPS=false`：默认阻止内网地址，建议保持不变。
- `ALLOWED_HOSTS=`：空值代表允许所有公网域名。
- `ALLOWED_HOSTS=github.com,raw.githubusercontent.com`：只允许这些域名。
- `EXTRA_BLOCKED_HOSTS=example.com,bad.example`：额外阻止这些域名。

### 4. 使用方式

浏览器打开：

```text
https://你的-worker.workers.dev/
```

页面里填目标 URL 和密码即可。

也可以用 URL 参数：

```text
https://你的-worker.workers.dev/?url=https%3A%2F%2Fexample.com%2Ffile.zip&token=你的密码
```

或路径模式：

```text
https://你的-worker.workers.dev/https://example.com/file.zip?token=你的密码
```

命令行下载：

```bash
curl -L -H "X-Proxy-Password: 你的密码" "https://你的-worker.workers.dev/?url=https%3A%2F%2Fexample.com%2Ffile.zip" -o file.zip
```

也支持：

```bash
curl -L -H "Authorization: Bearer 你的密码" "https://你的-worker.workers.dev/?url=https%3A%2F%2Fexample.com%2Ffile.zip" -o file.zip
```

首页还有“安装命令加速”工具，可以粘贴：

```bash
curl -fsSL https://get.docker.com | sh
```

生成代理后的安装命令。它适合安装脚本、普通文件、GitHub Raw 和 GitHub Release 资产；不适合完整代理 `docker pull` 镜像。

## 方案二：VPS Web 版

VPS 版适合长期自用：你可以绑定自己的域名，Nginx 开 HTTPS，PM2 守护 Node 进程。

下面以 Ubuntu 22.04/24.04 为例。

### 1. 安装 Node.js 20

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v
npm -v
```

确认 Node 版本是 `v20.x` 或更高。

### 2. 上传项目

在本机把 `universal-download-proxy/vps-web` 上传到 VPS，例如放到：

```text
/opt/universal-download-proxy
```

你可以用 `scp`：

```bash
scp -r vps-web root@你的服务器IP:/opt/universal-download-proxy
```

如果你在服务器上用 Git，也可以把整个项目拉过去后进入 `vps-web` 目录。

### 3. 配置环境变量

进入目录：

```bash
cd /opt/universal-download-proxy
cp .env.example .env
nano .env
```

推荐配置：

```text
HOST=127.0.0.1
PORT=8787
PROXY_PASSWORD=换成一串很长的随机密码
SESSION_SECRET=换成另一串很长的随机字符串
ALLOWED_HOSTS=
ALLOW_PRIVATE_IPS=false
EXTRA_BLOCKED_HOSTS=
MAX_REDIRECTS=8
MAX_TARGET_LENGTH=4096
```

生成随机字符串可以用：

```bash
openssl rand -hex 32
```

说明：

- `HOST=127.0.0.1`：只允许本机访问 Node 服务，由 Nginx 对外提供 HTTPS。
- `PORT=8787`：本机监听端口。
- `PROXY_PASSWORD`：登录密码，也是命令行 token/header 密码。
- `SESSION_SECRET`：签名网页登录 Cookie。
- `ALLOWED_HOSTS`：空值代表允许所有公网域名；填值则启用白名单。
- `ALLOW_PRIVATE_IPS=false`：阻止代理访问内网地址，建议保持不变。

### 4. 安装和启动

这个项目没有第三方依赖，但仍可用 npm 脚本统一启动：

```bash
npm install
npm run start
```

看到类似输出即启动成功：

```text
Universal Download Proxy listening on http://127.0.0.1:8787
```

本机测试：

```bash
curl http://127.0.0.1:8787/healthz
```

### 5. 使用 PM2 守护进程

安装 PM2：

```bash
sudo npm install -g pm2
```

启动：

```bash
cd /opt/universal-download-proxy
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup
```

`pm2 startup` 会输出一条 `sudo env ...` 命令，复制执行一次即可设置开机自启。

常用命令：

```bash
pm2 status
pm2 logs universal-download-proxy
pm2 restart universal-download-proxy
pm2 stop universal-download-proxy
```

### 6. Nginx 反向代理

安装 Nginx：

```bash
sudo apt install -y nginx
```

创建配置：

```bash
sudo nano /etc/nginx/sites-available/universal-download-proxy
```

写入，把 `download.example.com` 改成你的域名：

```nginx
server {
    listen 80;
    server_name download.example.com;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

启用站点：

```bash
sudo ln -s /etc/nginx/sites-available/universal-download-proxy /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. 配置 HTTPS

把域名 DNS A 记录指向 VPS IP 后，安装 Certbot：

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d download.example.com
```

按提示选择自动跳转 HTTPS。完成后访问：

```text
https://download.example.com/
```

### 8. VPS 版使用方式

网页登录：

```text
https://download.example.com/
```

命令行用 Header：

```bash
curl -L -H "X-Proxy-Password: 你的密码" "https://download.example.com/proxy?url=https%3A%2F%2Fexample.com%2Ffile.zip" -o file.zip
```

命令行用 Bearer：

```bash
curl -L -H "Authorization: Bearer 你的密码" "https://download.example.com/proxy?url=https%3A%2F%2Fexample.com%2Ffile.zip" -o file.zip
```

路径模式：

```bash
curl -L -H "X-Proxy-Password: 你的密码" "https://download.example.com/https://example.com/file.zip" -o file.zip
```

## 常见问题

### 这会缓存文件吗？

不会。两个版本都以流式方式转发响应，并设置 `no-store`。VPS 版和 Worker 版都没有接入对象存储。

### 为什么还要密码？

因为通用代理如果公开，会很容易被扫描和滥用。密码用于限制自用访问。

### 能加速所有网站吗？

它能让下载流量经过 Cloudflare 或你的 VPS，但真实速度仍取决于你的客户端到代理、代理到上游服务器两段链路。如果上游服务器本身限速，代理不能突破上游限制。

### GitHub release 跳转能用吗？

可以。两个版本都会手动跟随跳转，并在每次跳转后重新检查目标地址。

### 可以只允许部分网站吗？

可以。设置 `ALLOWED_HOSTS`：

```text
ALLOWED_HOSTS=github.com,raw.githubusercontent.com,objects.githubusercontent.com,example.com
```

这样只有列表里的主机名能通过代理访问。
