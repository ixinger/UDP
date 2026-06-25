# VPS Web 版

这是一个无第三方依赖的 Node.js 下载代理服务，带网页登录和密码验证。

快速启动：

```bash
cp .env.example .env
nano .env
npm install
npm run start
```

生产环境推荐：

- `HOST=127.0.0.1`
- 使用 PM2 守护进程。
- 使用 Nginx 反向代理。
- 使用 Certbot 配置 HTTPS。

完整教程见上一级目录的 `README.md`。
