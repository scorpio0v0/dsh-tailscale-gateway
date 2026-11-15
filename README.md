# dsh-tailscale-gateway

把**官方 DeepSeek Harness 网页 GUI** 暴露到你的 Tailscale 网络的 DSH 插件。

在 DSH 进程内运行,做三件事:

1. **自动探测本机 Tailscale IPv4**(`tailscale ip -4`);Tailscale 未运行时自动尝试启动其 Windows 服务并弹窗提醒;
2. 在 `<tailscale-ip>:3080` 起一个**纯 TCP 转发器**,指向回环上的官方 GUI(`127.0.0.1:<DSH端口>`)——DSH 本体仍只绑回环,电脑本地访问不受影响。传输层保持原始字节透传,WebSocket / SSE / 大文件上传都不受影响;
3. 提供 `tailscaleGateway.trustedHosts`(探测到的 IP + MagicDNS 域名),供 connection 行自动放行手机访问的 Host 权威。运行中每 30 秒复查,IP 变化自动重绑。

> 安全边界:转发器只监听 Tailscale 网卡(不在局域网/WLAN 暴露)。请只在你信任的 tailnet 中使用。

## 为什么要有「透明认证」

官方 GUI 的认证是两步式:`/?token=xxx` → 一个 **303 重定向**,在响应里下发
`HttpOnly; SameSite=Strict` 且**绑定精确 `host:port`** 的 Cookie → 之后靠这个 Cookie 访问。
这套设计在手机浏览器上非常不稳:

- Safari / WebKit 会丢弃或不在后续请求里带上「重定向响应里设置的 SameSite=Strict Cookie」;
- ITP、隐私模式、清理网站数据都会让 Cookie 消失;
- IP 与 MagicDNS 域名混用会生成**不同名字**的 Cookie;
- 浏览器普遍把 Cookie 寿命上限设为 **400 天**,`Max-Age=10年` 会被截断/拒收。

表现就是:**带 token 的 URL 能打开一次,之后直接访问裸 URL 又提示需要校验鉴权**。
以前自己写的 `/mobile` 插件是「每个请求校验 URL 里的固定令牌」,根本不依赖浏览器 Cookie,所以没这个问题。

本插件因此不再依赖浏览器:转发器**自己用 Connection 的公开方法
(`authenticatedUrl()` + `authorizeIndex()`)现场签发一个有效的浏览器会话 Cookie**,
并注入到**每一个**转发请求的 `Cookie` 头里。Cookie 的密钥、签名、名字、
权威绑定、有效期全部由当前 DSH 自己生成,版本升级也不会失配。

结果:**手机不需要任何令牌,也不需要存任何 Cookie**,
直接打开 `http://<电脑tailscale-ip>:3080/` 就能用,每次访问、任何浏览器都能用。

为保证 keep-alive 连接上的每个请求都被注入,普通请求会被改写为
`Connection: close`(一条连接只走一个请求);WebSocket/stream upgrade 请求保留
`Connection: Upgrade`,实时事件通道不受影响。

## 安装

前置:Windows、已安装并登录 [Tailscale](https://tailscale.com/)、DSH ≥ 0.2.x(web profile)。本包声明了 `dsh.bundle`:**在 GUI 插件管理器里安装即自动完成配置**(插入插件行 + 重述 connection 行),卸载自动还原。

### 方式 A:插件管理器(GitHub,推荐)

GUI → 插件 → 安装插件,填入:

```
https://github.com/scorpio0v0/dsh-tailscale-gateway
```

### 方式 B:本地源码(手动)

```sh
git clone https://github.com/scorpio0v0/dsh-tailscale-gateway.git
```

在 profile patch(`~/.dsh/profiles/web/cordis.patch.yml`)加入 `cordis.bundle.yml` 的两段内容,并把 insert 行的 `name` 换成插件源码绝对路径。

**重启 DSH**,启动日志出现 `[tailscale-gateway] forwarder <ip>:3080 -> 127.0.0.1:3080 (transparent auth on)` 即成功。

## 使用

手机(同一 tailnet)浏览器直接打开:

```
http://<电脑tailscale-ip>:3080/
```

**不需要 token,不需要先登录一次。** 用 MagicDNS 域名
`http://scorpio-mechrevo.tail0d0594.ts.net:3080/` 也可以,但请全程保持同一种写法。
建议把这个地址存为书签或添加到主屏幕。

## 安全说明 / 关闭透明认证

透明认证意味着:**能连到该端口的设备即被视为 owner**(可执行会话、工具等全部权限)。
监听地址只绑定 Tailscale 网卡,所以范围限于你的 tailnet;若 tailnet 内有不信任的设备,
或你更希望保留启动令牌校验,把插件行配置改为:

```yaml
- id: tailscale-gateway
  name: 'dsh-tailscale-gateway'
  config:
    listenPort: 3080
    autoAuth: false
```

此时恢复 DSH 自带的「启动令牌 → 签名 Cookie」流程(托盘日志里
`dsh web: ...?token=...`,把 127.0.0.1 换成 tailscale IP),Cookie 有效期 365 天。

`cookieMaxAgeDays` 也一并由组合包设为 365(≤400 天),避免浏览器截断。

## 卸载

GUI 插件管理器中移除本插件即可:组合包 patch 自动回滚,转发器随插件卸载关闭。

## 更新记录

- **0.1.5** 通用透明认证:不再依赖 DSH 内部 `authorizeIndex` 的写法(跨版本会失效)。改为两条版本无关的路径:① 用启动令牌向本机 DSH 发真实 HTTP 请求,读取它自己签发的 `Set-Cookie`(格式完全由当前 DSH 版本决定,兼容 0.2.2-alpha/rc/stable);② 回退为从凭据服务读持久密钥直接签 v1 Cookie。修复在 DSH 0.2.2-rc.3 上透明认证失效导致的 401。
- **0.1.4** 修复 `cannot get property "connection" without inject` 导致的进程级崩溃:改用 Cordis 的 `ctx.get()` 读取服务(避免与 connection 行的 `inject: [tailscaleGateway]` 形成循环依赖),并把 socket 回调整体包进 `try/catch`,任何异常都降级为纯透传而不再杀掉 DSH。
- **0.1.3** 引入透明认证(每请求注入有效 Cookie),手机无需令牌/Cookie。
- **0.1.2** 组合包 patch 修复安装。

## License

MIT
