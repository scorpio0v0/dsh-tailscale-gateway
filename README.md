# dsh-tailscale-gateway

把**官方 DeepSeek Harness 网页 GUI** 安全地暴露到你的 Tailscale 网络的 DSH 插件。

在 DSH 进程内运行,做三件事:

1. **自动探测本机 Tailscale IPv4**(`tailscale ip -4`);Tailscale 未运行时自动尝试启动其 Windows 服务并弹窗提醒;
2. 在 `<tailscale-ip>:3080` 起一个纯 TCP 转发器,指向回环上的官方 GUI(`127.0.0.1:<DSH端口>`)——DSH 本体仍只绑回环,电脑本地访问不受影响;
3. 提供 `tailscaleGateway.trustedHosts`(探测到的 IP + MagicDNS 域名),供 connection 行自动放行手机访问的 Host 权威。运行中每 30 秒复查,IP 变化自动重绑。

> 安全边界:转发器只监听 Tailscale 网卡(不在局域网/WLAN 暴露);认证仍由 DSH 自身的启动令牌+签名 Cookie 完成。请只在你信任的 tailnet 中使用。

## 安装

前置:Windows、已安装并登录 [Tailscale](https://tailscale.com/)、DSH ≥ 0.2.x(web profile)。

### 方式 A:插件管理器(GitHub)

GUI → 插件 → 安装插件,填入仓库地址:

```
https://github.com/scorpio0v0/dsh-tailscale-gateway
```

### 方式 B:本地源码

```sh
git clone https://github.com/scorpio0v0/dsh-tailscale-gateway.git
```

在你的 profile patch(或 `--patch` 叠加层,见 `cordis.example.yml`)中加入:

```yaml
- insert:
    - id: tailscale-gateway
      name: 'D:/absolute/path/to/dsh-tailscale-gateway/src/index.ts'
      config:
        listenPort: 3080
- id: connection
  inject: [ webStartup, tailscaleGateway ]
  config:
    trustedHosts: !!js "[...ctx.tailscaleGateway.trustedHosts, ...ctx.webStartup.trustedHosts]"
    cookieMaxAgeDays: 3650
```

重启 DSH。启动日志出现 `[tailscale-gateway] forwarder <ip>:3080 -> 127.0.0.1:3080` 即成功。

## 使用

手机(同一 tailnet)浏览器打开 `http://<电脑tailscale-ip>:3080/`。
首次登录需 DSH 的一次性启动令牌(托盘日志里 `dsh web: ...?token=...`,把 127.0.0.1 换成 tailscale IP)。
Cookie 默认 10 年(可在 patch 调整 `cookieMaxAgeDays`),登录一次长期有效。

## 卸载

从 patch 删除上述两段,重启 DSH;转发器随插件卸载自动关闭。

## License

MIT
