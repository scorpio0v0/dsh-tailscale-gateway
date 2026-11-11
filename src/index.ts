/**
 * dsh-tailscale-gateway — expose the official DSH web GUI to your tailnet.
 *
 * Runs inside the DSH host process and does two things:
 *   1. Detects the local Tailscale IPv4 (`tailscale ip -4`); when Tailscale is
 *      down it tries to start the Windows service and (optionally) pops up a
 *      notice; it re-checks periodically and rebinds when the IP changes.
 *   2. Serves a plain TCP forwarder <tailscale-ip>:<listenPort> -> 127.0.0.1:<webServer.port>,
 *      so phones on the tailnet reach the loopback-bound official GUI.
 *
 * It also provides the `tailscaleGateway` service with a `trustedHosts` array
 * ([detected-IP, MagicDNS-name]) so the connection row can admit the phone's
 * Host authority without any hardcoded addresses:
 *
 *   - id: connection
 *     inject: [webStartup, tailscaleGateway]
 *     config:
 *       trustedHosts: !!js "[...ctx.tailscaleGateway.trustedHosts, ...ctx.webStartup.trustedHosts]"
 *
 * All DSH packages stay type-only: runtime access goes through ctx, so the
 * plugin loads from any directory via tsx.
 */
import { connect, createServer, type Server } from 'node:net'
import { execFile } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-host-webserver'

export const name = 'tailscale-gateway'

export const inject = ['webServer']

/** Plugin configuration (the cordis row's config). */
export interface TailscaleGatewayConfig {
  /** Port the forwarder listens on, per Tailscale IP. Default: the webServer port. */
  readonly listenPort?: number
  /** Try to start the Windows Tailscale service when it is down. Default true. */
  readonly autoStartService?: boolean
  /** Show a Windows message box when Tailscale stays down. Default true. */
  readonly popup?: boolean
  /** Detection/retry interval (ms). Default 5000. */
  readonly retryMs?: number
  /** Running re-check interval (ms). Default 30000. */
  readonly recheckMs?: number
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    tailscaleGateway?: TailscaleGatewayService
  }
}

/** Service provided as ctx.tailscaleGateway for connection-row config expressions. */
export interface TailscaleGatewayService {
  /** Host authorities to admit: the detected Tailscale IP and the MagicDNS name. */
  readonly trustedHosts: string[]
  /** Current forwarder address, or null while Tailscale is down. */
  readonly forwarderAddress: string | null
  /** The MagicDNS name of this machine (lowercased, no trailing dot), or null. */
  readonly dnsName: string | null
}

function run(cmd: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout: 15000 }, (err, stdout) => {
      resolve(err ? null : String(stdout || '').trim())
    })
  })
}

async function detectIp(): Promise<string | null> {
  const out = await run('tailscale', ['ip', '-4'])
  const ip = (out || '').split(/\r?\n/).map(s => s.trim()).find(s => /^\d+\.\d+\.\d+\.\d+$/.test(s))
  return ip || null
}

async function detectDnsName(): Promise<string | null> {
  const out = await run('tailscale', ['status', '--json'])
  if (!out) return null
  try {
    const json = JSON.parse(out) as { Self?: { DNSName?: string } }
    const raw = json.Self?.DNSName || ''
    const name = raw.replace(/\.$/, '').toLowerCase()
    return name.includes('.') ? name : null
  } catch {
    return null
  }
}

export async function apply(ctx: Context, config: TailscaleGatewayConfig = {}): Promise<void> {
  const webServer = ctx.webServer
  const dshPort = webServer?.port ?? 3080
  const listenPort = config.listenPort ?? dshPort
  const retryMs = config.retryMs ?? 5000
  const recheckMs = config.recheckMs ?? 30000
  const autoStartService = config.autoStartService !== false
  const popup = config.popup !== false

  const service: { trustedHosts: string[]; forwarderAddress: string | null; dnsName: string | null } = {
    trustedHosts: [], forwarderAddress: null, dnsName: null,
  }
  ctx.provide('tailscaleGateway', service as TailscaleGatewayService)

  let lastPopupAt = 0
  let failCount = 0
  async function handleDown() {
    failCount += 1
    ctx.logger?.warn?.('[tailscale-gateway] tailscale down (attempt ' + failCount + ')')
    if (autoStartService) await run('powershell', ['-NoProfile', '-Command', 'Start-Service Tailscale -ErrorAction SilentlyContinue'])
    const now = Date.now()
    if (popup && failCount >= 6 && now - lastPopupAt > 30 * 60 * 1000) {
      lastPopupAt = now
      run('powershell', ['-NoProfile', '-STA', '-Command',
        "Add-Type -AssemblyName System.Windows.Forms; " +
        "[void][System.Windows.Forms.MessageBox]::Show(" +
        "'Tailscale 未运行,已尝试自动启动其服务。' + [char]10 + " +
        "'若仍未连接,请打开 Tailscale 应用并登录。', 'DSH tailscale-gateway', 'OK', 'Warning')"]).catch(() => {})
    }
  }

  let server: Server | null = null
  let boundIp: string | null = null
  function unbind(): void {
    if (server) { try { server.close() } catch { /* ignore */ } server = null; boundIp = null; service.forwarderAddress = null }
  }
  function bind(ip: string): Promise<boolean> {
    return new Promise((resolveBind) => {
      server = createServer((client) => {
        const upstream = connect(dshPort, '127.0.0.1')
        client.pipe(upstream); upstream.pipe(client)
        const wipe = () => { client.destroy(); upstream.destroy() }
        client.on('error', wipe); upstream.on('error', wipe)
        client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy())
      })
      server.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          ctx.logger?.warn?.('[tailscale-gateway] port ' + listenPort + ' on ' + ip + ' already bound - another forwarder owns it')
          unbind()
          resolveBind(false)
          return
        }
        ctx.logger?.warn?.('[tailscale-gateway] bind error on ' + ip + ': ' + err.code)
        unbind()
        resolveBind(false)
      })
      server.listen(listenPort, ip, () => {
        boundIp = ip
        service.forwarderAddress = ip + ':' + listenPort
        ctx.logger?.warn?.('[tailscale-gateway] forwarder ' + ip + ':' + listenPort + ' -> 127.0.0.1:' + dshPort)
        resolveBind(true)
      })
    })
  }

  // Bounded first detection: provide a useful service without blocking DSH startup for long.
  const detectDeadline = Date.now() + 45000
  let ip = await detectIp()
  while (ip === null && Date.now() < detectDeadline) {
    await handleDown()
    await new Promise(r => setTimeout(r, retryMs))
    ip = await detectIp()
  }
  if (ip !== null) {
    service.trustedHosts.push(ip)
    const dns = await detectDnsName()
    if (dns) { service.dnsName = dns; service.trustedHosts.push(dns) }
    ctx.logger?.warn?.('[tailscale-gateway] tailscale ip ' + ip + (dns ? ' (' + dns + ')' : ''))
  } else {
    ctx.logger?.warn?.('[tailscale-gateway] tailscale not reachable within 45s; trustedHosts stays empty until restart')
  }

  // Background loop: bind / rebind / keep watching for IP changes and downtime.
  async function checkOnce(): Promise<void> {
    const current = await detectIp()
    if (!current) {
      failCount += 1
      if (server || failCount === 1) await handleDown()
      if (server) unbind()
      return
    }
    failCount = 0
    if (!service.trustedHosts.includes(current)) {
      service.trustedHosts.unshift(current)
      ctx.logger?.warn?.('[tailscale-gateway] new tailscale ip admitted: ' + current)
    }
    if (boundIp !== current) {
      unbind()
      await bind(current)
    }
  }
  void checkOnce().catch(() => { /* keep running */ })
  const timer = setInterval(() => { void checkOnce().catch(() => { /* keep running */ }) }, recheckMs)

  ctx.effect(() => () => {
    clearInterval(timer)
    unbind()
  })
}
