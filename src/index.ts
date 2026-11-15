/**
 * dsh-tailscale-gateway — expose the official DSH web GUI to your tailnet.
 *
 * Runs inside the DSH host process and does three things:
 *   1. Detects the local Tailscale IPv4 (`tailscale ip -4`); when Tailscale is
 *      down it tries to start the Windows service and (optionally) pops up a
 *      notice; it re-checks periodically and rebinds when the IP changes.
 *   2. Serves a plain TCP forwarder <tailscale-ip>:<listenPort> -> 127.0.0.1:<webServer.port>,
 *      so phones on the tailnet reach the loopback-bound official GUI. The
 *      transport stays a raw byte pipe, so WebSocket/stream upgrades, SSE and
 *      large uploads pass through untouched.
 *   3. Provides the `tailscaleGateway` service with a `trustedHosts` array
 *      ([detected-IP, MagicDNS-name]) so the connection row can admit the
 *      phone's Host authority without any hardcoded addresses.
 *
 * ## Transparent authentication (the reason this plugin exists)
 *
 * The official GUI authenticates with a launch-token exchange on `/?token=`
 * that answers a 303 carrying an HttpOnly; SameSite=Strict cookie bound to the
 * exact `host:port` authority. Browsers are notoriously unreliable about
 * keeping that cookie (Safari drops Set-Cookie on redirects, ITP evicts it,
 * private mode never persists it, and mixing IP with MagicDNS name changes the
 * cookie name). The result is: "the token URL works once, but opening the bare
 * URL later asks for authentication again".
 *
 * Rather than relying on the browser, the forwarder mints a valid browser
 * session cookie itself — through Connection's own public `authenticatedUrl()`
 * and `authorizeIndex()`, so the secret/signature/name/lifetime always match
 * the running DSH version — and injects it into EVERY forwarded request's
 * `Cookie` header. The phone therefore needs no token and no cookie at all:
 * `http://<tailscale-ip>:3080/` just works, on every visit, in any browser.
 *
 * To guarantee that every request (including keep-alive reuse) is injected,
 * non-upgrade requests are rewritten to `Connection: close`, so each TCP
 * connection carries exactly one HTTP request. Upgrade requests keep
 * `Connection: Upgrade` so the WebSocket remote stream mux still works.
 *
 * Security: anyone who can reach the forwarder port is treated as the owner.
 * The listener only binds the Tailscale interface, so this is limited to your
 * tailnet. Set `autoAuth: false` to restore DSH's own token/cookie auth.
 *
 * All DSH packages stay type-only: runtime access goes through ctx, so the
 * plugin loads from any directory via tsx.
 */
import { connect, createServer, type Server, type Socket } from 'node:net'
import { execFile } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-client-connection'

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
  /**
   * Inject a valid owner cookie into every forwarded request so the phone
   * needs no launch token and no browser cookie. Default true.
   * Set false to keep DSH's own token + authority-bound cookie authentication.
   */
  readonly autoAuth?: boolean
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

/**
 * Ask Connection to mint exactly the browser-session cookie it would issue for
 * a token exchange on `authority`. Only public service methods are used, so
 * the secret, HMAC signature, cookie name, authority binding, lifetime and
 * Secure flag always match the running DSH version.
 * @returns the `name=value` pair, or null when Connection is not ready.
 */
/** Minimal shape of the Connection service methods this plugin needs. */
interface AuthConnection {
  authenticatedUrl?: (baseUrl: string) => string
  authorizeIndex?: (
    request: { method?: string; url?: string; headers: Record<string, string> },
    response: {
      writeHead: (status: number, headers?: Readonly<Record<string, string>>) => unknown
      end: (body?: string) => unknown
    },
  ) => boolean
}

function mintAuthCookie(ctx: Context, authority: string): string | null {
  // Everything here is defensive: this runs inside a socket 'data' event, where
  // an uncaught throw becomes a process-level fatal exception and kills DSH.
  try {
    // Cordis guards `ctx.<service>` reads with `inject`. The connection row
    // injects `tailscaleGateway` (provided here), so declaring `connection` in
    // our own `inject` would deadlock both fibers. `ctx.get()` is Cordis's
    // reflection accessor that reads a service WITHOUT the inject requirement
    // (DSH's own code uses `ctx.get('webServer')` the same way).
    const connection = ctx.get('connection', false) as AuthConnection | undefined
    if (typeof connection?.authenticatedUrl !== 'function'
      || typeof connection?.authorizeIndex !== 'function') return null
    const token = new URL(connection.authenticatedUrl(`http://${authority}/`)).searchParams.get('token')
    if (token === null || token === '') return null
    let setCookie: string | undefined
    connection.authorizeIndex(
      { method: 'GET', url: `/?token=${encodeURIComponent(token)}`, headers: { host: authority } },
      {
        writeHead(_status: number, headers?: Readonly<Record<string, string>>): void {
          const raw = headers?.['set-cookie'] ?? headers?.['Set-Cookie']
          if (typeof raw === 'string') setCookie = raw
        },
        end(): void {},
      },
    )
    if (setCookie === undefined) return null
    const pair = setCookie.split(';', 1)[0]?.trim()
    return pair !== undefined && pair.startsWith('dsh-auth-') ? pair : null
  } catch {
    return null
  }
}

/**
 * Rewrite one HTTP request head: drop any stale `dsh-auth-` cookie, inject the
 * freshly minted valid one, and force a single request per TCP connection so
 * every request is authenticated (keep-alive reuse included). Upgrade requests
 * keep `Connection: Upgrade` so the WebSocket remote stream mux survives.
 */
function rewriteHead(head: string, authCookie: string): string {
  const lines = head.split('\r\n')
  const requestLine = lines[0] ?? ''
  const headers = lines.slice(1).filter(line => line !== '')
  const isUpgrade = headers.some(line => /^upgrade\s*:/i.test(line))
  const kept = headers.filter(line => !/^(cookie|connection|keep-alive|proxy-connection)\s*:/i.test(line))
  const previous = headers.find(line => /^cookie\s*:/i.test(line))
  const others = previous === undefined
    ? []
    : previous.slice(previous.indexOf(':') + 1).split(';')
      .map(part => part.trim())
      .filter(part => part !== '' && !part.startsWith('dsh-auth-'))
  kept.push(`Cookie: ${[...others, authCookie].join('; ')}`)
  kept.push(isUpgrade ? 'Connection: Upgrade' : 'Connection: close')
  return `${requestLine}\r\n${kept.join('\r\n')}\r\n\r\n`
}

export async function apply(ctx: Context, config: TailscaleGatewayConfig = {}): Promise<void> {
  const webServer = ctx.webServer
  const dshPort = webServer?.port ?? 3080
  const listenPort = config.listenPort ?? dshPort
  const retryMs = config.retryMs ?? 5000
  const recheckMs = config.recheckMs ?? 30000
  const autoStartService = config.autoStartService !== false
  const popup = config.popup !== false
  const autoAuth = config.autoAuth !== false
  /** authority -> valid `name=value` browser cookie, minted once per process. */
  const cookieCache = new Map<string, string>()

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
        let buffered = Buffer.alloc(0)
        let decided = false
        let upstream: Socket | null = null
        const wipe = (): void => {
          try { client.destroy() } catch { /* ignore */ }
          if (upstream !== null) { try { upstream.destroy() } catch { /* ignore */ } }
        }
        client.on('error', wipe)

        /** Forward the already-buffered bytes, then raw-pipe both directions. */
        const pipe = (first: Buffer): void => {
          upstream = connect(dshPort, '127.0.0.1')
          upstream.on('error', wipe)
          upstream.write(first)
          client.pipe(upstream)
          upstream.pipe(client)
          client.on('close', () => { if (upstream !== null) upstream.destroy() })
          upstream.on('close', () => client.destroy())
        }

        client.on('data', (chunk: Buffer) => {
          // This is an EventEmitter callback: ANY uncaught throw here becomes a
          // process-level fatal exception and kills the whole DSH host. Degrade
          // to a pure byte pipe instead of ever letting that happen.
          try {
            if (decided) return
            buffered = Buffer.concat([buffered, chunk])
            const headerEnd = buffered.indexOf('\r\n\r\n')
            if (headerEnd === -1) {
              // Not HTTP, or an unusually large head: pass through untouched.
              if (buffered.length > 65536) { decided = true; pipe(buffered) }
              return
            }
            decided = true
            if (!autoAuth) { pipe(buffered); return }
            const headText = buffered.subarray(0, headerEnd).toString('latin1')
            const hostLine = headText.split('\r\n').find(line => /^host\s*:/i.test(line))
            const authority = hostLine === undefined ? '' : hostLine.slice(hostLine.indexOf(':') + 1).trim()
            if (authority === '') { pipe(buffered); return }
            let authCookie = cookieCache.get(authority) ?? null
            if (authCookie === null) {
              authCookie = mintAuthCookie(ctx, authority)
              if (authCookie === null) {
                // Connection is not ready yet (or this profile has none): stay a
                // pure byte pipe so the plugin degrades instead of breaking DSH.
                ctx.logger?.warn?.('[tailscale-gateway] connection unavailable; forwarding without transparent auth')
                pipe(buffered)
                return
              }
              cookieCache.set(authority, authCookie)
              ctx.logger?.warn?.('[tailscale-gateway] transparent auth ready for ' + authority)
            }
            const rest = buffered.subarray(headerEnd + 4)
            pipe(Buffer.concat([Buffer.from(rewriteHead(headText, authCookie), 'latin1'), rest]))
          } catch (error) {
            ctx.logger?.warn?.('[tailscale-gateway] request handling failed: ' + String(error))
            if (!decided) { decided = true; pipe(buffered) }
          }
        })
        client.on('close', wipe)
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
        ctx.logger?.warn?.('[tailscale-gateway] forwarder ' + ip + ':' + listenPort + ' -> 127.0.0.1:' + dshPort
          + (autoAuth ? ' (transparent auth on)' : ' (transparent auth off)'))
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
