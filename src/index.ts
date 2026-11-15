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
 * session cookie itself and injects it into EVERY forwarded request's `Cookie`
 * header, so the phone needs no token and no cookie at all. Two independent
 * strategies are used, both version-agnostic:
 *
 *   A. Ask DSH itself to mint the cookie over its OWN HTTP surface: perform a
 *      real `GET /?token=<launch-token>` against 127.0.0.1:<port> with the
 *      target Host header, and read the `Set-Cookie` from the response. This
 *      delegates cookie format/name/signature/lifetime entirely to the running
 *      DSH build, so it works across versions (alpha/rc/stable) without any
 *      knowledge of DSH internals. Requires Connection.authenticatedUrl().
 *   B. Read the durable HMAC secret from the credentials service and sign the
 *      well-known v1 cookie payload directly. Used when strategy A is not
 *      available. The v1 format is stable across DSH versions.
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
import { createHash, createHmac } from 'node:crypto'
import { request as httpRequest } from 'node:http'
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

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')
}

function decodeBase64Url(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return undefined
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const decoded = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/') + padding, 'base64')
  return encodeBase64Url(decoded) === value ? decoded : undefined
}

/** Minimal Connection surface needed to obtain the fresh launch token. */
interface AuthConnection {
  authenticatedUrl?: (baseUrl: string) => string
}

/** Minimal Credentials surface needed to read the durable signing secret. */
interface AuthCredentials {
  readRecord?: (key: string) => Promise<{ kind?: string; payload?: { version?: number; secret?: string } } | undefined>
}

const AUTH_RECORD_KEY = 'client-connection/browser-session'

/**
 * Strategy A: let DSH mint the cookie over its own HTTP surface.
 *
 * A real `GET /?token=<launch-token>` is sent to the loopback listener with
 * the target Host authority. DSH answers a 303 with a `Set-Cookie` in exactly
 * the format the running build expects (name, signature, lifetime), which we
 * capture verbatim. This avoids all dependence on internal response APIs such
 * as `authorizeIndex`'s `writeHead` shape — the reason a v0.1.3/v0.1.4 plugin
 * could fail on a different DSH version (e.g. 0.2.2-rc.3).
 *
 * @returns the `name=value` cookie pair, or null when unavailable.
 */
function mintViaHttp(ctx: Context, dshPort: number, launchToken: string, authority: string): Promise<string | null> {
  return new Promise((resolveMint) => {
    let settled = false
    const finish = (value: string | null): void => {
      if (settled) return
      settled = true
      resolveMint(value)
    }
    try {
      const req = httpRequest({
        host: '127.0.0.1',
        port: dshPort,
        method: 'GET',
        path: '/?token=' + encodeURIComponent(launchToken),
        headers: { host: authority, connection: 'close' },
        timeout: 8000,
      }, (resp) => {
        // Drain the response so the socket is released, then read Set-Cookie.
        resp.resume()
        const raw = resp.headers['set-cookie']
        const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw]
        const pair = list
          .map((line) => line.split(';', 1)[0]?.trim() ?? '')
          .find((line) => line.startsWith('dsh-auth-'))
        finish(pair !== undefined && pair !== '' ? pair : null)
      })
      req.on('error', () => finish(null))
      req.on('timeout', () => { req.destroy(); finish(null) })
      req.end()
    } catch {
      finish(null)
    }
  })
}

/**
 * Strategy B: sign the stable v1 browser cookie directly from the durable
 * HMAC secret. Used when strategy A cannot obtain a token. The payload shape
 * and HMAC scheme are fixed by DSH's browser-auth and have not changed.
 */
function mintDirect(secret: Buffer, authority: string): string | null {
  try {
    const now = Date.now()
    const payload = {
      version: 1,
      authority,
      issuedAt: now,
      expiresAt: now + 30 * 24 * 60 * 60 * 1000,
    }
    const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'))
    const signature = encodeBase64Url(createHmac('sha256', secret).update(body).digest())
    const name = 'dsh-auth-' + encodeBase64Url(createHash('sha256').update(authority).digest())
    return name + '=v1.' + body + '.' + signature
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
  kept.push('Cookie: ' + [...others, authCookie].join('; '))
  kept.push(isUpgrade ? 'Connection: Upgrade' : 'Connection: close')
  return requestLine + '\r\n' + kept.join('\r\n') + '\r\n\r\n'
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

  /**
   * Resolved once at startup, retried briefly because Connection/Credentials
   * are provided by other fibers that may activate slightly after this one.
   * Both accessors use ctx.get() (Cordis reflection, no inject requirement):
   * the connection row injects tailscaleGateway, so declaring connection here
   * would create a circular fiber dependency and deadlock both plugins.
   */
  let launchToken: string | null = null
  let signingSecret: Buffer | null = null
  if (autoAuth) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      try {
        if (launchToken === null) {
          const connection = ctx.get('connection', false) as AuthConnection | undefined
          if (typeof connection?.authenticatedUrl === 'function') {
            const token = new URL(connection.authenticatedUrl('http://127.0.0.1:' + String(dshPort) + '/'))
              .searchParams.get('token')
            if (token !== null && token !== '') launchToken = token
          }
        }
        if (signingSecret === null) {
          const credentials = ctx.get('credentials', false) as AuthCredentials | undefined
          if (typeof credentials?.readRecord === 'function') {
            const record = await credentials.readRecord(AUTH_RECORD_KEY)
            const raw = record?.payload?.secret
            if (typeof raw === 'string') {
              const decoded = decodeBase64Url(raw)
              if (decoded !== undefined && decoded.byteLength === 32) signingSecret = decoded
            }
          }
        }
      } catch {
        // Service not ready yet; retry below.
      }
      if (launchToken !== null || signingSecret !== null) break
      await new Promise(r => setTimeout(r, 250))
    }
    ctx.logger?.warn?.('[tailscale-gateway] auth strategy A (DSH HTTP mint): '
      + (launchToken !== null ? 'ready' : 'unavailable')
      + '; strategy B (direct v1 sign): ' + (signingSecret !== null ? 'ready' : 'unavailable'))
  }

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

        client.on('data', async (chunk: Buffer) => {
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
              authCookie = launchToken !== null
                ? await mintViaHttp(ctx, dshPort, launchToken, authority)
                : null
              if (authCookie === null && signingSecret !== null) {
                authCookie = mintDirect(signingSecret, authority)
              }
              if (authCookie === null) {
                ctx.logger?.warn?.('[tailscale-gateway] cookie mint failed for ' + authority
                  + '; forwarding without transparent auth')
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
