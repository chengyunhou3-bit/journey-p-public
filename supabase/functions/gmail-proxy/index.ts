import { createClient } from 'npm:@supabase/supabase-js@2.111.0'

const googleClientId = '457297734116-hhajtffo2igfqjtl3i94ff4re9v8iv1e.apps.googleusercontent.com'
const gmailScope = 'https://www.googleapis.com/auth/gmail.readonly'
const allowedOrigins = new Set([
  'https://chengyunhou3-bit.github.io',
  'http://localhost:8000',
  'http://127.0.0.1:8000',
])

class HttpError extends Error {
  status: number
  code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

const supabaseUrl = Deno.env.get('SUPABASE_URL')!
const secretKey = (() => {
  const modernKeys = Deno.env.get('SUPABASE_SECRET_KEYS')
  if (modernKeys) {
    const parsed = JSON.parse(modernKeys) as Record<string, string>
    const firstKey = parsed.default || Object.values(parsed)[0]
    if (firstKey) return firstKey
  }
  const legacyKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
  if (!legacyKey) throw new Error('Supabase service key is unavailable')
  return legacyKey
})()

const admin = createClient(supabaseUrl, secretKey, {
  auth: { persistSession: false, autoRefreshToken: false },
})

const encoder = new TextEncoder()
let encryptionKeyPromise: Promise<CryptoKey> | null = null

function googleClientSecret() {
  const value = Deno.env.get('GOOGLE_OAUTH_CLIENT_SECRET')
  if (!value) {
    throw new HttpError(503, 'gmail_server_not_configured', 'Gmail 後端尚未完成設定')
  }
  return value
}

function encryptionKey() {
  if (!encryptionKeyPromise) {
    encryptionKeyPromise = (async () => {
      const material = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(`${googleClientSecret()}|journey-p-gmail-token-encryption-v1`),
      )
      return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, [
        'encrypt',
        'decrypt',
      ])
    })()
  }
  return encryptionKeyPromise
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function base64ToBytes(value: string) {
  const binary = atob(value)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

async function encryptToken(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    await encryptionKey(),
    encoder.encode(value),
  )
  return {
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
    iv: bytesToBase64(iv),
  }
}

async function decryptToken(ciphertext: string, iv: string) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(iv) },
    await encryptionKey(),
    base64ToBytes(ciphertext),
  )
  return new TextDecoder().decode(decrypted)
}

function corsHeaders(origin: string) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers':
      'authorization, apikey, content-type, x-client-info, x-requested-with',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    Vary: 'Origin',
  }
}

function json(origin: string, body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  })
}

async function currentUser(req: Request) {
  const authorization = req.headers.get('Authorization') || ''
  const accessToken = authorization.replace(/^Bearer\s+/i, '')
  if (!accessToken) throw new HttpError(401, 'unauthorized', '請先登入 Journey P')
  const { data, error } = await admin.auth.getUser(accessToken)
  if (error || !data.user) throw new HttpError(401, 'unauthorized', 'Journey P 登入已失效')
  return data.user
}

async function parseGoogleError(response: Response) {
  try {
    const payload = await response.json()
    return payload?.error_description || payload?.error?.message || payload?.error || ''
  } catch {
    return ''
  }
}

async function exchangeAuthorizationCode(code: string, redirectUri: string) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: googleClientId,
      client_secret: googleClientSecret(),
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  })
  if (!response.ok) {
    const detail = await parseGoogleError(response)
    throw new HttpError(400, 'gmail_code_exchange_failed', detail || 'Gmail 授權碼交換失敗')
  }
  return response.json()
}

async function connection(userId: string) {
  const { data, error } = await admin
    .from('gmail_connections')
    .select('*')
    .eq('user_id', userId)
    .maybeSingle()
  if (error) throw new HttpError(500, 'gmail_storage_failed', '無法讀取 Gmail 連結狀態')
  return data
}

async function refreshAccessToken(userId: string, row?: Record<string, unknown>) {
  const saved = row || (await connection(userId))
  if (!saved) throw new HttpError(409, 'gmail_reconnect_required', '請重新連結 Gmail')

  let refreshToken: string
  try {
    refreshToken = await decryptToken(
      String(saved.refresh_token_ciphertext),
      String(saved.refresh_token_iv),
    )
  } catch {
    throw new HttpError(409, 'gmail_reconnect_required', 'Gmail 憑證已更新，請重新連結')
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: googleClientId,
      client_secret: googleClientSecret(),
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }),
  })

  if (!response.ok) {
    const detail = await parseGoogleError(response)
    if (/invalid_grant|revoked|expired/i.test(detail)) {
      await admin.from('gmail_connections').delete().eq('user_id', userId)
      throw new HttpError(409, 'gmail_reconnect_required', 'Gmail 授權已失效，請重新連結')
    }
    throw new HttpError(502, 'gmail_refresh_failed', detail || 'Gmail 授權暫時無法更新')
  }

  const tokens = await response.json()
  const encryptedAccess = await encryptToken(tokens.access_token)
  const expiresAt = new Date(Date.now() + (Number(tokens.expires_in) || 3600) * 1000).toISOString()
  const { error } = await admin
    .from('gmail_connections')
    .update({
      access_token_ciphertext: encryptedAccess.ciphertext,
      access_token_iv: encryptedAccess.iv,
      access_token_expires_at: expiresAt,
      updated_at: new Date().toISOString(),
    })
    .eq('user_id', userId)
  if (error) throw new HttpError(500, 'gmail_storage_failed', '無法保存更新後的 Gmail 憑證')
  return tokens.access_token as string
}

async function accessToken(userId: string, forceRefresh = false) {
  const row = await connection(userId)
  if (!row) throw new HttpError(409, 'gmail_reconnect_required', '請先連結 Gmail')
  const expiresAt = Date.parse(row.access_token_expires_at || '')
  if (
    !forceRefresh &&
    row.access_token_ciphertext &&
    row.access_token_iv &&
    expiresAt > Date.now() + 120_000
  ) {
    try {
      return await decryptToken(row.access_token_ciphertext, row.access_token_iv)
    } catch {
      return refreshAccessToken(userId, row)
    }
  }
  return refreshAccessToken(userId, row)
}

async function gmailFetch(userId: string, path: string) {
  let token = await accessToken(userId)
  let response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (response.status === 401) {
    token = await accessToken(userId, true)
    response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  }
  if (!response.ok) {
    const detail = await parseGoogleError(response)
    if (response.status === 403) {
      throw new HttpError(403, 'gmail_permission_denied', detail || 'Gmail 唯讀權限不足')
    }
    throw new HttpError(502, 'gmail_api_failed', detail || `Gmail API 錯誤 ${response.status}`)
  }
  return response.json()
}

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin') || ''
  if (!allowedOrigins.has(origin)) {
    return new Response('Origin not allowed', { status: 403 })
  }
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders(origin) })

  try {
    if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed', 'Method not allowed')
    if (req.headers.get('X-Requested-With') !== 'XmlHttpRequest') {
      throw new HttpError(403, 'invalid_request_origin', 'Invalid request origin')
    }

    const user = await currentUser(req)
    const body = await req.json()
    const action = String(body?.action || '')

    if (action === 'status') {
      const row = await connection(user.id)
      return json(origin, {
        connected: Boolean(row),
        email: row?.gmail_email || null,
        updatedAt: row?.updated_at || null,
      })
    }

    if (action === 'connect') {
      const code = String(body?.code || '')
      const redirectUri = String(body?.redirectUri || '')
      if (!code || redirectUri !== origin) {
        throw new HttpError(400, 'invalid_oauth_response', 'Gmail 授權回應無效')
      }

      const tokens = await exchangeAuthorizationCode(code, redirectUri)
      let refreshToken = tokens.refresh_token as string | undefined
      const existing = await connection(user.id)
      if (!refreshToken && existing) {
        refreshToken = await decryptToken(
          existing.refresh_token_ciphertext,
          existing.refresh_token_iv,
        )
      }
      if (!refreshToken) {
        throw new HttpError(
          409,
          'gmail_refresh_token_missing',
          'Google 未提供長效授權；請先撤銷 Journey P 權限後重新連結',
        )
      }

      const profileResponse = await fetch(
        'https://gmail.googleapis.com/gmail/v1/users/me/profile',
        { headers: { Authorization: `Bearer ${tokens.access_token}` } },
      )
      if (!profileResponse.ok) {
        throw new HttpError(403, 'gmail_permission_denied', '無法確認 Gmail 唯讀權限')
      }
      const profile = await profileResponse.json()
      const encryptedRefresh = await encryptToken(refreshToken)
      const encryptedAccess = await encryptToken(tokens.access_token)
      const expiresAt = new Date(
        Date.now() + (Number(tokens.expires_in) || 3600) * 1000,
      ).toISOString()
      const scopes = String(tokens.scope || gmailScope).split(/\s+/).filter(Boolean)

      const { error } = await admin.from('gmail_connections').upsert({
        user_id: user.id,
        refresh_token_ciphertext: encryptedRefresh.ciphertext,
        refresh_token_iv: encryptedRefresh.iv,
        access_token_ciphertext: encryptedAccess.ciphertext,
        access_token_iv: encryptedAccess.iv,
        access_token_expires_at: expiresAt,
        gmail_email: profile.emailAddress || user.email || null,
        scopes,
        updated_at: new Date().toISOString(),
      })
      if (error) throw new HttpError(500, 'gmail_storage_failed', '無法保存 Gmail 連結')
      return json(origin, { connected: true, email: profile.emailAddress || null })
    }

    if (action === 'disconnect') {
      const row = await connection(user.id)
      if (row) {
        try {
          const refreshToken = await decryptToken(
            row.refresh_token_ciphertext,
            row.refresh_token_iv,
          )
          await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(refreshToken)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          })
        } catch {
          // Local deletion still disconnects Journey P if Google revocation is unavailable.
        }
        await admin.from('gmail_connections').delete().eq('user_id', user.id)
      }
      return json(origin, { connected: false })
    }

    if (action === 'list') {
      const result = await gmailFetch(user.id, 'messages?labelIds=INBOX&maxResults=30')
      const messages = await Promise.all(
        (result.messages || []).map((item: { id: string }) =>
          gmailFetch(
            user.id,
            `messages/${encodeURIComponent(item.id)}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date`,
          )
        ),
      )
      return json(origin, { messages })
    }

    if (action === 'message') {
      const messageId = String(body?.messageId || '')
      if (!/^[A-Za-z0-9_-]{4,256}$/.test(messageId)) {
        throw new HttpError(400, 'invalid_message_id', '信件識別碼無效')
      }
      const message = await gmailFetch(
        user.id,
        `messages/${encodeURIComponent(messageId)}?format=full`,
      )
      return json(origin, { message })
    }

    throw new HttpError(400, 'unknown_action', '未知的 Gmail 操作')
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500
    const code = error instanceof HttpError ? error.code : 'gmail_server_error'
    const message = error instanceof HttpError ? error.message : 'Gmail 後端暫時無法使用'
    console.error('gmail-proxy request failed', { status, code })
    return json(origin, { error: message, code }, status)
  }
})
