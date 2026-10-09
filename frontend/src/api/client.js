export const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

export async function request(path, options = {}) {
  const headers = { ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...(options.headers || {}) }
  const accessToken = localStorage.getItem('sg_token')
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), options.timeout || 10000)
  let response
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers, signal: controller.signal })
  } catch (error) {
    throw new Error(error.name === 'AbortError' ? '请求超时，请检查主服务' : '无法连接主服务')
  } finally {
    clearTimeout(timeout)
  }
  let payload
  try { payload = await response.json() } catch { throw new Error(`服务返回了无效响应 (${response.status})`) }
  if (response.status === 401) {
    localStorage.removeItem('sg_token')
    localStorage.removeItem('sg_demo')
    window.dispatchEvent(new Event('sg:token-expired'))
    throw new Error(payload.error?.message || '登录已失效，请重新登录')
  }
  if (response.status === 403) throw new Error(payload.error?.message || '当前账号没有执行模型检测的权限')
  if (!response.ok || payload.error) throw new Error(payload.error?.message || `请求失败 (${response.status})`)
  return payload.data
}

export function stream(path, onMessage, onError, onOpen) {
  let stopped = false
  let controller
  let retry = 0
  let retryTimer
  const connect = async () => {
    controller = new AbortController()
    const accessToken = localStorage.getItem('sg_token')
    try {
      const response = await fetch(`${API_BASE}${path}`, { headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {}, signal: controller.signal })
      if (response.status === 401) window.dispatchEvent(new Event('sg:token-expired'))
      if (!response.ok || !response.body) throw new Error('SSE connection failed')
      retry = 0
      onOpen?.()
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (!stopped) {
        const result = await reader.read()
        if (result.done) break
        buffer += decoder.decode(result.value, { stream: true })
        const chunks = buffer.split('\n\n')
        buffer = chunks.pop() || ''
        chunks.forEach(chunk => {
          const line = chunk.split('\n').find(item => item.startsWith('data:'))
          if (!line) return
          try { onMessage(JSON.parse(line.slice(5).trim())) } catch { return undefined }
        })
      }
    } catch (error) {
      if (!stopped) onError?.(error)
    }
  }
  const connectWithRetry = async () => {
    await connect()
    if (!stopped) {
      retry += 1
      retryTimer = setTimeout(connectWithRetry, Math.min(30000, 1000 * 2 ** Math.min(retry, 5)))
    }
  }
  connectWithRetry()
  return () => {
    stopped = true
    clearTimeout(retryTimer)
    controller?.abort()
  }
}

