import { useEffect, useRef, useState } from 'react'
import { Check, FileSpreadsheet, FileUp, Play, Square, Wifi } from 'lucide-react'
import { API_BASE, request } from '../api/client'
import './PipelineControl.css'


const SOURCES = [
  { value: 'csv', label: '内置 CSV', description: '使用系统内置数据集进行离线检测', action: '开始检测', icon: FileSpreadsheet },
  { value: 'pcap', label: '外部 PCAP', description: '上传本地 PCAP 文件进行离线分析', action: '开始分析', icon: FileUp },
  { value: 'interface', label: 'WLAN 实时', description: '通过选定网卡实时采集网络数据', action: '开始实时检测', icon: Wifi },
]


export default function PipelineControl() {
  const [status, setStatus] = useState({ running: false, sampling: { source: 'csv' } })
  const [sourceState, setSourceState] = useState({ sources: [], interfaces: [] })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [uploadProgress, setUploadProgress] = useState(null)
  const [showInterfaces, setShowInterfaces] = useState(false)
  const fileInput = useRef(null)

  const refresh = async () => {
    try {
      const [nextStatus, nextSources] = await Promise.all([
        request('/api/v1/pipeline'),
        request('/api/v1/pipeline/sources'),
      ])
      setStatus(nextStatus)
      setSourceState(nextSources)
      setError('')
    } catch (reason) {
      setError(reason.message)
    }
  }

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 5000)
    return () => clearInterval(timer)
  }, [])

  const runAction = async action => {
    setBusy(true)
    setError('')
    try {
      const next = await action()
      if (next?.sampling) setStatus(next)
      setSourceState(await request('/api/v1/pipeline/sources'))
      return next
    } catch (reason) {
      setError(reason.message)
    } finally {
      setBusy(false)
    }
  }

  const toggle = () => runAction(() => request(`/api/v1/pipeline/${status.running ? 'stop' : 'start'}`, { method: 'POST' }))
  const switchSource = (source, extra = {}) => runAction(() => request('/api/v1/pipeline/source', {
    method: 'POST',
    body: JSON.stringify({ source, ...extra }),
  }))

  const uploadPcap = async event => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setError('仅支持 .pcap 或 .pcapng 文件')
      return
    }
    if (file.size > 50 * 1024 * 1024) {
      setError('PCAP 文件不能超过 50 MB')
      return
    }
    setBusy(true)
    setError('')
    setUploadProgress(0)
    try {
      const next = await uploadPcapFile(file, setUploadProgress)
      setStatus(next)
      setSourceState(await request('/api/v1/pipeline/sources'))
    } catch (reason) {
      setError(reason.message)
    } finally {
      setBusy(false)
      setUploadProgress(null)
    }
  }

  const selectInterface = async item => {
    const result = await switchSource('interface', { interface: item.deviceId })
    if (result) setShowInterfaces(false)
  }

  const running = status.running
  const currentSource = SOURCES.find(item => item.value === status.sampling?.source) || SOURCES[0]
  const sourceDetails = Object.fromEntries((sourceState.sources || []).map(item => [item.source, item]))
  const title = error || (running
    ? `采样中 · 已处理 ${status.batchesProcessed || 0} 批 · 新增 ${status.insertedSamples || 0} 条 · 跳过 ${status.duplicateSamples || 0} 条`
    : status.sampling?.available === false ? '当前采样源未配置或不可用' : '自动采样检测已关闭')

  return (
    <div className="pipeline-control" title={title} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div className="pipeline-source-wrap">
        <span className="pipeline-source-label">数据源</span>
        <div className="segmented pipeline-sources" role="radiogroup" aria-label="检测数据源">
          {SOURCES.map(item => {
            const Icon = item.icon
            const selected = status.sampling?.source === item.value
            return <button
              key={item.value}
              className={`pipeline-source-option ${selected ? 'selected' : ''}`}
              disabled={busy}
              role="radio"
              aria-checked={selected}
              title={sourceDetails[item.value]?.reason || sourceDetails[item.value]?.fileName || item.description}
              onClick={() => item.value === 'pcap'
                ? fileInput.current?.click()
                : item.value === 'interface'
                  ? setShowInterfaces(value => !value)
                  : switchSource('csv')}
            >
              <Icon size={12}/><span>{item.label}</span>{selected && <Check className="source-check" size={10}/>}<i aria-hidden="true"/>
            </button>
          })}
        </div>
      </div>
      <input ref={fileInput} className="pipeline-file-input" type="file" accept=".pcap,.pcapng" onChange={uploadPcap}/>
      {showInterfaces && <div className="pipeline-interface-popover">
        <div className="pipeline-popover-title"><Wifi size={13}/>选择实时网卡</div>
        {(sourceState.interfaces || []).length ? sourceState.interfaces.map(item => (
          <button key={item.deviceId} disabled={busy || !item.available} onClick={() => selectInterface(item)}>
            <span><b>{item.name}{item.recommended ? ' · 推荐' : ''}</b><small>{item.description}</small></span>
            <em>{item.ip}</em>
          </button>
        )) : <p>{sourceDetails.interface?.reason || '未发现可用网卡'}</p>}
      </div>}
      <button className={running ? 'pipeline-toggle pipeline-stop' : 'primary pipeline-toggle'} disabled={busy} onClick={toggle}>
        {running ? <Square size={13}/> : <Play size={13}/>}
        {busy ? uploadProgress == null ? '处理中…' : `上传 ${uploadProgress}%` : running ? '停止检测' : currentSource.action}
      </button>
      <span className={`pipeline-run-state ${running ? 'running' : ''}`}><span className={`dot ${running ? 'online' : ''}`}/>{running ? '正在检测' : '已停止'}</span>
      {running && <span className="pipeline-counts">新增 {status.insertedSamples || 0} · 跳过 {status.duplicateSamples || 0}</span>}
      {error && <span className="pipeline-error">{error}</span>}
    </div>
  )
}


function uploadPcapFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const form = new FormData()
    form.append('file', file)
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${API_BASE}/api/v1/pipeline/pcap`)
    const token = localStorage.getItem('sg_token')
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    xhr.upload.onprogress = event => {
      if (event.lengthComputable) onProgress(Math.round(event.loaded * 100 / event.total))
    }
    xhr.onerror = () => reject(new Error('PCAP 上传失败，请检查主服务'))
    xhr.ontimeout = () => reject(new Error('PCAP 上传超时'))
    xhr.onload = () => {
      let payload
      try { payload = JSON.parse(xhr.responseText) } catch { reject(new Error(`服务返回了无效响应 (${xhr.status})`)); return }
      if (xhr.status === 401) window.dispatchEvent(new Event('sg:token-expired'))
      if (xhr.status < 200 || xhr.status >= 300 || payload.error) reject(new Error(payload.error?.message || `上传失败 (${xhr.status})`))
      else resolve(payload.data)
    }
    xhr.timeout = 120000
    xhr.send(form)
  })
}

