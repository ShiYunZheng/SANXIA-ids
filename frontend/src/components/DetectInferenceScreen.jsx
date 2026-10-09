import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, CheckCircle2, CircleAlert, Cpu, FileSearch, FileUp, Play, Radio, ShieldCheck, Square, UploadCloud, Wifi, XCircle } from 'lucide-react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../api/services'
import { stream } from '../api/client'
import BigScreenShell, { CHART_TOOLTIP, ScreenPanel } from './BigScreenShell'
import { useDetectionSession } from '../state/DetectionSessionContext'
import './BigScreenPages.css'
import './DetectInferenceScreen.css'

const isSupported = file => file && ['.csv', '.pcap', '.pcapng'].some(ext => file.name.toLowerCase().endsWith(ext))
const isPcapFile = file => file && ['.pcap', '.pcapng'].some(ext => file.name.toLowerCase().endsWith(ext))
const systemResult = system => system?.result?.data || system?.result || {}
const displayLabel = (types, value) => typeof value === 'number' ? (types[value] || `Class ${value}`) : (value ?? '--')
const systemError = error => {
  const value = String(error || '')
  if (value.includes('独立校验服务未') || value.includes('HTTP 404') || value.includes('404')) return '独立校验暂不可用，SANXIA 主检测结果仍然有效'
  return value
}
const formatPercent = value => Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : '--'
const formatValue = value => value == null || value === '' ? '--' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const windowRange = row => row.packetRange || (row.packetStart != null || row.packetEnd != null ? `${row.packetStart ?? '?'} - ${row.packetEnd ?? '?'}` : '--')
const windowKey = row => `${row.sampleId ?? row.index ?? row.windowIndex ?? 'window'}:${row.predictedLabel ?? 'unknown'}`
const isNormalPrediction = value => {
  const label = String(value ?? '').trim().toLowerCase()
  return label === 'normal' || label === '正常' || label === '正常流量'
}
const featureEntries = value => Array.isArray(value)
  ? value.map((entry, index) => [`证据 ${index + 1}`, formatValue(entry)])
  : Object.entries(value || {}).map(([key, entry]) => [key, formatValue(entry)])
const chartColors = ['#27d6a2', '#2374ff', '#ff565f', '#ffae43', '#8a73ff', '#19d3ff', '#b7d7ff', '#4de0b4']
const WLAN_MACHINE_NAME = '以太网交换机'
const mergeLiveEvents = (current, incoming) => {
  const merged = new Map()
  ;[...(incoming || []), ...current].forEach((event, index) => {
    const key = String(event?._id || `${event?.pipelineRunId || 'event'}:${event?.eventType || index}:${event?.start_timestamp || index}`)
    if (!merged.has(key)) merged.set(key, event)
  })
  return [...merged.values()].slice(0, 100)
}
const mergeRuntimeAlerts = (current, incoming) => {
  const merged = new Map()
  ;[...(incoming || []), ...current].forEach((alert, index) => {
    const key = String(alert?.alertId || `${alert?.runId || 'run'}:${alert?.attackLabel || index}:${alert?.source || ''}:${alert?.target || ''}:${alert?.emittedAt || index}`)
    if (!merged.has(key)) merged.set(key, alert)
  })
  return [...merged.values()].slice(0, 200)
}

function EmptyChart({ text = '等待真实推理结果' }) {
  return <div className="inference-chart-empty"><Activity size={25}/><span>{text}</span></div>
}

function ChartCard({ title, badge, children }) {
  return <div className="inference-chart-card"><div className="inference-chart-head"><b>{title}</b><span>{badge}</span></div><div className="inference-chart-body">{children}</div></div>
}

function RunState({ running, system }) {
  const unavailable = system && !system.ok && /未启动|暂不可用|HTTP 404|404/.test(systemError(system.error))
  const state = running ? 'running' : !system ? 'idle' : system.ok ? 'done' : unavailable ? 'unavailable' : 'error'
  const label = { idle: '等待', running: '推理中', done: '完成', unavailable: '不可用', error: '失败' }[state]
  const Icon = state === 'done' ? CheckCircle2 : state === 'error' ? XCircle : state === 'unavailable' ? AlertTriangle : Activity
  return <span className={`validation-status ${state}`}><Icon size={13}/>{label}</span>
}

export default function DetectInferenceScreen({ user, onNavigate, onLogout }) {
  const [health, setHealth] = useState(null)
  const { file, fileMeta, busy, runStartedAt, error, report, view, resultFilter, associationCache, hydrated, persistenceNotice, selectFile, runDetection, setError, setView, setResultFilter, setAssociationCache } = useDetectionSession()
  const [runElapsed, setRunElapsed] = useState(0)
  const [selected, setSelected] = useState(null)
  const [associationBusy, setAssociationBusy] = useState(false)
  const [associationError, setAssociationError] = useState('')
  const [dataMode, setDataMode] = useState('file')
  const [pipeline, setPipeline] = useState(null)
  const [sourceState, setSourceState] = useState({ sources: [], interfaces: [] })
  const [monitorBusy, setMonitorBusy] = useState(false)
  const [monitorError, setMonitorError] = useState('')
  const [monitorNotice, setMonitorNotice] = useState('')
  const [noPersist, setNoPersist] = useState(false)
  const [liveEvents, setLiveEvents] = useState([])
  const [runtimeAlerts, setRuntimeAlerts] = useState([])
  const [liveConnected, setLiveConnected] = useState(false)
  const [liveResetPending, setLiveResetPending] = useState(false)
  const currentRunIdRef = useRef(null)
  const currentSourceContextIdRef = useRef(null)
  const pendingSourceResetRef = useRef(false)

  const resetLiveRunView = () => {
    setLiveEvents([])
    setRuntimeAlerts([])
    setSelected(null)
  }

  const updatePipelineScope = nextPipeline => {
    const nextRunId = nextPipeline?.runId || null
    const nextContextId = nextPipeline?.sourceContextId || null
    const contextChanged = currentSourceContextIdRef.current !== null && nextContextId !== currentSourceContextIdRef.current
    const runChanged = nextRunId !== currentRunIdRef.current
    if (contextChanged || runChanged) resetLiveRunView()
    currentSourceContextIdRef.current = nextContextId
    currentRunIdRef.current = nextRunId
    if (contextChanged && pendingSourceResetRef.current) {
      pendingSourceResetRef.current = false
      setLiveResetPending(false)
    }
    return { nextRunId, canLoad: Boolean(nextRunId) && !pendingSourceResetRef.current }
  }

  useEffect(() => {
    if (user?.demo) {
      setHealth({ models: { cascade: { ready: true, device: 'demo', unknownThreshold: '--' } }, demo: true })
      setError('')
      return undefined
    }
    let active = true
    api.health().then(value => { if (active) setHealth(value) }).catch(reason => { if (active) setError(reason?.message || '模型健康状态不可用') })
    return () => { active = false }
  }, [user?.demo])

  useEffect(() => {
    if (user?.demo) {
      setPipeline({ running: false, runStatus: 'idle', processedSamples: 0, attackSamples: 0, alertsDetected: 0, eventsCreated: 0, duplicateSamples: 0, sampling: { source: 'interface', capturedSamples: 0, bufferedSamples: 0, running: false } })
      setSourceState({ sources: [], interfaces: [] })
      return undefined
    }
    let active = true
    const refresh = async () => {
      try {
        const [nextPipeline, nextSources] = await Promise.all([api.pipelineStatus(), api.pipelineSources()])
        if (active) {
          const { nextRunId, canLoad } = updatePipelineScope(nextPipeline)
          setPipeline(nextPipeline); setSourceState(nextSources); setMonitorError('')
          if (canLoad) {
            api.pipelineAlerts(nextRunId, 100)
              .then(items => { if (active && currentRunIdRef.current === nextRunId) setRuntimeAlerts(current => mergeRuntimeAlerts(current, items)) })
              .catch(() => undefined)
            if (!nextPipeline.shadowMode) {
              api.events(1, 100, { pipelineRunId: nextRunId })
                .then(result => { if (active && currentRunIdRef.current === nextRunId) setLiveEvents(current => mergeLiveEvents(current, result.events)) })
                .catch(() => undefined)
            }
          }
        }
      } catch (reason) { if (active) setMonitorError(reason?.message || '无法读取实时检测状态') }
    }
    refresh()
    const timer = window.setInterval(refresh, 3000)
    const close = stream('/api/v1/events/stream', event => {
      if (!event || !active) return
      const runId = currentRunIdRef.current
      if (!pendingSourceResetRef.current && runId && event.pipelineRunId === runId) setLiveEvents(current => mergeLiveEvents(current, [event]))
    }, () => active && setLiveConnected(false), () => active && setLiveConnected(true))
    const closeAlerts = stream('/api/v1/pipeline/alerts/stream', alert => {
      if (!alert || !active) return
      const runId = currentRunIdRef.current
      if (!pendingSourceResetRef.current && runId && alert.runId === runId) setRuntimeAlerts(current => mergeRuntimeAlerts(current, [alert]))
    })
    return () => { active = false; window.clearInterval(timer); close?.(); closeAlerts?.() }
  }, [user?.demo])

  useEffect(() => {
    if (view === 'diff') setView('live')
  }, [view, setView])

  useEffect(() => {
    if (!selected) return undefined
    const closeOnEscape = event => { if (event.key === 'Escape') setSelected(null) }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [selected])

  useEffect(() => {
    if (!runStartedAt) return undefined
    const update = () => setRunElapsed(Math.max(0, Math.floor((Date.now() - runStartedAt) / 1000)))
    update()
    const timer = setInterval(update, 1000)
    return () => clearInterval(timer)
  }, [runStartedAt])

  const pickFile = event => {
    const next = event.target.files?.[0]
    event.target.value = ''
    const isReplayFile = isPcapFile(next)
    if (isSupported(next) && (dataMode !== 'replay' || isReplayFile)) {
      selectFile(next, { clearReport: dataMode === 'file' })
      setError('')
      if (dataMode === 'replay') {
        pendingSourceResetRef.current = true
        setLiveResetPending(true)
        resetLiveRunView()
        setMonitorError('')
      }
      setMonitorNotice(dataMode === 'replay' ? 'PCAP 已就绪，旧的本轮结果已清空，点击“上传并开始模拟”' : '文件已就绪，可以开始检测')
    }
    else setError('仅支持 CSV、PCAP 或 PCAPNG 文件')
  }

  const changeDataMode = mode => {
    setDataMode(mode)
    setMonitorError('')
    setMonitorNotice('')
    setView(mode === 'file' ? 'sanxia' : 'live')
  }

  const refreshPipeline = async () => {
    if (user?.demo) return
    try {
      const [nextPipeline, nextSources] = await Promise.all([api.pipelineStatus(), api.pipelineSources()])
      const { nextRunId, canLoad } = updatePipelineScope(nextPipeline)
      setPipeline(nextPipeline); setSourceState(nextSources); setMonitorError('')
      if (canLoad) {
        const alerts = await api.pipelineAlerts(nextRunId, 100)
        if (currentRunIdRef.current === nextRunId) setRuntimeAlerts(current => mergeRuntimeAlerts(current, alerts))
        if (!nextPipeline.shadowMode) {
          const result = await api.events(1, 100, { pipelineRunId: nextRunId })
          if (currentRunIdRef.current === nextRunId) setLiveEvents(current => mergeLiveEvents(current, result.events))
        }
      }
    } catch (reason) { setMonitorError(reason?.message || '无法读取实时检测状态') }
  }

  const selectInterface = async deviceId => {
    if (!deviceId || monitorBusy) return
    setMonitorBusy(true); setMonitorError(''); setMonitorNotice('')
    try { await api.pipelineSource('interface', { interface: deviceId, machineName: WLAN_MACHINE_NAME }); setDataMode('interface'); setMonitorNotice('WLAN 网卡已就绪，资产归属“以太网交换机”，可以开始实时监测'); await refreshPipeline() }
    catch (reason) { setMonitorError(reason?.message || 'WLAN 网卡不可用') }
    finally { setMonitorBusy(false) }
  }

  const toggleMonitor = async () => {
    if (monitorBusy || user?.demo) return
    setMonitorBusy(true); setMonitorError(''); setMonitorNotice('')
    try {
      if (pipeline?.running) {
        await api.pipelineStop()
        setMonitorNotice(dataMode === 'replay' ? '模拟 WLAN 回放已停止' : '实时监测已停止')
      } else {
        resetLiveRunView()
        if (dataMode === 'replay') {
          if (!file && sampling.source !== 'replay') {
            setMonitorError('请先选择 PCAP/PCAPNG 文件')
            return
          }
          if (file) {
            const prepared = await api.pipelinePcap(file, 'replay', { machineName: WLAN_MACHINE_NAME })
            updatePipelineScope(prepared)
            setPipeline(prepared)
            pendingSourceResetRef.current = false
            setLiveResetPending(false)
          }
          await api.pipelineStart({ persist: !noPersist })
          setMonitorNotice(noPersist ? '模拟 WLAN 影子检测已启动，本轮不写数据库' : '模拟 WLAN 已启动，正在按实时节奏回放 PCAP')
        } else {
          await api.pipelineStart({ persist: !noPersist })
          setMonitorNotice(noPersist ? 'WLAN 影子检测已启动，本轮不写数据库' : '实时监测已启动')
        }
      }
      await refreshPipeline()
    } catch (reason) { setMonitorError(reason?.message || '实时检测流水线操作失败') }
    finally { setMonitorBusy(false) }
  }

  const run = async () => {
    if (dataMode !== 'file' || !file || busy) return
    setRunElapsed(0); setSelected(null); setAssociationError('')
    await runDetection()
  }

  const model = health?.models?.cascade || {}
  const sanxia = report?.systems?.sanxia
  const standalone = report?.systems?.standalone
  const sanxiaData = systemResult(sanxia)
  const standaloneData = systemResult(standalone)
  const standaloneWindows = Array.isArray(standaloneData.windows) ? standaloneData.windows : []
  const abnormalWindows = useMemo(() => standaloneWindows.filter(row => !isNormalPrediction(row.predictedLabel)), [standaloneWindows])
  const normalWindows = useMemo(() => standaloneWindows.filter(row => isNormalPrediction(row.predictedLabel)), [standaloneWindows])
  const visibleStandaloneWindows = useMemo(() => {
    const source = resultFilter === 'abnormal' ? abnormalWindows : resultFilter === 'normal' ? normalWindows : [...abnormalWindows, ...normalWindows]
    return source
  }, [abnormalWindows, normalWindows, resultFilter])
  const attackTypes = sanxiaData.attack_types || []
  const current = view === 'standalone' ? standaloneData : sanxiaData
  const labels = current.labels || []
  const counts = useMemo(() => labels.reduce((map, value) => { const name = displayLabel(attackTypes, value); map[name] = (map[name] || 0) + 1; return map }, {}), [labels, attackTypes])
  const normal = counts.Normal || counts.normal || 0
  const unknown = counts['未知攻击'] || counts.unknown || 0
  const attacks = Math.max(labels.length - normal, 0)
  const differences = report?.differences || []
  const independent = report?.summary?.comparisonMode === 'independent'
  const unknownValues = (sanxiaData.unknown_scores || []).filter(value => Number.isFinite(value))
  const trafficDistribution = useMemo(() => [
    { name: '正常流量', value: normal, color: '#27d6a2' },
    { name: '已知攻击', value: Math.max(attacks - unknown, 0), color: '#2374ff' },
    { name: '未知攻击', value: unknown, color: '#ff565f' },
  ].filter(item => item.value > 0), [normal, attacks, unknown])
  const classificationRanking = useMemo(() => Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, value], index) => ({ name, value, color: chartColors[index % chartColors.length] })), [counts])
  const selectedAssociation = selected?.kind === 'standalone' ? associationCache[windowKey(selected.data)] : null
  const loadAssociation = async (data, force = false) => {
    if (!data || associationBusy) return
    const key = windowKey(data)
    if (!force && associationCache[key]) return
    setAssociationBusy(true); setAssociationError('')
    try {
      const result = await api.validationAssociation(data, force)
      setAssociationCache(cache => ({ ...cache, [key]: result }))
    } catch (reason) {
      setAssociationError(reason?.message || '关联研判加载失败')
    } finally { setAssociationBusy(false) }
  }
  const selectStandalone = data => {
    setSelected({ kind: 'standalone', data })
    setAssociationError('')
    if (!user?.demo) void loadAssociation(data)
  }

  const sampling = pipeline?.sampling || {}
  const livePipeline = liveResetPending ? {
    ...pipeline,
    running: false,
    runId: null,
    runStatus: 'idle',
    processedSamples: 0,
    attackSamples: 0,
    runtimeAlerts: 0,
    eventsCreated: 0,
    duplicateSamples: 0,
    duplicateAlerts: 0,
  } : pipeline
  const interfaces = sourceState?.interfaces || []
  const selectedInterface = sourceState?.selectedInterface || ''
  const selectedInterfaceInfo = interfaces.find(item => item.deviceId === selectedInterface)
  const monitorRunning = Boolean(livePipeline?.running)
  const replayFileName = dataMode === 'replay' && isPcapFile(file) ? file.name : (sampling.source === 'replay' ? sampling.sourceFileName : '')
  const monitorStatus = user?.demo ? 'DEMO' : monitorError ? '失败' : liveResetPending ? '等待开始' : livePipeline?.runStatus === 'completed' ? '已完成' : livePipeline?.runStatus === 'stopped' ? '已停止' : dataMode === 'replay' ? monitorRunning ? (sampling.running ? '正在回放' : '正在推理') : replayFileName ? 'SIMULATED' : '等待 PCAP' : monitorRunning ? (sampling.running ? '正在采集' : '正在推理') : '未启动'
  const monitorSourceReady = dataMode === 'interface' ? Boolean(selectedInterface || sampling.interfaceName) : dataMode === 'replay' ? Boolean(replayFileName) : false
  const liveMode = dataMode === 'interface' || dataMode === 'replay'
  const reportFileName = report?.input?.filename || fileMeta?.name || ''
  const displayFileName = file?.name || reportFileName
  const sourceDescription = dataMode === 'interface' ? 'WLAN 网卡采集 · 模型实时推理' : dataMode === 'replay' ? '模拟 WLAN · PCAP 实时回放 · 模型推理' : 'CSV / PCAP / PCAPNG 离线检测'
  const sourceStatus = liveMode && livePipeline?.shadowMode ? `SHADOW · ${monitorStatus}` : liveMode ? monitorStatus : user?.demo ? 'DEMO' : file ? '文件已就绪' : report ? '结果已恢复' : '等待输入'

  return <BigScreenShell page="detect" pageTitle="检测推理" subtitle="Keras 已知攻击 + TorchScript 未知攻击 · standalone 独立校验" live={model.ready || Boolean(report)} user={user} onNavigate={onNavigate} onLogout={onLogout}>
    <div className="screen-page screen-page-detect detect-inference-page">
      <section className="inference-source-strip">
        <div className="inference-source-title"><div className="inference-source-icon">{dataMode === 'replay' ? <Radio size={18}/> : <Wifi size={18}/>}</div><div><b>数据源与实时检测</b><small>{sourceDescription}</small></div><span className={`inference-source-status ${livePipeline?.shadowMode ? 'shadow' : monitorRunning ? 'running' : monitorError ? 'error' : user?.demo ? 'demo' : dataMode === 'replay' ? 'simulated' : ''}`}><i/>{sourceStatus}</span></div>
        <div className="inference-source-modes"><button className={dataMode === 'file' ? 'active' : ''} onClick={() => changeDataMode('file')}><FileUp size={14}/>文件检测</button><button className={dataMode === 'interface' ? 'active' : ''} onClick={() => changeDataMode('interface')}><Wifi size={14}/>WLAN 实时</button><button className={dataMode === 'replay' ? 'active simulated' : ''} onClick={() => changeDataMode('replay')}><Radio size={14}/>模拟 WLAN</button></div>
        <div className="inference-source-input">{dataMode === 'file' ? <label className="inference-file-picker"><UploadCloud size={15}/><span>{displayFileName || '选择 CSV / PCAP / PCAPNG'}</span><input type="file" accept=".csv,.pcap,.pcapng" onChange={pickFile} disabled={!hydrated || busy}/></label> : dataMode === 'replay' ? <label className="inference-file-picker replay-picker"><Radio size={15}/><span>{replayFileName || '选择 PCAP / PCAPNG 回放文件'}</span><input type="file" accept=".pcap,.pcapng" onChange={pickFile} disabled={!hydrated || busy || monitorBusy}/></label> : <select value={selectedInterface} onChange={event => selectInterface(event.target.value)} disabled={monitorBusy || monitorRunning}><option value="">选择 WLAN 网卡</option>{interfaces.map(item => <option key={item.deviceId} value={item.deviceId} disabled={!item.available}>{item.name}{item.recommended ? ' · 推荐' : ''} · {item.ip}</option>)}</select>}</div>
        <div className="inference-source-actions">{dataMode === 'file' ? <button className="source-action primary" disabled={!hydrated || !file || busy} onClick={run}>{busy ? `推理 ${runElapsed}s` : '开始检测'}<FileSearch size={15}/></button> : <><button className={`source-action ${monitorRunning ? 'danger' : 'primary'} ${dataMode === 'replay' ? 'simulated-action' : ''}`} disabled={user?.demo || monitorBusy || (!monitorRunning && !monitorSourceReady)} onClick={toggleMonitor}>{monitorRunning ? <><Square size={14}/>{dataMode === 'replay' ? '停止模拟' : '停止监测'}</> : <><Play size={14}/>{dataMode === 'replay' ? (sampling.source === 'replay' && !file ? '开始模拟回放' : '上传并开始模拟') : '开始实时监测'}</>}</button><label className={`shadow-mode-toggle ${noPersist ? 'active' : ''}`}><input type="checkbox" checked={noPersist} disabled={monitorRunning || monitorBusy} onChange={event => setNoPersist(event.target.checked)}/><span/>本次不入库</label></>}</div>
        <div className="inference-source-metrics"><span><b>{liveMode ? livePipeline?.processedSamples ?? 0 : (file?.size || fileMeta?.size) ? `${((file?.size || fileMeta.size) / 1024).toFixed(1)} KB` : '--'}</b><small>{liveMode ? '已处理流量' : '输入文件'}</small></span><span><b>{liveMode ? livePipeline?.attackSamples ?? 0 : liveEvents.length}</b><small>{liveMode ? '攻击样本' : '实时事件'}</small></span><span className="danger"><b>{liveMode ? livePipeline?.runtimeAlerts ?? 0 : '--'}</b><small>实时告警</small></span></div>
        <div className="inference-source-note">{monitorNotice || (monitorError ? <><CircleAlert size={13}/>{monitorError}</> : liveMode && noPersist ? <><ShieldCheck size={13}/>影子检测：执行完整推理与告警展示，但不写业务数据库</> : dataMode === 'interface' ? (selectedInterfaceInfo?.name || sampling.interfaceName || (user?.demo ? '演示模式不连接真实网卡' : '请选择 WLAN 网卡')) : dataMode === 'replay' ? (user?.demo ? '演示模式不连接主服务，无法启动模拟回放' : '选择 PCAP/PCAPNG 后上传并按实时节奏回放') : '上传文件后执行已知攻击 + 未知攻击级联检测')}</div>
      </section>
      <div className="validation-top-grid">
        <ScreenPanel title="模型并行检测" icon={dataMode === 'replay' ? Radio : dataMode === 'interface' ? Wifi : UploadCloud} badge={dataMode === 'interface' ? 'WLAN LIVE' : dataMode === 'replay' ? 'SIMULATED WLAN' : 'PCAP / PCAPNG / RAW CSV'}>
          <div className="validation-input-summary"><div className="validation-input-icon">{dataMode === 'replay' ? <Radio size={28}/> : dataMode === 'interface' ? <Wifi size={28}/> : <UploadCloud size={28}/>}</div><div><b>{dataMode === 'interface' ? (selectedInterfaceInfo?.name || sampling.interfaceName || '等待选择 WLAN 网卡') : dataMode === 'replay' ? (replayFileName || '等待选择 PCAP 回放文件') : (displayFileName || '等待选择流量文件')}</b><small>{dataMode === 'interface' ? (selectedInterfaceInfo?.ip || '实时网卡采样') : dataMode === 'replay' ? (replayFileName ? `${(file?.size / 1024).toFixed(1)} KB · 模拟 WLAN 回放` : '上传 PCAP 后按实时节奏回放') : file ? `${(file.size / 1024).toFixed(1)} KB · 文件已就绪` : report ? '已恢复上次检测结果 · 重新检测需选择文件' : 'CSV 必须包含 raw_bytes 或 byte_n 原始字节列'}</small></div></div>
          {busy && <div className="inference-running-note"><span className="inference-spinner"/><div><b>请求已提交，正在处理真实流量</b><small>PCAP/PCAPNG 会先完成 SANXIA 逐包检测，再等待独立校验返回，请勿重复点击</small></div></div>}
          {error && <p className="inference-error"><AlertTriangle size={14}/>{error}</p>}
          {persistenceNotice && <p className="inference-error persistence-warning"><CircleAlert size={14}/>{persistenceNotice}</p>}
          <div className="validation-system-grid">
            <div className="validation-system-card"><div><b>SANXIA 正式检测</b><RunState running={busy} system={sanxia}/></div><small>逐包 · Keras → TorchScript 级联</small><span>{sanxia?.error || (sanxia?.elapsedMs != null ? `${sanxia.elapsedMs} ms · ${sanxiaData.labels?.length || 0} 包` : '等待真实输入')}</span></div>
            <div className="validation-system-card"><div><b>standalone 独立校验</b><RunState running={busy} system={standalone}/></div><small>滑动窗口 · 不覆盖正式结果</small><span>{systemError(standalone?.error) || (standalone?.elapsedMs != null ? `${standalone.elapsedMs} ms · ${standaloneData.labels?.length || 0} 窗` : '等待服务')}</span></div>
          </div>
        </ScreenPanel>

        <ScreenPanel title="模型加载与推理状态" icon={Cpu} badge={user.demo ? 'DEMO MODEL' : model.ready ? 'MODEL READY' : 'MODEL CHECK'}>
          <div className="validation-model-list">
            <div><span className={model.ready ? 'ok' : 'warn'}>{model.ready ? 'READY' : 'DOWN'}</span><b>已知攻击 · Keras</b><small>17 类 · 输入 (120, 1) · {String(model.device || 'cpu').toUpperCase()}</small></div>
            <div><span className={model.ready ? 'ok' : 'warn'}>{model.ready ? 'READY' : 'DOWN'}</span><b>未知攻击 · TorchScript</b><small>输入 120 bytes · 阈值 {model.unknownThreshold ?? '--'}</small></div>
            <div><span className={standalone?.ok ? 'ok' : standalone ? 'warn' : ''}>{standalone?.ok ? 'READY' : standalone ? 'DOWN' : 'WAIT'}</span><b>standalone 校验</b><small>{systemError(standalone?.error) || '独立窗口结果，不与逐包下标强行对齐'}</small></div>
          </div>
          <div className="validation-note"><ShieldCheck size={18}/><span>{user.demo ? '演示模式：使用本地演示数据，不连接主服务。' : model.loadError ? `模型加载失败：${model.loadError}` : model.ready ? `模型已真实加载，耗时 ${model.loadElapsedMs ?? '--'} ms。` : '资源存在不代表可推理，请检查后端健康状态。'}</span></div>
        </ScreenPanel>
      </div>

      <div className="inference-chart-grid single-chart">
        <ChartCard title="攻击与流量分布" badge={view === 'standalone' ? 'STANDALONE' : 'SANXIA'}>
          {trafficDistribution.length ? <div className="traffic-chart-layout"><div className="traffic-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={trafficDistribution} dataKey="value" innerRadius="57%" outerRadius="82%" paddingAngle={3} stroke="none">{trafficDistribution.map(item => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={CHART_TOOLTIP}/></PieChart></ResponsiveContainer><div><strong>{labels.length}</strong><span>样本总量</span></div></div><div className="traffic-legend">{trafficDistribution.map(item => <div key={item.name}><i style={{ background: item.color }}/><span>{item.name}</span><b>{item.value}</b></div>)}<div className="classification-ranking">{classificationRanking.slice(0, 4).map(item => <div key={item.name}><span>{item.name}</span><em style={{ width: `${labels.length ? Math.max(4, item.value / labels.length * 100) : 0}%`, background: item.color }}/><b>{item.value}</b></div>)}</div></div></div> : <EmptyChart/>}
        </ChartCard>
      </div>

      <ScreenPanel title="真实推理结果" icon={Activity} badge={!hydrated ? 'RESTORING' : report ? 'REAL RESULT' : 'WAITING'} className="validation-results-panel">
        <div className="validation-tabs"><button className={view === 'sanxia' ? 'active' : ''} title="按原始数据包逐包检测" onClick={() => setView('sanxia')}>SANXIA 正式结果</button><button className={view === 'standalone' ? 'active' : ''} title="按滑动窗口聚合后独立校验" onClick={() => setView('standalone')}>standalone 窗口结果</button><button className={view === 'live' ? 'active' : ''} title="WLAN 网卡或模拟 PCAP 的实时结果" onClick={() => setView('live')}>WLAN 实时结果{runtimeAlerts.length > 0 && <b>{runtimeAlerts.length}</b>}</button></div>
        <div className="validation-mode-note"><span>SANXIA 正式结果：按原始数据包逐包检测；standalone 窗口结果：按滑动窗口聚合后独立校验，两者统计粒度不同，不要求逐条相同。</span></div>
        {view === 'live' ? (
          <div className="validation-result-body live-result-body">
            <div className="validation-summary-grid"><span>已处理流量<strong>{livePipeline?.processedSamples ?? 0}</strong></span><span>攻击样本<strong className="danger">{livePipeline?.attackSamples ?? 0}</strong></span><span>实时告警<strong>{livePipeline?.runtimeAlerts ?? 0}</strong></span><span>{livePipeline?.shadowMode ? '持久化模式' : '新增归档'}<strong>{livePipeline?.shadowMode ? 'SHADOW' : livePipeline?.eventsCreated ?? 0}</strong></span></div>
            <div className="validation-summary-grid"><span>重复样本<strong>{livePipeline?.duplicateSamples ?? 0}</strong></span><span>去重告警<strong>{livePipeline?.duplicateAlerts ?? 0}</strong></span><span>连接状态<strong>{liveConnected ? 'SSE' : user?.demo ? 'DEMO' : '--'}</strong></span><span>运行状态<strong>{monitorStatus}</strong></span></div>
            {runtimeAlerts.length ? <div className="screen-table-scroll"><table><thead><tr><th>告警类型</th><th>级别</th><th>来源</th><th>目标</th><th>发生时间</th><th>样本</th><th>状态</th></tr></thead><tbody>{runtimeAlerts.map((alert, index) => <tr key={(alert.alertId || 'runtime') + index}><td><b>{alert.eventType || alert.attackLabel || '未命名告警'}</b></td><td><span className={`inference-severity ${Number(alert.eventSeverity) <= 0 ? 'critical' : Number(alert.eventSeverity) === 1 ? 'high' : 'medium'}`}>{['严重', '高危', '中危', '低危'][Math.min(3, Math.max(0, Number(alert.eventSeverity)))]}</span></td><td>{alert.source || '未知源'}</td><td>{alert.target || '多节点'}</td><td>{alert.startAt || alert.emittedAt || '--'}</td><td>{alert.sampleCount || 0} 包</td><td>{alert.archiveStatus === 'shadow' ? '仅实时展示' : alert.archiveStatus === 'archived' ? '已生成事件' : alert.archiveStatus === 'deduplicated' ? '重复告警' : '待归档'}</td></tr>)}</tbody></table></div> : <div className="validation-note"><Activity size={18}/><span>{user?.demo ? '演示模式不连接实时网卡，切换到文件检测执行演示推理。' : dataMode === 'replay' ? '等待模拟 PCAP 回放产生实时告警。' : '等待 WLAN 网卡产生实时告警。'}</span></div>}
          </div>
        ) : view === 'diff' ? (
          <div className="validation-diff-wrap">
            <div className="validation-summary-grid">
              <span>SANXIA 包数<strong>{report?.summary?.sanxiaCount ?? '--'}</strong></span>
              <span>standalone 窗数<strong>{report?.summary?.standaloneCount ?? '--'}</strong></span>
              <span>对齐模式<strong>{independent ? '独立' : '样本'}</strong></span>
              <span>可比差异<strong>{independent ? '--' : report?.summary?.differentCount ?? '--'}</strong></span>
            </div>
            <div className="validation-note"><AlertTriangle size={18}/><span>{independent ? 'standalone 按滑动窗口输出，SANXIA 按数据包输出，两者粒度不同，因此只比较总体分布和运行状态，不生成误导性的逐下标差异。' : '两个系统已按稳定样本 ID 对齐，可查看逐项差异。'}</span></div>
            {!independent && <div className="screen-table-scroll"><table><thead><tr><th>索引</th><th>SANXIA</th><th>standalone</th><th>已知置信度</th><th>未知分数</th></tr></thead><tbody>{differences.map(row => <tr key={row.index} onClick={() => setSelected({ kind: 'difference', data: row })}><td>#{row.index}</td><td>{displayLabel(attackTypes, row.sanxia)}</td><td>{displayLabel(attackTypes, row.standalone)}</td><td>{formatPercent(row.sanxiaConfidence)}</td><td>{row.unknownScore == null ? '--' : Number(row.unknownScore).toFixed(3)}</td></tr>)}</tbody></table></div>}
          </div>
        ) : view === 'standalone' ? (
          <div className="validation-result-body standalone-result-body">
            <div className="validation-summary-grid">
              <span>检测窗口<strong>{standaloneWindows.length || '--'}</strong></span>
              <span>正常<strong>{normal}</strong></span>
              <span>攻击<strong className="danger">{attacks}</strong></span>
              <span>独立标签<strong>{Object.keys(counts).length}</strong></span>
            </div>
            <div className="standalone-granularity"><ShieldCheck size={16}/><span>standalone 为滑动窗口推理；详情展示显式模型说明与规则证据。</span></div>
            {standaloneWindows.length ? (
              <div className="screen-table-scroll standalone-window-table">
                <div className="prediction-filter" role="group" aria-label="预测结果筛选">
                  {[['all', '全部', standaloneWindows.length], ['abnormal', '异常', abnormalWindows.length], ['normal', '正常', normalWindows.length]].map(([value, label, count]) => <button key={value} type="button" className={resultFilter === value ? 'active' : ''} onClick={() => setResultFilter(value)}>{label}<b>{count}</b></button>)}
                </div>
                {visibleStandaloneWindows.length ? (
                <table>
                  <thead><tr><th>窗口</th><th>包范围</th><th>预测标签</th><th>置信度</th><th>检测层级</th><th>耗时</th><th>通信端点</th></tr></thead>
                  <tbody>{visibleStandaloneWindows.map((row, index) => <tr key={row.sampleId || `${row.index}-${index}`} onClick={() => selectStandalone(row)}><td>#{row.index ?? index}</td><td>{windowRange(row)}</td><td><b className={`window-label ${isNormalPrediction(row.predictedLabel) ? 'normal' : 'abnormal'}`}>{row.predictedLabel ?? '--'}</b></td><td>{formatPercent(row.confidence)}</td><td>{row.detectionTier ?? '--'}</td><td>{row.inferenceMs == null ? '--' : `${row.inferenceMs} ms`}</td><td>{row.sourceIp || row.destinationIp ? `${row.sourceIp ?? '?'} → ${row.destinationIp ?? '?'}` : '--'}</td></tr>)}</tbody>
                </table>
                ) : <div className="prediction-empty">{resultFilter === 'abnormal' ? '暂无异常预测结果' : '暂无正常预测结果'}</div>}
              </div>
            ) : <div className="validation-note"><AlertTriangle size={18}/><span>{standalone?.error || (report ? 'standalone 未返回窗口级结果' : '请先选择文件并执行并行检测')}</span></div>}
          </div>
        ) : (
          <div className="validation-result-body">
            <div className="validation-summary-grid"><span>有效包<strong>{labels.length || '--'}</strong></span><span>正常<strong>{normal}</strong></span><span>攻击<strong className="danger">{attacks}</strong></span><span>未知攻击<strong>{unknown}</strong></span></div>
            <div className="validation-summary-grid"><span>跳过包<strong>{sanxiaData.skipped_packets ?? '--'}</strong></span><span>未知评分包<strong>{unknownValues.length}</strong></span><span>未知阈值<strong>{sanxiaData.unknown_threshold ?? '--'}</strong></span></div>
            <div className="validation-bars">{Object.entries(counts).slice(0, 10).map(([name, value]) => <div key={name}><span>{name}</span><i><em style={{ width: `${labels.length ? Math.max(3, value / labels.length * 100) : 0}%` }}/></i><b>{value}</b></div>)}</div>
            {report && !labels.length && <div className="validation-note"><AlertTriangle size={18}/><span>{sanxia?.error || 'SANXIA 未返回逐包结果'}</span></div>}
          </div>
        )}
      </ScreenPanel>
      {selected && <><button type="button" className="inference-drawer-backdrop" aria-label="关闭详情" onClick={() => setSelected(null)}/><aside className="inference-drawer validation-drawer" onClick={event => event.stopPropagation()}>
        <button className="drawer-close" aria-label="关闭详情" onClick={() => setSelected(null)}>×</button>
        {selected.kind === 'standalone' ? <>
          <h3>standalone 窗口 #{selected.data.index ?? '--'}</h3>
          <p>{selected.data.sampleId || '独立滑动窗口推理'}</p>
          <div className="drawer-section">
            <b>窗口判定</b>
            <span>预测标签：{selected.data.predictedLabel ?? '--'}</span>
            <span>置信度：{formatPercent(selected.data.confidence)}</span>
            <span>检测层级：{selected.data.detectionTier ?? '--'}</span>
            <span>推理耗时：{selected.data.inferenceMs == null ? '--' : `${selected.data.inferenceMs} ms`}</span>
            <span>包范围：{windowRange(selected.data)}</span>
            <span>通信端点：{selected.data.sourceIp || selected.data.destinationIp ? `${selected.data.sourceIp ?? '?'} → ${selected.data.destinationIp ?? '?'}` : '--'}</span>
            <span>时间：{selected.data.timestamp ?? '--'}</span>
          </div>
          <div className="drawer-section evidence-answer"><b>研判摘要</b><em>{selectedAssociation?.cause || selected.data.evidence || '点击“加载研判”获取攻击原因、影响后果和处置建议。'}</em></div>
          <button className="association-load-button" disabled={associationBusy || user?.demo} onClick={() => loadAssociation(selected.data, Boolean(selectedAssociation))}>{associationBusy ? '正在生成研判…' : selectedAssociation ? '重新生成研判' : '生成研判'}<ShieldCheck size={14}/></button>
          {associationError && <p className="association-error"><AlertTriangle size={14}/>{associationError}</p>}
          {selectedAssociation && <>
            <div className="drawer-section association-summary"><b>攻击关联</b><span>类型：{selectedAssociation.attackInfo?.name || selectedAssociation.label || '--'}</span><span>研判记录：{selectedAssociation.cached ? '数据库复用' : '本次生成'} · v{selectedAssociation.version ?? 1} · {selectedAssociation.engine || 'standalone'}</span><span>严重度：{selectedAssociation.attackInfo?.severity || '--'}</span><span>影响子系统：{selectedAssociation.affectedSubsystem || '--'}</span><small>{selectedAssociation.attackInfo?.description || selectedAssociation.cause || '--'}</small></div>
            <div className="drawer-section association-summary"><b>物理后果</b><em>{selectedAssociation.physicalConsequence || '--'}</em></div>
            <div className="drawer-section association-history"><b>历史故障关联</b>{selectedAssociation.historicalMatch?.matched ? <><span>匹配 {selectedAssociation.historicalMatch.totalMatchingRecords ?? 0} 条记录，{selectedAssociation.historicalMatch.uniqueFaultModes ?? 0} 种故障模式</span>{(selectedAssociation.historicalMatch.topFaults || []).slice(0, 3).map((fault, index) => <small key={`${fault.fault_mode}-${index}`}>{fault.fault_mode} · {fault.typical_response || '暂无典型处置措施'}</small>)}</> : <small>{selectedAssociation.historicalMatch?.reason || '未匹配到历史故障记录'}</small>}</div>
            <div className="drawer-section association-recommendations"><b>预防与处置建议</b>{(selectedAssociation.recommendations || []).slice(0, 5).map((item, index) => <span key={`${item.action}-${index}`}><i>{item.priority || '建议'}</i>{item.action}</span>)}</div>
          </>}
          <div className="drawer-section"><b>特征证据</b>{featureEntries(selected.data.features).length ? <div className="drawer-feature-grid">{featureEntries(selected.data.features).map(([key, value], index) => <div key={`${key}-${index}`}><span>{key}</span><b title={value}>{value}</b></div>)}</div> : <em>当前模型未返回特征证据</em>}</div>
        </> : <>
          <h3>差异 #{selected.data.index}</h3>
          <div className="drawer-section"><b>双系统结果</b><span>SANXIA：{displayLabel(attackTypes, selected.data.sanxia)}</span><span>standalone：{displayLabel(attackTypes, selected.data.standalone)}</span><span>未知分数：{selected.data.unknownScore ?? '--'} / 阈值 {sanxiaData.unknown_threshold ?? '--'}</span></div>
        </>}
      </aside></>}
    </div>
  </BigScreenShell>
}
