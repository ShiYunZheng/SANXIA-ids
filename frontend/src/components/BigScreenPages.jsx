import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, BarChart3, Bell, CheckCircle2, CircleUserRound, Database, FileSearch, Gauge, LockKeyhole, Network, Radio, ShieldCheck, UploadCloud, UserCheck, Wifi, Zap } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ComposedChart, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/services'
import { stream } from '../api/client'
import { attackTypes, demoEvents, demoMetrics, demoRecords } from '../data/demoData'
import BigScreenShell, { CHART_TOOLTIP, SCREEN_COLORS, ScreenKpi, ScreenPanel } from './BigScreenShell'
import './BigScreenPages.css'

const severityLabels = ['严重', '高危', '中危', '低危']
const severityColors = [SCREEN_COLORS[2], SCREEN_COLORS[3], SCREEN_COLORS[1], SCREEN_COLORS[0]]
const hasData = value => Array.isArray(value) ? value.length > 0 : value && typeof value === 'object' ? Object.values(value).some(hasData) : value !== null && value !== undefined && value !== ''
const eventSourceLabel = (event, fallback) => event.dataSource || event.data_source || event.sourceType || fallback || '未知来源'
const isSanxiaEvent = event => event?.engine !== 'standalone'
const mergeRuntimeAlerts = (current, incoming) => {
  const merged = new Map()
  ;[...(incoming || []), ...current].forEach((alert, index) => {
    const key = String(alert?.alertId || `${alert?.runId || 'run'}:${alert?.attackLabel || index}:${alert?.source || ''}:${alert?.target || ''}:${alert?.emittedAt || index}`)
    if (!merged.has(key)) merged.set(key, alert)
  })
  return [...merged.values()].slice(0, 100)
}
const runtimeAlertEvent = alert => ({
  _id: `runtime:${alert.alertId}`,
  formalEventId: alert.eventId || null,
  eventType: alert.eventType || alert.attackLabel,
  eventSeverity: alert.eventSeverity,
  start_timestamp: alert.startAt || alert.emittedAt,
  dataSource: alert.dataSource,
  archiveStatus: alert.archiveStatus,
  engine: 'sanxia-runtime',
  detail: [{ source: alert.source, target: alert.target }],
})

function useScreenData(loader, fallback) {
  const demo = localStorage.getItem('sg_demo') === '1'
  const [data, setData] = useState(fallback)
  const [live, setLive] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    if (demo) return () => { active = false }
    loader().then(value => { if (active && hasData(value)) { setData(value); setLive(true); setError('') } }).catch(reason => { if (active) setError(reason?.message || '数据服务不可用') })
    return () => { active = false }
  }, [demo])
  return [data, live && !demo, error, setData]
}

function ScreenPage({ id, title, subtitle, live, shell, children }) {
  return <BigScreenShell page={id} pageTitle={title} subtitle={subtitle} live={live} {...shell}><div className={`screen-page screen-page-${id}`}>{children}</div></BigScreenShell>
}

function SeverityDonut({ events, summary }) {
  const counts = summary?.bySeverity || {}
  const data = severityLabels.map((name, severity) => ({ name, value: Number(counts[severity] ?? events.filter(item => item.eventSeverity === severity).length), color: severityColors[severity] })).filter(item => item.value)
  const total = Number(summary?.total ?? data.reduce((sum, item) => sum + item.value, 0))
  return <div className="screen-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" innerRadius="57%" outerRadius="82%" paddingAngle={3} stroke="none">{data.map((item, index) => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={CHART_TOOLTIP}/></PieChart></ResponsiveContainer><div><strong>{total}</strong><span>事件总量</span></div></div>
}

function CompactEventList({ events, defaultSource }) {
  return <div className="screen-event-list" aria-label="实时事件队列">{events.map((event, index) => {
    const severity = Number(event.eventSeverity)
    const level = 4 - Math.min(3, Math.max(0, Number.isFinite(severity) ? severity : 0))
    const source = event.detail?.[0]?.source || '未知源'
    const target = event.detail?.[0]?.target || '多节点'
    const time = String(event.start_timestamp || '').split(' ').pop() || '刚刚'
    const label = severityLabels[event.eventSeverity] || '告警'
    return <article className={`event-alert-card level-${level}`} key={(event._id || 'event') + index}>
      <div className="event-alert-rail"><span className="event-beacon">{level}</span></div>
      <div className="event-alert-main"><b>{event.eventType || '未命名事件'}</b><div className="event-alert-meta"><span className="event-route"><i>{source}</i><em>→</em><i>{target}</i></span><span className="event-source-tag">{event.archiveStatus === 'deduplicated' ? '已去重' : event.archiveStatus === 'archived' ? '已归档' : eventSourceLabel(event, defaultSource)}</span></div></div>
      <time className="event-alert-time">{time}</time>
      <span className={`severity-text s${event.eventSeverity}`}>{label}</span>
    </article>
  })}</div>
}

export function RealtimeScreen({ user, onNavigate, onLogout }) {
  const [data, live, error, setData] = useScreenData(() => api.events(1, 20), { events: demoEvents, total: demoEvents.length, summary: { total: demoEvents.length, bySeverity: {} } })
  const [streamEvents, setStreamEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const [filter, setFilter] = useState('全部')
  const [runtimeAlerts, setRuntimeAlerts] = useState([])
  const runtimeRunRef = useRef(null)
  useEffect(() => {
    if (user.demo) return undefined
    const close = stream('/api/v1/events/stream', event => { if (event && isSanxiaEvent(event)) { setConnected(true); setStreamEvents(current => [event, ...current].slice(0, 20)); setData(current => { const severity = String(event.eventSeverity); const bySeverity = { ...(current.summary?.bySeverity || {}) }; bySeverity[severity] = Number(bySeverity[severity] || 0) + 1; const total = Number(current.total || 0) + 1; return { ...current, total, summary: { total, bySeverity } } }) } }, () => setConnected(false))
    return close
  }, [user.demo])
  useEffect(() => {
    if (user.demo) return undefined
    let active = true
    const refresh = async () => {
      try {
        const pipeline = await api.pipelineStatus()
        const runId = pipeline?.runId || null
        if (runtimeRunRef.current !== runId) { runtimeRunRef.current = runId; setRuntimeAlerts([]) }
        if (runId) {
          const alerts = await api.pipelineAlerts(runId, 100)
          if (active && runtimeRunRef.current === runId) setRuntimeAlerts(current => mergeRuntimeAlerts(current, alerts))
        }
      } catch { /* event archive remains available when pipeline status is offline */ }
    }
    refresh()
    const timer = window.setInterval(refresh, 3000)
    const close = stream('/api/v1/pipeline/alerts/stream', alert => {
      if (active && alert && (!runtimeRunRef.current || alert.runId === runtimeRunRef.current)) setRuntimeAlerts(current => mergeRuntimeAlerts(current, [alert]))
    })
    return () => { active = false; window.clearInterval(timer); close?.() }
  }, [user.demo])
  const all = useMemo(() => {
    const merged = new Map()
    ;[...runtimeAlerts.map(runtimeAlertEvent), ...streamEvents, ...(data.events || [])].filter(isSanxiaEvent).forEach((event, index) => {
      const key = String(event._id || index)
      if (!merged.has(key)) merged.set(key, event)
    })
    return [...merged.values()]
  }, [streamEvents, data.events, runtimeAlerts])
  const events = all.filter(event => filter === '全部' || severityLabels[event.eventSeverity] === filter)
  const high = all.filter(event => event.eventSeverity <= 1).length
  const sources = new Set(all.map(event => event.detail?.[0]?.source).filter(Boolean)).size
  const highRate = all.length ? Math.round(high / all.length * 100) : 0
  const latestTime = String(all[0]?.start_timestamp || '').split(' ').pop() || '--'
  const trend = [...all].reverse().slice(-10).map((event, index) => ({ time: String(event.start_timestamp || index).split(' ').pop()?.slice(0, 5), 风险级别: 4 - Math.min(3, Math.max(0, Number(event.eventSeverity))), 告警: 1 }))
  const shell = { user, onNavigate, onLogout }
  return <ScreenPage id="realtime" title="实时事件" subtitle="安全事件流与威胁告警监控" live={live || connected} shell={shell}>
    <div className="screen-kpi-row"><ScreenKpi label="告警总量" value={data.total ?? all.length} unit="起" icon={Bell} note="当前事件队列"/><ScreenKpi label="高危事件" value={high} unit="起" icon={AlertTriangle} tone="red" note="需优先关注"/><ScreenKpi label="攻击来源" value={sources} unit="个" icon={Network} tone="orange" note="去重来源地址"/><ScreenKpi label="事件通道" value={connected ? 'SSE' : live ? 'API' : 'DEMO'} icon={Radio} tone={connected || live ? 'green' : 'orange'} note={connected ? '实时连接正常' : error || '使用当前数据源'}/></div>
    <div className="realtime-grid"><ScreenPanel title="告警级别分布" icon={Gauge} badge="SANXIA EVENT"><div className="donut-with-legend"><SeverityDonut events={all} summary={data.summary}/><div className="screen-legend">{severityLabels.map((label, index) => <div key={label}><i style={{ background: severityColors[index] }}/><span>{label}</span><b>{Number(data.summary?.bySeverity?.[index] ?? all.filter(item => item.eventSeverity === index).length)}</b></div>)}</div></div></ScreenPanel>
      <ScreenPanel title="事件风险走势" icon={Activity} badge="LATEST"><ResponsiveContainer width="100%" height="100%"><LineChart data={trend} margin={{ top: 14, right: 14, left: -18, bottom: 0 }}><CartesianGrid stroke="#164b7c" strokeDasharray="2 3" vertical={false}/><XAxis dataKey="time" tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis domain={[0, 4]} tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={CHART_TOOLTIP}/><Line type="monotone" dataKey="风险级别" stroke="#ff565f" strokeWidth={2.6} dot={{ r: 3, fill: '#ff565f', stroke: '#ffd0d4' }} activeDot={{ r: 5 }}/></LineChart></ResponsiveContainer></ScreenPanel>
      <ScreenPanel title="实时事件队列" icon={Bell} badge={`${events.length} 条`} className="event-queue" action={<div className="screen-segmented">{['全部', '严重', '高危', '中危'].map(item => <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)}>{item}</button>)}</div>}><div className="screen-event-queue-layout"><div className="screen-event-summary"><div><span>高危占比</span><b>{highRate}%</b></div><div><span>攻击来源</span><b>{sources}</b></div><div><span>最近告警</span><b>{latestTime}</b></div></div><CompactEventList events={events} defaultSource={user.demo ? 'DEMO' : connected ? 'WLAN实时' : '未知来源'}/></div></ScreenPanel></div>
  </ScreenPage>
}

function MetricRings({ metrics }) {
  const labels = ['准确率', '精确率', '召回率', 'F1 值']
  return <div className="metric-rings">{(metrics || demoMetrics).slice(0, 4).map((item, index) => { const value = Math.round((item.value || 0) * 100); return <div key={item.name} style={{ '--value': `${value * 3.6}deg` }}><div><strong>{value}<small>%</small></strong><span>{labels[index]}</span></div></div> })}</div>
}

function AttackBars({ counts, total }) {
  const data = Object.entries(counts).filter(([name]) => name !== 'Normal').map(([name, value]) => ({ name, value }))
  return <div className="attack-bars"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} layout="vertical" margin={{ top: 8, right: 24, left: 14, bottom: 4 }}><CartesianGrid stroke="#164b7c" strokeDasharray="2 3" horizontal={false}/><XAxis type="number" tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis type="category" dataKey="name" width={88} tick={{ fill: '#b4d5e7', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={CHART_TOOLTIP}/><Bar dataKey="value" fill="#19d3ff" radius={[0, 5, 5, 0]}/></BarChart></ResponsiveContainer></div>
}

export function DetectScreen({ user, onNavigate, onLogout }) {
  const [metrics, metricsLive] = useScreenData(api.metrics, demoMetrics)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const pick = event => { const selected = event.target.files[0]; if (selected && ['.csv', '.pcap', '.pcapng'].some(extension => selected.name.toLowerCase().endsWith(extension))) setFile(selected) }
  const run = async () => { if (!file) return; setBusy(true); try { setResult(await api.detect(file)) } catch { setResult({ demo: true, labels: Array.from({ length: 240 }, (_, index) => index % 7), message: '演示检测完成' }) } finally { setBusy(false) } }
  const resultAttackTypes = result?.attack_types || attackTypes
  const counts = (result?.labels || []).reduce((current, value) => { const name = resultAttackTypes[value] || `Class ${value}`; return { ...current, [name]: (current[name] || 0) + 1 } }, {})
  const total = result?.labels?.length || 0
  const attacks = total - (counts.Normal || 0)
  const unknownAttacks = counts['未知攻击'] || 0
  const knownAttacks = Math.max(0, attacks - unknownAttacks)
  const knownRate = attacks ? Math.round(knownAttacks / attacks * 100) : 0
  const unknownRate = attacks ? Math.round(unknownAttacks / attacks * 100) : 0
  const hasUnknownThreshold = result?.unknown_threshold !== null && result?.unknown_threshold !== undefined && Number.isFinite(Number(result.unknown_threshold))
  const unknownNote = hasUnknownThreshold ? `判定阈值 ${(Number(result.unknown_threshold) * 100).toFixed(1)}%` : `${String(result?.engine || (result?.demo ? 'demo' : 'unknown')).toUpperCase()} 引擎`
  const pie = [{ name: '正常流量', value: counts.Normal || 0 }, { name: '攻击流量', value: attacks }]
  const shell = { user, onNavigate, onLogout }
  return <ScreenPage id="detect" title="检测中心" subtitle="工业流量文件智能检测" live={metricsLive} shell={shell}>
    <div className="screen-kpi-row"><ScreenKpi label="模型状态" value="READY" icon={ShieldCheck} tone="green" note="已知 + 未知级联"/><ScreenKpi label="检测准确率" value={`${Math.round((metrics[0]?.value || 0) * 100)}%`} icon={Gauge} note="当前模型指标"/><ScreenKpi label="本次流量" value={total || '--'} unit={total ? '条' : ''} icon={Database} note={result ? `${result.engine || 'demo'} 引擎` : '等待文件输入'}/><ScreenKpi label="攻击流量" value={result ? attacks : '--'} unit={result ? '条' : ''} icon={AlertTriangle} tone="red" note={result?.demo ? 'DEMO 检测结果' : '本次识别结果'}/></div>
    <div className="detect-screen-grid"><ScreenPanel title="上传检测文件" icon={UploadCloud} badge="CSV / PCAP · MAX 50MB" className="upload-panel"><label className="screen-dropzone"><span><UploadCloud size={38}/></span><b>{file ? file.name : '点击选择流量 CSV 或抓包文件'}</b><small>{file ? `${(file.size / 1024).toFixed(1)} KB · 文件已就绪` : '支持 CSV、PCAP、PCAPNG'}</small><input type="file" accept=".csv,.pcap,.pcapng" onChange={pick}/></label><button className="screen-primary" disabled={!file || busy} onClick={run}>{busy ? '模型分析中…' : '开始检测'}<FileSearch size={17}/></button></ScreenPanel>
      <ScreenPanel title="模型性能状态" icon={Gauge} badge="MODEL METRICS"><MetricRings metrics={metrics}/><div className="model-foot"><span><i className="live"/>模型服务已加载</span><span>输入维度 · 自动适配</span><span>输出类别 · {attackTypes.length}</span></div></ScreenPanel>
      <ScreenPanel title={result ? '检测结果分析' : '检测任务说明'} icon={BarChart3} badge={result ? (result.demo ? 'DEMO RESULT' : 'RESULT') : 'WAITING'} className="detect-result">{result ? <div className="detection-result-layout"><div className="attack-origin-summary"><div className="attack-origin-card known"><div><span className="attack-origin-icon"><ShieldCheck size={25}/></span><span><small>已知攻击</small><strong>{knownAttacks}<em>条</em></strong></span></div><div className="attack-origin-rate"><b>{knownRate}%</b><span>攻击占比</span></div><i>已知模型识别</i></div><div className="attack-origin-card unknown"><div><span className="attack-origin-icon"><AlertTriangle size={25}/></span><span><small>未知攻击</small><strong>{unknownAttacks}<em>条</em></strong></span></div><div className="attack-origin-rate"><b>{unknownRate}%</b><span>攻击占比</span></div><i>{unknownNote}</i></div></div><div className="result-visual"><div className="result-pie"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={pie} dataKey="value" innerRadius="58%" outerRadius="83%" stroke="none"><Cell fill="#27d6a2"/><Cell fill="#ff565f"/></Pie><Tooltip contentStyle={CHART_TOOLTIP}/></PieChart></ResponsiveContainer><div><strong>{total}</strong><span>总流量</span></div></div><AttackBars counts={counts} total={total}/></div></div> : <div className="empty-detection"><ShieldCheck size={52}/><h3>模型检测通道已就绪</h3><p>选择 CSV 文件后，系统将展示攻击占比、分类数量和模型分析结果。</p><div className="detection-process"><span>格式校验</span><i/><span>特征提取</span><i/><span>模型推理</span><i/><span>结果归档</span></div><div className="detection-summary-grid"><div><span>模型状态</span><b>READY</b></div><div><span>输入格式</span><b>CSV</b></div><div><span>分类数量</span><b>{attackTypes.length}</b></div><div><span>当前数据源</span><b>{user.demo ? 'DEMO' : 'API'}</b></div></div></div>}</ScreenPanel></div>
  </ScreenPage>
}

const RECORD_SERIES = {
  正常: { color: '#25d7ff', unit: '条' },
  攻击: { color: '#ff6470', unit: '条' },
  正常率: { color: '#42e0ae', unit: '%' },
}

function RecordsTrendTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return <div className="records-trend-tooltip"><div className="records-trend-tooltip-time"><span>检测时间</span><strong>{label}</strong></div>{payload.map(item => {
    const series = RECORD_SERIES[item.dataKey] || { color: item.color, unit: '' }
    return <div className="records-trend-tooltip-row" key={item.dataKey}><i style={{ '--series-color': series.color }}/><span>{item.name}</span><b>{Number(item.value || 0).toLocaleString()}</b><em>{series.unit}</em></div>
  })}</div>
}

function RecordsTrendCursor({ x, y, width, height }) {
  const center = x + width / 2
  return <g className="records-trend-cursor"><rect x={center - 18} y={y} width={36} height={height} rx={14}/><line x1={center} x2={center} y1={y + 5} y2={y + height}/></g>
}

function RecordsTrendChart({ data }) {
  const latest = data.at(-1) || {}
  return <div className="records-trend-layout">
    <div className="records-trend-meta"><div className="records-trend-legend"><span><i className="normal"/>正常流量</span><span><i className="attack"/>攻击流量</span><span><i className="rate"/>正常率</span></div><div className="records-latest-summary"><span>最近批次</span><b>{Number(latest.total || 0).toLocaleString()} 条</b><b className="danger">{Number(latest.攻击 || 0).toLocaleString()} 攻击</b><b className="good">{latest.正常率 || 0}% 正常</b></div></div>
    <div className="records-trend-chart"><ResponsiveContainer width="100%" height="100%"><ComposedChart data={data} margin={{ top: 10, right: 16, left: -4, bottom: 2 }} barCategoryGap="54%">
      <defs>
        <linearGradient id="recordsNormalBar" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#72ecff"/><stop offset=".2" stopColor="#25d7ff"/><stop offset="1" stopColor="#087fab"/></linearGradient>
        <linearGradient id="recordsAttackBar" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ff929a"/><stop offset=".2" stopColor="#ff6470"/><stop offset="1" stopColor="#d83249"/></linearGradient>
        <filter id="recordsNormalGlow" x="-80%" y="-25%" width="260%" height="170%"><feDropShadow dx="0" dy="0" stdDeviation="2.4" floodColor="#19d3ff" floodOpacity=".38"/></filter>
        <filter id="recordsAttackGlow" x="-80%" y="-25%" width="260%" height="170%"><feDropShadow dx="0" dy="0" stdDeviation="2.4" floodColor="#ff5364" floodOpacity=".34"/></filter>
      </defs>
      <CartesianGrid stroke="rgba(38, 124, 183, .32)" strokeDasharray="3 7" vertical={false}/>
      <XAxis dataKey="time" tick={{ fill: '#88b1ce', fontSize: 12 }} tickMargin={9} axisLine={false} tickLine={false}/>
      <YAxis yAxisId="count" tick={{ fill: '#759ab8', fontSize: 12 }} width={48} axisLine={false} tickLine={false}/>
      <YAxis yAxisId="rate" orientation="right" domain={[0, 100]} tick={{ fill: '#71ddb8', fontSize: 12 }} width={42} axisLine={false} tickLine={false}/>
      <Tooltip content={<RecordsTrendTooltip/>} cursor={<RecordsTrendCursor/>} allowEscapeViewBox={{ x: true, y: true }} wrapperStyle={{ outline: 'none' }}/>
      <Bar yAxisId="count" dataKey="正常" stackId="flow" fill="url(#recordsNormalBar)" barSize={28} filter="url(#recordsNormalGlow)" fillOpacity={.86} activeBar={{ stroke: '#d8faff', strokeWidth: 1.2, fillOpacity: 1 }}/>
      <Bar yAxisId="count" dataKey="攻击" stackId="flow" fill="url(#recordsAttackBar)" barSize={28} radius={[7, 7, 2, 2]} filter="url(#recordsAttackGlow)" fillOpacity={.9} activeBar={{ stroke: '#ffe1e4', strokeWidth: 1.2, fillOpacity: 1 }}/>
      <Line yAxisId="rate" type="monotone" dataKey="正常率" stroke="#42e0ae" strokeWidth={2.7} dot={{ r: 3, fill: '#071b36', stroke: '#67efc1', strokeWidth: 1.5 }} activeDot={{ r: 5.5, fill: '#42e0ae', stroke: '#d7fff2', strokeWidth: 2 }}/>
    </ComposedChart></ResponsiveContainer></div>
  </div>
}

export function RecordsScreen({ user, onNavigate, onLogout }) {
  const [data, live] = useScreenData(() => api.records(), { attack_types: attackTypes, records: demoRecords, total: demoRecords.length })
  const [page, setPage] = useState(1)
  const records = data.records || demoRecords
  const recordAttackTypes = data.attack_types || attackTypes
  const pageSize = 6
  const pageCount = Math.max(1, Math.ceil(records.length / pageSize))
  const safePage = Math.min(page, pageCount)
  const pageRecords = records.slice((safePage - 1) * pageSize, safePage * pageSize)
  const pageStart = Math.min(Math.max(safePage - 2, 1), Math.max(pageCount - 4, 1))
  const pageNumbers = Array.from({ length: Math.min(pageCount, 5) }, (_, index) => pageStart + index)
  const totals = records.reduce((sum, item) => ({ total: sum.total + (item.total || 0), benign: sum.benign + (item.benign || 0), attacks: sum.attacks + (item.attack_total ?? (item.total || 0) - (item.benign || 0)) }), { total: 0, benign: 0, attacks: 0 })
  const normalRate = totals.total ? Math.round(totals.benign / totals.total * 100) : 0
  const chart = [...records].reverse().map(item => ({ ...item, time: String(item.timestamp || '').split(' ').pop()?.slice(0, 5), 攻击: item.attack_total ?? (item.total || 0) - (item.benign || 0), 正常: item.benign || 0, 正常率: item.total ? Math.round((item.benign || 0) / item.total * 100) : 0 }))
  const shell = { user, onNavigate, onLogout }
  return <ScreenPage id="records" title="检测归档" subtitle="历史流量检测统计与趋势回溯" live={live} shell={shell}>
    <div className="screen-kpi-row"><ScreenKpi label="记录批次" value={data.total || records.length} unit="批" icon={Database} note="历史检测任务"/><ScreenKpi label="累计流量" value={totals.total.toLocaleString()} unit="条" icon={BarChart3} note="当前记录汇总"/><ScreenKpi label="攻击流量" value={totals.attacks.toLocaleString()} unit="条" icon={AlertTriangle} tone="red" note="识别攻击样本"/><ScreenKpi label="正常流量占比" value={`${normalRate}%`} icon={ShieldCheck} tone="green" note="历史平均水平"/></div>
    <div className="records-grid"><ScreenPanel title="历史检测趋势" icon={Activity} badge="BAR / LINE"><RecordsTrendChart data={chart}/></ScreenPanel>
      <ScreenPanel title="历史检测归档" icon={Database} badge={`${records.length} 条`} className="screen-table-panel" action={<div className="screen-segmented"><button className="selected">全部归档</button><button>日期范围</button></div>}><div className="screen-table-scroll"><table><thead><tr><th>检测时间</th><th>总流量</th><th>正常</th>{recordAttackTypes.slice(1).map(name => <th key={name}>{name}</th>)}</tr></thead><tbody>{pageRecords.map((record, index) => <tr key={`${safePage}-${index}`}><td>{record.timestamp}</td><td><b>{record.total}</b></td><td className="cell-good">{record.benign}</td>{recordAttackTypes.slice(1).map(name => <td key={name}>{record[name] || 0}</td>)}</tr>)}</tbody></table></div><div className="screen-pagination"><span>共 {data.total || records.length} 条归档 · 第 {safePage}/{pageCount} 页</span><button disabled={safePage === 1} onClick={() => setPage(current => Math.max(1, current - 1))}>‹</button>{pageNumbers.map(number => <button key={number} className={number === safePage ? 'active' : ''} onClick={() => setPage(number)}>{number}</button>)}<button disabled={safePage === pageCount} onClick={() => setPage(current => Math.min(pageCount, current + 1))}>›</button></div></ScreenPanel></div>
  </ScreenPage>
}

function TargetRankingTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return <div className="target-ranking-tooltip"><span>受影响目标</span><strong>{label}</strong><div><i/><b>{Number(payload[0].value || 0).toLocaleString()}</b><em>起关联事件</em></div></div>
}

function TargetRankingCursor({ x, y, width, height }) {
  return <rect className="target-ranking-cursor" x={x} y={y + height * .14} width={width} height={height * .72} rx={10}/>
}

function TargetRankingChart({ data }) {
  const items = data.slice(0, 6)
  if (!items.length) return <div className="target-ranking-empty"><Network size={42}/><span>暂无受影响目标数据</span></div>
  return <div className="target-ranking-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={items} layout="vertical" margin={{ top: 12, right: 46, left: 20, bottom: 8 }} barCategoryGap="34%">
    <defs><linearGradient id="targetRankBar" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="#1266ff"/><stop offset=".48" stopColor="#18b8ee"/><stop offset="1" stopColor="#6eeeff"/></linearGradient><filter id="targetRankGlow" x="-20%" y="-80%" width="150%" height="260%"><feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#19d3ff" floodOpacity=".42"/></filter></defs>
    <CartesianGrid stroke="rgba(38,124,183,.28)" strokeDasharray="3 8" horizontal={false}/>
    <XAxis type="number" allowDecimals={false} tick={{ fill: '#789fbd', fontSize: 12 }} tickMargin={8} axisLine={false} tickLine={false}/>
    <YAxis type="category" dataKey="name" width={118} tick={{ fill: '#c2e4f3', fontSize: 12, fontWeight: 600 }} tickFormatter={(value, index) => String(index + 1).padStart(2, '0') + '  ' + value} axisLine={false} tickLine={false}/>
    <Tooltip content={<TargetRankingTooltip/>} cursor={<TargetRankingCursor/>} allowEscapeViewBox={{ x: true, y: true }} wrapperStyle={{ outline: 'none' }}/>
    <Bar dataKey="value" fill="url(#targetRankBar)" barSize={24} radius={[0, 12, 12, 0]} background={{ fill: 'rgba(14,62,108,.36)', radius: 12 }} filter="url(#targetRankGlow)" label={{ position: 'right', fill: '#e8fbff', fontSize: 13, fontWeight: 700 }} activeBar={{ stroke: '#d9fbff', strokeWidth: 1.5, fillOpacity: 1 }}>{items.map((item, index) => <Cell key={item.name} fill="url(#targetRankBar)" fillOpacity={Math.max(.62, 1 - index * .08)}/>)}</Bar>
  </BarChart></ResponsiveContainer></div>
}

export function EventsScreen({ user, onNavigate, onLogout }) {
  const [data, live] = useScreenData(() => api.events(1, 20), { events: demoEvents, total: demoEvents.length, summary: { total: demoEvents.length, bySeverity: {} } })
  const [expanded, setExpanded] = useState(null)
  const events = (data.events || demoEvents).filter(isSanxiaEvent)
  const high = events.filter(item => item.eventSeverity <= 1).length
  const sourceCount = new Set(events.map(item => item.detail?.[0]?.source).filter(Boolean)).size
  const targetMap = useMemo(() => events.reduce((map, event) => { const target = event.detail?.[0]?.target || '未知目标'; map[target] = (map[target] || 0) + 1; return map }, {}), [events])
  const targets = Object.entries(targetMap).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  const typeCounts = events.reduce((map, event) => { const name = event.eventType || '未知事件'; map[name] = (map[name] || 0) + 1; return map }, {})
  const dominantType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || '--'
  const latestArchived = String(events[0]?.start_timestamp || '').split(' ').pop() || '--'
  const highRate = events.length ? Math.round(high / events.length * 100) : 0
  const shell = { user, onNavigate, onLogout }
  return <ScreenPage id="events" title="事件档案" subtitle="历史安全事件与攻击详情追溯" live={live} shell={shell}>
    <div className="screen-kpi-row"><ScreenKpi label="事件档案" value={data.total ?? events.length} unit="起" icon={Bell} note="累计归档数量"/><ScreenKpi label="高危及严重" value={high} unit="起" icon={AlertTriangle} tone="red" note="重点安全事件"/><ScreenKpi label="攻击来源" value={sourceCount} unit="个" icon={Network} tone="orange" note="来源地址去重"/><ScreenKpi label="受影响目标" value={targets.length} unit="个" icon={Zap} note="涉及工控节点"/></div>
    <div className="archive-grid"><ScreenPanel title="严重级别分布" icon={Gauge} badge="SANXIA ARCHIVE"><div className="donut-with-legend"><SeverityDonut events={events} summary={data.summary}/><div className="screen-legend">{severityLabels.map((label, index) => <div key={label}><i style={{ background: severityColors[index] }}/><span>{label}</span><b>{Number(data.summary?.bySeverity?.[index] ?? events.filter(item => item.eventSeverity === index).length)}</b></div>)}</div></div></ScreenPanel>
      <ScreenPanel title="受影响目标排行" icon={Network} badge="TOP TARGET"><TargetRankingChart data={targets}/></ScreenPanel>
      <ScreenPanel title="档案态势摘要" icon={ShieldCheck} badge="INSIGHT"><div className="archive-insight-grid"><div><span>高危占比</span><strong>{highRate}%</strong><small>高危及严重事件</small></div><div><span>主要事件类型</span><strong>{dominantType}</strong><small>当前出现频率最高</small></div><div><span>最近归档</span><strong>{latestArchived}</strong><small>最近事件时间</small></div><div><span>归档状态</span><strong className="good">完整</strong><small>{events.length} 起事件可追溯</small></div></div></ScreenPanel>
      <ScreenPanel title="安全事件列表" icon={Bell} badge={`${events.length} 条`} className="screen-table-panel archive-table"><div className="screen-table-scroll"><table><thead><tr><th>级别</th><th>事件类型</th><th>开始时间</th><th>结束时间</th><th>目标</th><th>操作</th></tr></thead><tbody>{events.map((event, index) => <Fragment key={(event._id || 'event') + index}><tr onClick={() => setExpanded(expanded === event._id ? null : event._id)}><td><span className={`screen-severity s${event.eventSeverity}`}>{severityLabels[event.eventSeverity]}</span></td><td><b>{event.eventType}</b></td><td>{event.start_timestamp}</td><td>{event.end_timestamp}</td><td>{event.detail?.[0]?.target}</td><td><button className="table-action">{expanded === event._id ? '收起' : '详情'}</button></td></tr>{expanded === event._id && <tr className="screen-expanded"><td colSpan="6"><div><span>攻击来源 <b>{event.detail?.[0]?.source}</b></span><span>受影响组件 <b>{event.detail?.[0]?.target}</b></span><span>归档状态 <b className="cell-good">已记录</b></span></div></td></tr>}</Fragment>)}</tbody></table></div></ScreenPanel></div>
  </ScreenPage>
}

export function SettingsScreen({ user, onNavigate, onLogout }) {
  const [rights, live] = useScreenData(api.rights, { rights: { delete_record: true, register_user: true } })
  const permissions = [{ label: '查看安全态势', granted: true }, { label: '执行流量检测', granted: true }, { label: '查看模型推理', granted: true }, { label: '注册新用户', granted: Boolean(rights.rights?.register_user) }, { label: '删除敏感记录', granted: Boolean(rights.rights?.delete_record) }]
  const granted = permissions.filter(item => item.granted).length
  const shell = { user, onNavigate, onLogout }
  return <ScreenPage id="settings" title="系统设置" subtitle="用户身份、认证会话与权限状态" live={live} shell={shell}>
    <div className="screen-kpi-row"><ScreenKpi label="账号状态" value="正常" icon={UserCheck} tone="green" note="当前会话有效"/><ScreenKpi label="认证方式" value={user.demo ? 'DEMO' : 'TOKEN'} icon={LockKeyhole} note={user.demo ? '演示身份' : 'JWT 身份认证'}/><ScreenKpi label="已授权权限" value={`${granted}/${permissions.length}`} icon={CheckCircle2} tone="green" note="当前账号权限"/><ScreenKpi label="平台角色" value={user.demo ? '演示用户' : '管理员'} icon={ShieldCheck} note="访问控制角色"/></div>
    <div className="settings-screen-grid"><ScreenPanel title="当前用户" icon={CircleUserRound} badge="ACCOUNT"><div className="screen-user-card"><div><CircleUserRound size={42}/><i/></div><section><small>当前登录用户</small><h2>{user.username}</h2><span>{user.demo ? '演示用户' : '运营管理员'}</span></section></div><div className="account-facts"><div><span>账号状态</span><b className="cell-good">正常</b></div><div><span>认证模式</span><b>{user.demo ? '本地演示会话' : 'Token / JWT'}</b></div><div><span>数据模式</span><b>{user.demo ? 'DEMO DATA' : live ? 'REALTIME' : 'CHECKING'}</b></div></div></ScreenPanel>
      <ScreenPanel title="权限概览" icon={LockKeyhole} badge="ACCESS CONTROL"><div className="permission-ring" style={{ '--value': `${granted / permissions.length * 360}deg` }}><div><strong>{Math.round(granted / permissions.length * 100)}<small>%</small></strong><span>权限覆盖</span></div></div><div className="screen-permissions">{permissions.map(item => <div key={item.label} className={item.granted ? 'granted' : ''}><span>{item.granted ? <CheckCircle2 size={16}/> : <LockKeyhole size={16}/>} {item.label}</span><b>{item.granted ? '已授权' : '未授权'}</b></div>)}</div></ScreenPanel>
      <ScreenPanel title="安全会话信息" icon={ShieldCheck} badge="SESSION"><div className="session-timeline"><div className="done"><i><UserCheck size={17}/></i><section><b>身份验证</b><span>{user.demo ? '演示模式已启用' : '登录凭证验证通过'}</span></section></div><div className="done"><i><LockKeyhole size={17}/></i><section><b>权限加载</b><span>{granted} 项权限已生效</span></section></div><div className={live || user.demo ? 'done' : ''}><i><Wifi size={17}/></i><section><b>数据连接</b><span>{user.demo ? '使用本地演示数据' : live ? '权限服务连接正常' : '正在检查服务状态'}</span></section></div></div></ScreenPanel>
      <ScreenPanel title="平台运行说明" icon={Gauge} badge="SYSTEM"><div className="system-notes"><ShieldCheck size={48}/><h3>工业控制网络安全监控平台</h3><p>Token、SSE、检测接口和演示数据回退机制均保持启用。</p><div><span>界面版本</span><b>V2.6.0</b></div><div><span>字体系统</span><b>HarmonyOS Sans SC + Inter</b></div><div><span>安全策略</span><b>基于角色的访问控制</b></div></div></ScreenPanel></div>
  </ScreenPage>
}
