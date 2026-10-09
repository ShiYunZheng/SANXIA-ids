import { useEffect, useRef, useState } from 'react'
import { Activity, AlertTriangle, BarChart3, Bell, Cpu, Database, Gauge, Radio, Server, Shield, Wifi, Zap } from 'lucide-react'
import { Area, Bar, BarChart, CartesianGrid, Cell, ComposedChart, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/services'
import { stream } from '../api/client'
import { demoEvents, demoOverview, demoTrend } from '../data/demoData'
import heroImage from '../assets/reservoir-cyber-hero.png'
import BigScreenShell, { CHART_TOOLTIP, SCREEN_COLORS, ScreenPanel } from './BigScreenShell'
import './BigScreenOverview.css'

const severity = ['严重', '高危', '中危', '低危']
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000
const prioritizeWindows = items => [...(items || [])].sort((left, right) => {
  const abnormalOrder = Number(left.predictedLabel === 'normal') - Number(right.predictedLabel === 'normal')
  if (abnormalOrder) return abnormalOrder
  return new Date(right.createdAt || 0).getTime() - new Date(left.createdAt || 0).getTime()
}).slice(0, 5)

const demoInferenceJob = {
  id: 'demo-job', status: 'completed', progress: 100, actual_engine: 'cascade', requested_engine: 'cascade',
  stats: { totalWindows: 42, attackWindows: 31, averageConfidence: 0.948, averageLatencyMs: 3.7, highRiskCount: 18, attackDistribution: { '已知攻击': 18, '未知攻击': 13, '正常流量': 11 } },
}
const demoInferenceResults = Array.from({ length: 5 }, (_, index) => {
  const rows = [['已知攻击', 'critical'], ['未知攻击', 'high'], ['未知攻击', 'high'], ['正常流量', 'info'], ['已知攻击', 'critical']]
  const [label, severityLevel] = rows[index]
  const attack = severityLevel !== 'info'
  return { id: 'demo-result-' + index, window_index: index, label_display: label, severity: severityLevel, confidence: 0.88 + index * 0.018, src_ip: attack ? '192.168.101.99' : '192.168.101.10', dst_ip: '192.168.101.41', actual_engine: 'cascade' }
})
const demoModbusWindows = demoInferenceResults.map((item, index) => ({
  _id: item.id, windowKey: item.id, windowIndex: index + 18,
  predictedLabel: index === 3 ? 'normal' : index % 2 ? 'fuzzing' : 'write_single_register',
  severity: index === 3 ? 'normal' : item.severity,
  confidence: item.confidence, sourceIp: item.src_ip, destinationIp: item.dst_ip,
  engine: 'modbus-fast', createdAt: new Date(Date.now() - index * 15000).toISOString(),
  evidence: index === 3 ? '规则未发现异常行为' : 'Modbus 功能码与请求频率命中快速规则',
  association: index === 3 ? {} : {
    attackInfo: { name: index % 2 ? 'Modbus 模糊测试' : '写寄存器攻击', severity: item.severity, description: '演示窗口规则化研判' },
    cause: '异常 Modbus 操作序列触发窗口规则。',
    affectedSubsystem: '调速器控制链路',
    physicalConsequence: '可能造成控制参数异常，需结合现场状态核验。',
    recommendations: [{ priority: '最高', action: '隔离异常源并核验目标设备寄存器状态。' }],
  },
}))

function Ring({ value, label, tone = 'cyan' }) {
  const safe = Math.max(0, Math.min(100, Math.round(value || 0)))
  return <div className={`bs-ring ${tone}`} style={{ '--ring-value': `${safe * 3.6}deg` }}><div><strong>{safe}<small>%</small></strong><span>{label}</span></div></div>
}

function useDashboardData() {
  const demo = localStorage.getItem('sg_demo') === '1'
  const [overview, setOverview] = useState(demo ? demoOverview : {})
  const [trend, setTrend] = useState(demo ? demoTrend : [])
  const [eventData, setEventData] = useState(demo ? { events: demoEvents, total: demoEvents.length } : { events: [], total: 0 })
  const [inference, setInference] = useState({ job: demo ? demoInferenceJob : null, results: demo ? demoInferenceResults : [], source: demo ? 'DEMO' : 'WAITING' })
  const [alertHighlightIds, setAlertHighlightIds] = useState(() => new Set())
  const alertHighlightTimers = useRef(new Map())
  const [judgementData, setJudgementData] = useState({ items: demo ? demoModbusWindows : [], error: '', highlightId: null })
  const [dashboardState, setDashboardState] = useState({ totals: null, pipeline: null, generatedAt: null, error: '' })
  const [live, setLive] = useState(false)
  useEffect(() => {
    if (demo) return undefined
    let active = true
    const refreshJudgements = () => api.realtimeModbusWindows(5)
      .then(items => { if (active) setJudgementData({ items: prioritizeWindows(items), error: '' }) })
      .catch(reason => { if (active) setJudgementData(current => ({ ...current, error: reason?.message || 'standalone 窗口加载失败' })) })
    const refreshDashboard = () => api.dashboardRealtime(ONE_YEAR_MS, 6)
      .then(value => {
        if (!active) return
        setOverview(value.summary || {})
        setTrend(value.history || [])
        setDashboardState({ totals: value.totals || null, pipeline: value.pipeline || null, generatedAt: value.generatedAt || null, error: '' })
        setLive(true)
      })
      .catch(reason => {
        if (active) setDashboardState(current => ({ ...current, error: reason?.message || '实时态势更新中断' }))
      })
    refreshJudgements()
    refreshDashboard()
    Promise.allSettled([api.events(1, 8)]).then(results => {
      if (!active) return
      if (results[0].status === 'fulfilled') setEventData(results[0].value)
      if (active) {
        const latestEvents = results[0]?.status === 'fulfilled' ? results[0].value?.events || [] : []
        setInference({
          job: null,
          results: latestEvents.slice(0, 5).map((event, index) => ({
            id: event._id || `event-${index}`,
            label_display: event.eventType || '未命名告警',
            severity: Number(event.eventSeverity) <= 0 ? 'critical' : Number(event.eventSeverity) === 1 ? 'high' : Number(event.eventSeverity) === 2 ? 'medium' : 'info',
            confidence: null,
            src_ip: event.detail?.[0]?.source || event.detail?.[0]?.source_ip,
            dst_ip: event.detail?.[0]?.target || event.detail?.[0]?.destination_ip,
            dataSource: event.dataSource || event.data_source || '事件告警',
            timestamp: event.start_timestamp,
          })),
          source: latestEvents.length ? 'EVENTS' : 'WAITING',
        })
      }
    })
    let refreshTimer
    const scheduleRefresh = () => {
      window.clearTimeout(refreshTimer)
      refreshTimer = window.setTimeout(async () => {
        await refreshDashboard()
        if (active) scheduleRefresh()
      }, document.hidden ? 10000 : 2000)
    }
    const handleVisibility = () => scheduleRefresh()
    document.addEventListener('visibilitychange', handleVisibility)
    scheduleRefresh()
    const close = stream('/api/v1/events/stream', event => {
      if (!active || !event || event.engine === 'standalone') return
      const eventId = event._id ? String(event._id) : null
      setEventData(current => {
        const exists = Boolean(eventId && (current.events || []).some(item => String(item._id) === eventId))
        return { ...current, total: Number(current.total || 0) + (exists ? 0 : 1), events: [event, ...(current.events || []).filter(item => !eventId || String(item._id) !== eventId)].slice(0, 8) }
      })
      setInference(current => ({
        ...current,
        source: current.source === 'DEMO' ? current.source : 'EVENTS',
        results: [{
          id: event._id || `event-${Date.now()}`,
          label_display: event.eventType || '未命名告警',
          severity: Number(event.eventSeverity) <= 0 ? 'critical' : Number(event.eventSeverity) === 1 ? 'high' : Number(event.eventSeverity) === 2 ? 'medium' : 'info',
          confidence: null,
          src_ip: event.detail?.[0]?.source || event.detail?.[0]?.source_ip,
          dst_ip: event.detail?.[0]?.target || event.detail?.[0]?.destination_ip,
          dataSource: event.dataSource || event.data_source || '事件告警',
          timestamp: event.start_timestamp,
        }, ...(current.results || []).filter(item => !eventId || String(item.id) !== eventId)].slice(0, 5),
      }))
      if (eventId) {
        const previousTimer = alertHighlightTimers.current.get(eventId)
        if (previousTimer) window.clearTimeout(previousTimer)
        setAlertHighlightIds(current => new Set(current).add(eventId))
        const timer = window.setTimeout(() => {
          alertHighlightTimers.current.delete(eventId)
          setAlertHighlightIds(current => {
            const next = new Set(current)
            next.delete(eventId)
            return next
          })
        }, 6000)
        alertHighlightTimers.current.set(eventId, timer)
      }
      refreshDashboard()
      setLive(true)
    })
    const closeModbus = stream('/api/v1/pipeline/modbus/stream', item => {
      if (!active || !item) return
      const itemId = item.windowKey || item._id
      setJudgementData(current => ({
        error: '',
        highlightId: itemId,
        items: prioritizeWindows([item, ...(current.items || []).filter(existing => (existing.windowKey || existing._id) !== itemId)]),
      }))
      window.setTimeout(() => setJudgementData(current => current.highlightId === itemId ? { ...current, highlightId: null } : current), 4200)
      setLive(true)
    })
    return () => {
      active = false
      window.clearTimeout(refreshTimer)
      alertHighlightTimers.current.forEach(timer => window.clearTimeout(timer))
      alertHighlightTimers.current.clear()
      document.removeEventListener('visibilitychange', handleVisibility)
      close?.()
      closeModbus?.()
    }
  }, [demo])
  return { overview, trend, eventData, inference, alertHighlightIds, judgementData, dashboardState, demo, live: live && !demo }
}

function SecuritySummary({ score, total, attacks, alerts, status, error }) {
  return <div className="bs-security-summary"><div className="bs-score" style={{ '--score': `${score * 3.6}deg` }}><div><span>安全评分</span><strong>{score}</strong><small>/ 100 · 良好</small></div></div><div className="bs-stat-stack"><div><span>监测流量</span><strong>{total.toLocaleString()}</strong><small>条</small><b>实时</b></div><div><span>攻击告警</span><strong>{attacks.toLocaleString()}</strong><small>次</small><b className="danger">关注</b></div><div title="数据库正式事件与本轮待归档候选事件之和"><span>累计风险事件</span><strong>{alerts}</strong><small>起</small><b className="warn">含待归档</b></div></div>{(status || error) && <em className={`bs-realtime-note ${error ? 'error' : ''}`}>{error ? '数据更新中断 · 已保留上次结果' : status}</em>}</div>
}

function hasTrendEvents(data) {
  return (data || []).some(item => Object.entries(item || {}).some(([key, value]) => key !== 'time' && key !== 'Normal' && Number(value) > 0))
}

function formatTrendTime(value) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 5)
  return `${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

function formatTrendMonth(value) {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 7)
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
}

function RiskTrend({ data }) {
  const series = getEventSeries(data)
  if (!hasTrendEvents(data)) return <div className="bs-event-empty"><Activity size={22}/><span>近半年暂无安全事件</span></div>
  return <ResponsiveContainer width="100%" height="100%"><LineChart data={data} margin={{ top: 12, right: 9, left: -20, bottom: 0 }}><CartesianGrid stroke="#164b7c" strokeDasharray="2 3" vertical={false}/><XAxis dataKey="time" tickFormatter={formatTrendTime} tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip labelFormatter={formatTrendTime} contentStyle={CHART_TOOLTIP}/>{series.map(item => <Line key={item.key} type="monotone" dataKey={item.key} name={item.label} stroke={item.color} strokeWidth={2.2} dot={false} activeDot={{ r: 3 }}/>)}</LineChart></ResponsiveContainer>
}

const EVENT_SERIES_META = {
  SYN泛洪: { color: '#ff6470', label: 'SYN 泛洪', fill: 'url(#bsEventRed)' },
  nmap扫描: { color: '#25d7ff', label: 'nmap 扫描', fill: 'url(#bsEventCyan)' },
  MITM: { color: '#ffae43', label: 'MITM' },
  未知攻击: { color: '#c184ff', label: '未知攻击' },
}
const EVENT_SERIES_COLORS = ['#ff6470', '#25d7ff', '#ffae43', '#c184ff', '#27d6a2', '#62a8ff', '#f06dff', '#ffd166', '#42e8b4', '#ff8c42', '#9bde5b', '#4ecdc4', '#ff6b9f', '#5f8cff', '#b8e986', '#e76f51', '#2ec4b6', '#a78bfa']

function getEventSeries(data, includeEmpty = false) {
  const keys = [...new Set((data || []).flatMap(item => Object.keys(item || {})))]
    .filter(key => key !== 'time' && key !== 'Normal')
    .filter(key => includeEmpty || (data || []).some(item => Number(item?.[key]) > 0))
  return keys.map((key, index) => ({
    key,
    ...(EVENT_SERIES_META[key] || { color: EVENT_SERIES_COLORS[index % EVENT_SERIES_COLORS.length], label: key }),
  }))
}

function EventTrendTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return <div className="event-trend-tooltip"><div className="event-trend-tooltip-time"><span>监测日期</span><strong>{formatTrendTime(label)}</strong></div>{payload.map(item => {
    const series = EVENT_SERIES_META[item.dataKey] || { color: item.color, label: item.name }
    return <div className="event-trend-tooltip-row" key={item.dataKey}><i style={{ '--series-color': series.color }}/><span>{series.label}</span><b>{Number(item.value || 0).toLocaleString()}</b><em>次</em></div>
  })}</div>
}

function EventTrendCursor({ x, y, width, height }) {
  const center = x + width / 2
  return <g className="event-trend-cursor"><rect x={center - 14} y={y} width={28} height={height} rx={12}/><line x1={center} x2={center} y1={y + 4} y2={y + height}/></g>
}

function EventTrendChart({ data }) {
  const series = getEventSeries(data, true)
  if (!series.length) return <div className="bs-event-empty"><Activity size={22}/><span>近一年暂无安全事件</span></div>
  const totals = series
    .map(item => ({ ...item, total: (data || []).reduce((sum, row) => sum + Number(row?.[item.key] || 0), 0) }))
    .sort((left, right) => right.total - left.total || left.label.localeCompare(right.label, 'zh-CN'))
  const grandTotal = totals.reduce((sum, item) => sum + item.total, 0)
  const barSize = Math.max(3, Math.min(9, Math.floor(58 / Math.max(series.length, 1))))
  return <div className="bs-event-bars"><div className="bs-event-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} margin={{ top: 12, right: 12, left: -8, bottom: 3 }} barGap={series.length > 6 ? 1 : 3} barCategoryGap="24%">
    <defs>
      <linearGradient id="bsEventRed" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ff7d87"/><stop offset=".18" stopColor="#ff5e6b"/><stop offset="1" stopColor="#d92f47"/></linearGradient>
      <linearGradient id="bsEventCyan" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#72ecff"/><stop offset=".18" stopColor="#25d7ff"/><stop offset="1" stopColor="#078abb"/></linearGradient>
      <filter id="bsEventGlowRed" x="-80%" y="-30%" width="260%" height="180%"><feDropShadow dx="0" dy="0" stdDeviation="2.5" floodColor="#ff4f61" floodOpacity=".38"/></filter>
      <filter id="bsEventGlowCyan" x="-80%" y="-30%" width="260%" height="180%"><feDropShadow dx="0" dy="0" stdDeviation="2.5" floodColor="#19d3ff" floodOpacity=".42"/></filter>
    </defs>
    <CartesianGrid stroke="rgba(75, 157, 205, .32)" strokeDasharray="3 7" vertical strokeOpacity={.55}/>
    <XAxis dataKey="time" tickFormatter={formatTrendMonth} interval={0} tick={{ fill: '#9bc5dd', fontSize: 11 }} tickMargin={9} axisLine={false} tickLine={false}/>
    <YAxis tick={{ fill: '#759ab8', fontSize: 10 }} width={34} axisLine={false} tickLine={false}/>
    <Tooltip content={<EventTrendTooltip/>} cursor={<EventTrendCursor/>} allowEscapeViewBox={{ x: true, y: true }} wrapperStyle={{ outline: 'none' }}/>
    {series.map(item => <Bar key={item.key} dataKey={item.key} name={item.label} fill={item.fill || item.color} barSize={barSize} radius={[4, 4, 1, 1]} stroke={item.color} strokeWidth={1} fillOpacity={.94} activeBar={{ stroke: '#ffffff', strokeWidth: 1.6, fillOpacity: 1 }}/>) }
  </BarChart></ResponsiveContainer></div><div className="bs-event-summary"><div className="bs-event-summary-head"><span>攻击类型</span><span>总量 / 占比</span></div><div className="bs-event-summary-grid">{totals.map(item => <div className="bs-event-summary-item" key={item.key} title={item.label}><span><i style={{ background: item.color, boxShadow: `0 0 7px ${item.color}` }}/><b>{item.label}</b></span><strong>{item.total.toLocaleString()}<small>{grandTotal ? (item.total / grandTotal * 100).toFixed(1) : '0.0'}%</small></strong></div>)}</div></div></div>
}
function AttackDonut({ data }) {
  const items = (data || [])
    .filter(item => item.name !== 'Normal' && Number(item.total) > 0)
    .map((item, index) => ({ ...item, total: Number(item.total), color: SCREEN_COLORS[index % SCREEN_COLORS.length] }))
  const total = items.reduce((sum, item) => sum + item.total, 0)
  const topItems = [...items]
    .filter(item => total && Math.round(item.total / total * 100) > 0)
    .sort((left, right) => right.total - left.total || String(left.name).localeCompare(String(right.name), 'zh-CN'))
    .slice(0, 5)
  return <div className="bs-donut-layout"><div className="bs-donut-chart"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={items} dataKey="total" nameKey="name" innerRadius="56%" outerRadius="82%" paddingAngle={2} stroke="none">{items.map(item => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={CHART_TOOLTIP}/></PieChart></ResponsiveContainer><div><strong>{total.toLocaleString()}</strong><span>攻击总量</span></div></div><div className="bs-attack-legend"><div className="bs-attack-legend-title">攻击类型分布 TOP 5</div><div className="bs-legend">{topItems.map(item => <div key={item.name}><i style={{ background: item.color }}/><span>{item.name}</span><b>{total ? Math.round(item.total / total * 100) : 0}%</b></div>)}</div></div></div>
}

function ReservoirMap({ assetData, alerts, total }) {
  const nodes = [{ name: '监控主机', x: 49, y: 24, icon: Server }, { name: '数据服务器', x: 27, y: 43, icon: Database }, { name: '以太网交换机', x: 52, y: 55, icon: Wifi, core: true }, { name: '左阀门', x: 28, y: 72, icon: Gauge }, { name: '右阀门', x: 76, y: 68, icon: Zap, warning: true }]
  const counts = Object.fromEntries(assetData.map(item => [item.name, Object.entries(item).filter(([key]) => key !== 'name').reduce((sum, [, value]) => sum + (Number(value) || 0), 0)]))
  const background = `linear-gradient(180deg, rgba(2,13,31,.08), rgba(2,13,31,.25)), url(${heroImage})`
  return <div className="bs-reservoir" style={{ backgroundImage: background }}><div className="bs-map-vignette"/><svg className="bs-map-lines" viewBox="0 0 100 100" preserveAspectRatio="none"><path d="M49 24 C43 34 35 38 27 43 M49 24 C52 35 52 45 52 55 M27 43 C35 54 42 57 52 55 M52 55 C62 58 68 64 76 68 M52 55 C42 62 35 68 28 72"/><path className="hot" d="M52 55 C62 58 68 64 76 68"/></svg>{nodes.map(({ name, x, y, icon: Icon, core, warning }) => <div key={name} className={`bs-map-node ${core ? 'core ' : ''}${warning ? 'warning' : ''}`} style={{ left: `${x}%`, top: `${y}%` }}><span><Icon size={core ? 19 : 15}/></span><div><b>{name}</b><small>{warning ? '发现异常流量' : `检测样本 ${(counts[name] || 0).toLocaleString()}`}</small></div></div>)}<div className="bs-map-facts"><div><span>在线节点</span><strong>05</strong></div><div><span>风险节点</span><strong className="warn">{Math.min(5, alerts)}</strong></div><div><span>累计流量</span><strong>{total.toLocaleString()}</strong></div></div><div className="bs-scan-line"/></div>
}

function Assets({ data }) {
  const items = data.map(item => ({ name: item.name, total: Object.entries(item).filter(([key]) => key !== 'name').reduce((sum, [, value]) => sum + (Number(value) || 0), 0) }))
  const total = items.reduce((sum, item) => sum + item.total, 0)
  return <div className="bs-asset-layout" title="按实时检测样本关联的设备组件统计，不代表资产发现数量"><div className="bs-mini-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={items} dataKey="total" innerRadius="56%" outerRadius="82%" stroke="none">{items.map((item, index) => <Cell key={item.name} fill={SCREEN_COLORS[index]}/>)}</Pie></PieChart></ResponsiveContainer><div><strong>{items.length}</strong><span>设备类型</span></div></div><div className="bs-legend">{items.map((item, index) => <div key={item.name}><i style={{ background: SCREEN_COLORS[index] }}/><span>{item.name}</span><b>{total ? Math.round(item.total / total * 100) : 0}%</b></div>)}</div></div>
}

function FlowChart({ data }) {
  return <ResponsiveContainer width="100%" height="100%"><ComposedChart data={data} margin={{ top: 10, right: 8, left: -20, bottom: 0 }}><defs><linearGradient id="bsFlow" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#16cfff" stopOpacity=".55"/><stop offset="1" stopColor="#1266ff" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="#164b7c" strokeDasharray="2 3" vertical={false}/><XAxis dataKey="time" tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={CHART_TOOLTIP}/><Area type="monotone" dataKey="nmap扫描" stroke="#19d3ff" fill="url(#bsFlow)" strokeWidth={2.2}/><Line type="monotone" dataKey="MITM" stroke="#ffae43" strokeWidth={2.1} dot={{ r: 2 }}/></ComposedChart></ResponsiveContainer>
}

const inferenceSeverity = { critical: ['严重', 'critical'], high: ['高危', 'high'], medium: ['中危', 'medium'], info: ['正常', 'info'] }

function InferenceResultsPreview({ results, source, highlightIds }) {
  return <div className="bs-inference-results-preview">{results.length ? results.slice(0, 5).map((item, index) => {
    const [level, levelClass] = inferenceSeverity[item.severity] || ['告警', 'medium']
    const isNew = highlightIds?.has(String(item.id))
    return <div className={`bs-inference-result ${levelClass}${isNew ? ' live-alert' : ''}`} key={item.id || index}><span className="bs-inference-window">#{String(index + 1).padStart(2, '0')}{isNew && <i>NEW</i>}</span><div className="bs-inference-result-main"><b>{item.label_display || item.label || '未知判定'}</b><small>{item.src_ip || '--'} → {item.dst_ip || '--'} · {item.dataSource || '模型研判'}</small></div><span className={`bs-inference-level ${levelClass}`}>{level}</span><strong>{item.confidence == null ? '已告警' : `${(Number(item.confidence) * 100).toFixed(1)}%`}</strong></div>
  }) : <div className="bs-inference-empty"><Cpu size={28}/><b>暂无模型推理结果</b><small>等待模型推理或实时告警</small></div>}<em className={`bs-inference-source ${source === 'API' || source === 'EVENTS' ? 'live' : ''}`}>{source}</em></div>
}

function formatOverviewTime(value) {
  const date = value ? new Date(value) : null
  return date && !Number.isNaN(date.getTime()) ? date.toLocaleTimeString('zh-CN', { hour12: false }) : '刚刚'
}

function JudgementPreview({ items, error, highlightId }) {
  const latestId = items[0]?.windowKey || items[0]?._id
  const [openId, setOpenId] = useState(latestId || null)
  useEffect(() => { if (latestId) setOpenId(latestId) }, [latestId])
  return <div className="bs-judgement-preview">
    {error && <div className="bs-judgement-error">{error} · 已保留上次结果</div>}
    <div className="bs-judgement-accordion">{items.length ? items.slice(0, 5).map((item, index) => {
      const itemId = item.windowKey || item._id || `judgement-${index}`
      const analysis = item.association || {}
      const severityName = analysis.attackInfo?.severity || item.severity
      const level = ({ critical: 0, high: 1, medium: 2, low: 3, normal: 3 })[severityName] ?? 2
      const normal = item.predictedLabel === 'normal'
      const expanded = openId === itemId
      const recommendations = [...(analysis.recommendations || [])].sort((left, right) => (left.priority === '最高' ? -1 : 0) - (right.priority === '最高' ? -1 : 0))
      return <article className={`bs-judgement-entry ${expanded ? 'expanded' : ''} ${highlightId === itemId ? 'live-window' : ''}`} key={itemId}>
        <button className="bs-judgement-toggle" aria-expanded={expanded} onClick={() => setOpenId(expanded ? null : itemId)}>
          <span className={`bs-judgement-priority p${level}`}>P{level + 1}</span>
          <b>W#{item.windowIndex ?? index} · {analysis.attackInfo?.name || item.predictedLabel || '未知窗口'}</b>
          <small>{normal ? '正常' : severityName || '--'} · {item.confidence == null ? '--' : `${(Number(item.confidence) * 100).toFixed(1)}%`}</small>
          <time>{formatOverviewTime(item.createdAt)}</time>
          <em>{item.engine || 'modbus-fast'}</em>
          <i>{expanded ? '−' : '+'}</i>
        </button>
        {expanded && <div className="bs-judgement-detail">
          <section><b>1. 判定依据</b><p>{normal ? item.evidence || '窗口未触发异常规则' : analysis.cause || item.evidence || '暂无规则化研判摘要'}</p></section>
          <section><b>2. {normal ? '窗口信息' : '攻击关联'}</b><p><strong>类型：</strong>{analysis.attackInfo?.name || item.predictedLabel || '--'}　<strong>严重度：</strong>{normal ? '正常' : severityName || '--'}</p>{!normal && <p><strong>影响子系统：</strong>{analysis.affectedSubsystem || '待人工确认'}</p>}<p><strong>通信路径：</strong>{item.sourceIp || '--'} → {item.destinationIp || '--'}</p>{!normal && analysis.physicalConsequence && <p className="bs-judgement-consequence">{analysis.physicalConsequence}</p>}</section>
          <section><b>3. 预防与处置建议</b>{recommendations.length ? recommendations.slice(0, 5).map((recommendation, recommendationIndex) => <p className="bs-judgement-recommendation" key={`${recommendation.action}-${recommendationIndex}`}><span>{recommendation.priority || '建议'}</span>{recommendation.action}</p>) : <p>暂无规则化建议，请转人工研判。</p>}</section>
        </div>}
      </article>
    }) : <div className="bs-judgement-empty"><Shield size={25}/><b>暂无 standalone 窗口</b><small>{error || 'WLAN 或模拟回放产生的 Modbus 窗口将在此显示'}</small></div>}</div>
  </div>
}
export default function BigScreenOverview({ user, onNavigate, onLogout }) {
  const { overview, trend, eventData, inference, alertHighlightIds, judgementData, dashboardState, demo, live } = useDashboardData()
  const pieData = overview.pie_data || []
  const assetData = overview.list_data || []
  const pieTotal = pieData.reduce((sum, item) => sum + (Number(item.total) || 0), 0)
  const pieAttacks = pieTotal - (pieData.find(item => item.name === 'Normal')?.total || 0)
  const total = Number(dashboardState.totals?.monitoredTraffic ?? pieTotal)
  const attacks = Number(dashboardState.totals?.attackAlerts ?? pieAttacks)
  const alerts = Number(dashboardState.totals?.riskEvents ?? eventData.total ?? 0)
  const events = demo ? demoEvents : (eventData.events || [])
  const highRisk = events.filter(item => item.eventSeverity <= 1).length
  const score = Math.max(72, Math.min(99, 98 - highRisk * 2 - Math.round(attacks / Math.max(total, 1) * 8)))
  const dashboardBadge = demo ? 'DEMO' : dashboardState.error ? 'STALE' : dashboardState.pipeline?.running ? 'REALTIME' : 'LIVE'
  const dashboardStatus = dashboardState.pipeline?.running
    ? `运行 ${String(dashboardState.pipeline.runId || '').slice(0, 8)} · ${dashboardState.generatedAt ? new Date(dashboardState.generatedAt).toLocaleTimeString('zh-CN', { hour12: false }) : '更新中'}`
    : dashboardState.generatedAt ? `更新于 ${new Date(dashboardState.generatedAt).toLocaleTimeString('zh-CN', { hour12: false })}` : ''

  return <BigScreenShell page="overview" pageTitle="态势总览" subtitle="工业控制网络实时态势感知" user={user} onNavigate={onNavigate} onLogout={onLogout} live={live}>
    <div className="bs-main-grid"><div className="bs-column left"><ScreenPanel title="总体态势概览" icon={Shield} className="summary" badge={dashboardBadge}><SecuritySummary score={score} total={total} attacks={attacks} alerts={alerts} status={dashboardStatus} error={dashboardState.error}/></ScreenPanel><ScreenPanel title="风险趋势分析" icon={Activity} className="risk" badge={dashboardBadge}><RiskTrend data={trend}/></ScreenPanel><ScreenPanel title="攻击类型分布" icon={AlertTriangle} className="attacks" badge={dashboardBadge}><AttackDonut data={pieData}/></ScreenPanel></div>
      <div className="bs-column center"><ScreenPanel title="工业控制网络实时态势感知" icon={Radio} className="hero" badge={dashboardBadge}><ReservoirMap assetData={assetData} alerts={highRisk} total={total}/></ScreenPanel><ScreenPanel title="安全事件趋势" icon={BarChart3} className="event-trend" badge={dashboardBadge}><EventTrendChart data={trend}/></ScreenPanel></div>
      <div className="bs-column right"><ScreenPanel title="检测流量设备分布" icon={Database} className="assets" badge={dashboardBadge}><Assets data={assetData}/></ScreenPanel><ScreenPanel title="最新安全研判" icon={Bell} className="flow judgement" badge={`${judgementData.items.length} 条`}><JudgementPreview items={judgementData.items} error={judgementData.error} highlightId={judgementData.highlightId}/></ScreenPanel><ScreenPanel title="最新安全事件" icon={AlertTriangle} className="alerts inference-latest" badge={`${inference.results.length || 0} 条`}><InferenceResultsPreview results={inference.results} source={inference.source} highlightIds={alertHighlightIds}/></ScreenPanel></div></div>
  </BigScreenShell>
}
