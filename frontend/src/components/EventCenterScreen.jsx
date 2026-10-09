import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, Bell, Check, ChevronRight, Clock3, Copy, Gauge, Network, RefreshCw, Save, ShieldCheck, Wifi, X } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/services'
import { stream } from '../api/client'
import { demoEvents } from '../data/demoData'
import BigScreenShell, { CHART_TOOLTIP, SCREEN_COLORS, ScreenPanel } from './BigScreenShell'
import './BigScreenPages.css'
import './EventCenterScreen.css'

const severityLabels = ['严重', '高危', '中危', '低危']
const severityColors = [SCREEN_COLORS[2], SCREEN_COLORS[3], SCREEN_COLORS[1], SCREEN_COLORS[0]]
const sourceLabels = { interface: 'WLAN实时', replay: 'PCAP回放', pcap: 'PCAP文件', csv: 'CSV文件' }
const ARCHIVE_PAGE_SIZE = 10
const dispositionLabels = { pending: '待确认', investigating: '研判中', contained: '已遏制', resolved: '已处置', false_positive: '误报', closed: '已关闭' }
const severityNames = { critical: '严重', high: '高危', medium: '中危', low: '低危', unknown: '待确认' }
const severitySourceLabels = { rule: '规则定级', 'rule-fallback': '规则未覆盖', human: '人工确认', historical: '历史数据' }
const severityStatusLabels = { assessed: '已完成', pending_confirmation: '待人工确认', evidence_insufficient: '证据不足', confirmed: '人工已确认' }
const isSanxiaEvent = event => event?.engine !== 'standalone'
const mergeRuntimeAlerts = (current, incoming) => {
  const merged = new Map()
  ;[...(incoming || []), ...current].forEach((alert, index) => {
    const key = String(alert?.alertId || `${alert?.runId || 'run'}:${alert?.attackLabel || index}:${alert?.source || ''}:${alert?.target || ''}:${alert?.emittedAt || index}`)
    if (!merged.has(key)) merged.set(key, alert)
  })
  return [...merged.values()].slice(0, 200)
}
const runtimeAlertEvent = alert => ({
  _id: `runtime:${alert.alertId}`,
  runtimeAlertId: alert.alertId,
  formalEventId: alert.eventId || null,
  pipelineRunId: alert.runId,
  sourceContextId: alert.sourceContextId,
  eventType: alert.eventType || alert.attackLabel,
  attackLabel: alert.attackLabel,
  eventSeverity: alert.eventSeverity,
  start_timestamp: alert.startAt || alert.emittedAt,
  end_timestamp: alert.endAt,
  receivedAt: alert.emittedAt,
  sampleCount: Number(alert.sampleCount || 0),
  dataSource: alert.dataSource,
  archiveStatus: alert.archiveStatus,
  severitySource: alert.severitySource,
  severityPolicyVersion: alert.severityPolicyVersion,
  severityStatus: alert.severityStatus,
  riskAssessment: alert.riskAssessment,
  engine: 'sanxia-runtime',
  detail: [{ source: alert.source, target: alert.target }],
})

const eventSourceLabel = (event, fallback) => event.dataSource || event.data_source || event.sourceType || fallback || '未知来源'
const percent = value => Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : '--'
const scorePosition = value => Number.isFinite(Number(value)) ? Math.max(0, Math.min(100, Number(value) * 100)) : 0
const validAsset = value => {
  const text = String(value || '').trim()
  return text && !/^(test|unknown|未知|未知组件|未标注组件|--|modbus\/tcp)$/i.test(text)
}
const displayTime = value => {
  const date = value ? new Date(value) : null
  return date && !Number.isNaN(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : value || '--'
}
const recommendationGroup = item => {
  const text = `${item?.domain || ''} ${item?.action || ''}`
  if (/设备|现场|寄存器|控制器|阀门|物理/.test(text)) return '设备核验'
  if (/观察|监控|持续|审计|日志|关联/.test(text)) return '持续观察'
  return '立即处置'
}
const communicationSummary = details => {
  const routes = new Map()
  const sources = new Set()
  const targets = new Set()
  details.forEach(item => {
    const source = item.source_ip || item.source || '未知源'
    const target = item.destination_ip || item.target || '未知目标'
    sources.add(source); targets.add(target)
    const key = `${source} → ${target}`
    routes.set(key, (routes.get(key) || 0) + 1)
  })
    const times = details.map(item => new Date(item.timestamp).getTime()).filter(Number.isFinite)
  return {
    sources: sources.size,
    targets: targets.size,
    duration: times.length > 1 ? Math.max(0, (Math.max(...times) - Math.min(...times)) / 1000).toFixed(3) + ' 秒' : '--',
    routes: [...routes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5),
  }
}

function EvidenceMeter({ value, threshold, label = '模型分数' }) {
  const hasValue = Number.isFinite(Number(value))
  const hasThreshold = Number.isFinite(Number(threshold))
  return <div className="event-score-meter">
    <div><span>{label}</span><b>{hasValue ? percent(value) : '--'}</b>{hasThreshold && <em>阈值 {percent(threshold)}</em>}</div>
    <div className="event-score-track"><i style={{ width: `${scorePosition(value)}%` }}/>{hasThreshold && <mark style={{ left: `${scorePosition(threshold)}%` }}/>}</div>
  </div>
}

function SeverityDonut({ events, summary }) {
  const counts = summary?.bySeverity || {}
  const data = severityLabels
    .map((name, severity) => ({ name, value: Number(counts[severity] ?? events.filter(item => item.eventSeverity === severity).length), color: severityColors[severity] }))
    .filter(item => item.value)
  const total = Number(summary?.total ?? data.reduce((sum, item) => sum + item.value, 0))
  return <div className="screen-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" innerRadius="57%" outerRadius="82%" paddingAngle={3} stroke="none">{data.map(item => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={CHART_TOOLTIP}/></PieChart></ResponsiveContainer><div><strong>{total}</strong><span>事件总量</span></div></div>
}

function CompactEventList({ events, highlightIds, defaultSource, archiveLinkCounts, onOpen }) {
  if (!events.length) return <div className="screen-event-list event-list-empty"><Bell size={30}/><b>暂无匹配告警</b><span>可切换上方告警级别查看其他事件</span></div>
  return <div className="screen-event-list">{events.map((event, index) => {
    const severity = Math.min(3, Math.max(0, Number(event.eventSeverity)))
    const level = 4 - severity
    const detail = event.detail?.[0] || {}
    const time = event.start_timestamp || detail.timestamp || '刚刚'
    const isNew = highlightIds?.has(String(event._id))
    const linkedAlerts = event.formalEventId ? Number(archiveLinkCounts?.get(event.formalEventId) || 0) : 0
    const archiveLabel = event.archiveStatus === 'deduplicated'
      ? '重复告警'
      : event.archiveStatus === 'archived' && linkedAlerts > 1
        ? '已聚合至事件'
        : event.archiveStatus === 'archived'
          ? '已生成事件'
          : '待归档'
    const canOpen = Boolean(event.formalEventId) && event.archiveStatus !== 'deduplicated'
    const open = () => { if (canOpen) onOpen?.({ ...event, _id: event.formalEventId }) }
    const onKeyDown = keyEvent => {
      if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
        keyEvent.preventDefault()
        open()
      }
    }
    return <article role={canOpen ? 'button' : undefined} tabIndex={canOpen ? 0 : -1} aria-label={canOpen ? `查看${event.eventType || '告警事件'}详情` : `${event.eventType || '告警事件'}已去重`} onClick={open} onKeyDown={onKeyDown} className={'event-alert-card level-' + level + (isNew ? ' event-live-highlight' : '')} key={(event._id || 'event') + index}>
      <div className="event-alert-rail"><span className={'event-beacon level-' + level}>{level}</span><small>{severityLabels[severity] || '告警'}</small></div>
      <div className="event-alert-main"><div className="event-alert-title"><b>{event.eventType || '未命名告警'}</b><span>SANXIA</span><span>{severitySourceLabels[event.severitySource] || '规则定级'}</span>{event.severityStatus === 'pending_confirmation' && <span>待确认</span>}{isNew && <span>NEW</span>}</div><div className="event-alert-meta"><div className="event-route"><i>{detail.source || detail.source_ip || '未知源'}</i><em>→</em><i>{detail.target || detail.destination_ip || '多节点'}</i></div><span className="event-source-tag">{eventSourceLabel(event, defaultSource)}</span><span className="event-alert-samples">{event.sampleCount || 0} 包</span><span className={`event-archive-state ${event.archiveStatus || 'pending'}`}>{archiveLabel}</span></div></div>
      <div className="event-alert-fact event-alert-time"><Clock3 size={16}/><span>发生时间</span><time>{String(time)}</time></div>
      <em className={'severity-text s' + severity}>{severityLabels[severity] || '告警'}</em>
      <ChevronRight className="event-alert-chevron" size={20} aria-hidden="true"/>
    </article>
  })}</div>
}

const demoPlaybooks = {
  'SYN泛洪': {
    cause: '检测到短时间内大量 SYN 请求集中指向同一控制节点，连接建立率明显异常，符合拒绝服务攻击特征。',
    consequence: '持续的连接洪泛可能耗尽阀门控制节点的会话资源，导致控制指令延迟或暂时不可达。',
    recommendations: ['限制异常源地址的连接速率并临时隔离该主机', '检查右阀门控制器的连接队列和资源占用', '关联同期网络设备日志确认是否存在协同攻击'],
  },
  'nmap扫描': {
    cause: '同一来源连续探测多个端口和服务，访问序列符合网络资产扫描行为。',
    consequence: '扫描本身通常不直接改变设备状态，但可能用于识别后续攻击入口和暴露服务。',
    recommendations: ['核验扫描源是否属于授权运维终端', '封禁未授权扫描源并复核暴露端口', '检查数据服务器是否存在弱口令或过期服务'],
  },
  MITM: {
    cause: '通信路径出现地址解析或会话映射异常，符合中间人劫持风险特征。',
    consequence: '攻击者可能监听或篡改控制指令，造成状态数据失真或未经授权的设备操作。',
    recommendations: ['隔离可疑源地址并刷新交换设备地址表', '核对关键控制指令与现场设备状态', '启用静态绑定或链路层防护策略'],
  },
  '电机开关故障': {
    cause: '控制流量中的开关状态与预期操作序列不一致，需要结合设备日志确认是攻击还是设备故障。',
    consequence: '异常开关操作可能影响阀门执行机构的启停与联锁状态。',
    recommendations: ['切换至安全控制模式并核验现场状态', '检查执行机构、控制回路和同期操作日志', '保留相关流量并转交人工复核'],
  },
}

function buildDemoEventDetail(event) {
  const detail = event.detail?.[0] || {}
  const playbookKey = Object.keys(demoPlaybooks).find(key => event.eventType?.includes(key))
  const playbook = demoPlaybooks[playbookKey] || {
    cause: '该演示告警尚未匹配专用规则，需要结合通信流量、设备日志和现场状态进行人工研判。',
    consequence: '当前证据不足以确认具体物理影响。',
    recommendations: ['检查源地址相关通信记录', '核对目标设备日志和现场运行状态'],
  }
  return {
    event: { ...event, engine: event.engine || 'sanxia', dataSource: eventSourceLabel(event, 'DEMO'), disposition: { status: 'pending', assignee: '', conclusion: '' }, dispositionHistory: [] },
    judgement: {
      eventId: event._id,
      timestamp: event.start_timestamp,
      eventType: event.eventType,
      eventSeverity: event.eventSeverity,
      dataSource: eventSourceLabel(event, 'DEMO'),
      sourceIp: detail.source,
      destinationIp: detail.target,
      status: '规则辅助研判',
      engine: 'sanxia-rule',
      cause: playbook.cause,
      attackInfo: {
        name: playbookKey || event.eventType || '未知攻击',
        severity: ['critical', 'high', 'medium', 'low'][Math.min(3, Math.max(0, Number(event.eventSeverity)))],
        description: '演示模式规则化研判结果，仅用于功能展示。',
      },
      affectedSubsystem: detail.target || '待人工确认',
      physicalConsequence: playbook.consequence,
      historicalMatch: { matched: false, reason: '演示模式未连接历史故障库', totalMatchingRecords: 0, uniqueFaultModes: 0, topFaults: [] },
      recommendations: playbook.recommendations.map((action, index) => ({ priority: index === 0 ? '最高' : '建议', domain: '安全运营', action, source: 'demo' })),
    },
  }
}

function EventDetailDrawer({ selectedEvent, payload, loading, error, onClose, onRetry, onRegenerate, onDisposition, user }) {
  const event = payload?.event || selectedEvent || {}
  const judgement = payload?.judgement || {}
  const disposition = event.disposition || { status: 'pending', assignee: '', confirmedAttackType: '', actualImpact: '', conclusion: '' }
  const [form, setForm] = useState({ status: 'pending', assignee: '', confirmedAttackType: '', actualImpact: '', conclusion: '', note: '', eventSeverity: 2, severityLocked: false })
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [copied, setCopied] = useState(false)
  const [manualSeverityTouched, setManualSeverityTouched] = useState(false)
  useEffect(() => {
    setForm({ status: disposition.status || 'pending', assignee: disposition.assignee || '', confirmedAttackType: disposition.confirmedAttackType || '', actualImpact: disposition.actualImpact || '', conclusion: disposition.conclusion || '', note: '', eventSeverity: Number(event.eventSeverity ?? 2), severityLocked: Boolean(event.severityLocked) })
    setManualSeverityTouched(false)
    setSaveError('')
  }, [event._id, event.eventSeverity, event.severityLocked, disposition.status, disposition.assignee, disposition.confirmedAttackType, disposition.actualImpact, disposition.conclusion])
  if (!selectedEvent) return null

  const severity = Math.min(3, Math.max(0, Number(event.eventSeverity)))
  const details = event.detail || []
  const faultHistory = judgement.historicalMatch
  const recommendations = judgement.recommendations || []
  const recommendationGroups = recommendations.reduce((groups, item) => {
    const group = recommendationGroup(item)
    groups[group] = [...(groups[group] || []), item]
    return groups
  }, {})
  const evidence = event.modelEvidence || {}
  const risk = event.riskAssessment || {}
  const unknown = event.attackLabel === '未知攻击' || String(event.eventType || '').includes('未知攻击')
  const mapped = Boolean(judgement.label)
  const comms = communicationSummary(details)
  const components = [...new Set(details.map(item => item.component).filter(validAsset))]
  const primarySource = judgement.sourceIp || details[0]?.source_ip || details[0]?.source || '未记录'
  const primaryTarget = judgement.destinationIp || details[0]?.destination_ip || details[0]?.target || '未记录'
  const representativeDetails = details.slice(0, 5)
  const isAdmin = Number(user?.role) === 0
  const finalLocked = !isAdmin && ['false_positive', 'closed'].includes(disposition.status)
  const allowedStatuses = isAdmin ? Object.keys(dispositionLabels) : finalLocked ? [disposition.status] : ['pending', 'investigating', 'contained', 'resolved']

  const submitDisposition = async submitEvent => {
    submitEvent.preventDefault()
    setSaving(true)
    setSaveError('')
    try {
      const payload = isAdmin && manualSeverityTouched
        ? form
        : (({ eventSeverity, severityLocked, ...allowed }) => allowed)(form)
      await onDisposition?.(payload)
      setForm(current => ({ ...current, note: '' }))
    } catch (reason) {
      setSaveError(reason?.message || '处置记录保存失败')
    } finally {
      setSaving(false)
    }
  }
  const copyId = async () => {
    try {
      await navigator.clipboard.writeText(event._id || '')
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }

  return <>
    <button type="button" className="event-detail-backdrop" aria-label="关闭告警详情" onClick={onClose}/>
    <aside className="event-detail-drawer event-analysis-workbench" role="dialog" aria-modal="true" aria-labelledby="event-detail-title">
      <header className="event-detail-header">
        <div><span>SANXIA EVENT / INCIDENT RESPONSE</span><h2 id="event-detail-title">{event.eventType || '安全事件详情'}</h2></div>
        <button type="button" className="event-detail-close" aria-label="关闭告警详情" onClick={onClose}><X size={18}/></button>
      </header>
      {loading && <div className="event-detail-state"><i/><b>正在加载安全分析与处置记录</b><span>正在读取模型证据、规则关联和人工处置历史…</span></div>}
      {!loading && error && <div className="event-detail-state error"><AlertTriangle size={30}/><b>详情加载失败</b><span>{error}</span><button type="button" onClick={onRetry}><RefreshCw size={14}/>重新加载</button></div>}
      {!loading && !error && payload && <div className="event-detail-content">
        <section className="event-detail-overview">
          <div><span>告警级别</span><b className={'screen-severity s' + severity}>{severityLabels[severity]}</b></div>
          <div><span>处置状态</span><b className={`disposition-status ${disposition.status || 'pending'}`}>{dispositionLabels[disposition.status] || '待确认'}</b></div>
          <div><span>数据来源</span><b>{eventSourceLabel(event, judgement.dataSource)}</b></div>
          <div><span>检测引擎</span><b>SANXIA 级联模型</b></div>
          <div><span>主要源地址</span><b>{primarySource}</b></div>
          <div><span>主要目标地址</span><b>{primaryTarget}</b></div>
          <div><span>负责人</span><b>{disposition.assignee || '未认领'}</b></div>
          <div className="event-id-cell"><span>事件编号</span><b title={event._id}>{event._id || '--'}</b><button type="button" onClick={copyId}>{copied ? <Check size={12}/> : <Copy size={12}/>}</button></div>
          <div><span>开始时间</span><b>{displayTime(event.start_timestamp)}</b></div>
          <div><span>结束时间</span><b>{displayTime(event.end_timestamp)}</b></div>
          {selectedEvent?.receivedAt && <div><span>告警接收时间</span><b>{displayTime(selectedEvent.receivedAt)}</b></div>}
          <div><span>事件持续时间</span><b>{comms.duration}</b></div>
        </section>
        <div className="event-risk-note"><AlertTriangle size={14}/><span>告警级别表示事件聚合风险，不等于模型置信度。</span></div>

        <section className="event-detail-section event-risk-assessment">
          <h3>风险定级依据 <em>{event.severityPolicyVersion || '历史规则'}</em></h3>
          <p>{risk.reason || (event.severitySource === 'historical' ? '历史事件未保存完整模型证据，当前等级仅供人工复核。' : '该事件尚未保存结构化定级依据。')}</p>
          <div className="event-detail-facts"><span>最终等级<b>{severityLabels[severity]}</b></span><span>等级来源<b>{severitySourceLabels[event.severitySource] || '历史数据'}</b></span><span>定级状态<b>{severityStatusLabels[event.severityStatus] || '待确认'}</b></span><span>基础等级<b>{Number.isFinite(Number(risk.baseSeverity)) ? severityLabels[Number(risk.baseSeverity)] : '--'}</b></span><span>样本数量<b>{risk.sampleCount ?? evidence.sampleCount ?? details.length}</b></span><span>持续时间<b>{Number.isFinite(Number(risk.durationSeconds)) ? `${risk.durationSeconds} 秒` : comms.duration}</b></span></div>
          {!!risk.matchedRules?.length && <div className="event-rule-tags">{risk.matchedRules.map(rule => <span key={rule}>{rule}</span>)}</div>}
          <div className="event-risk-evidence-grid"><div><h4>已确认依据</h4>{risk.evidence?.length ? risk.evidence.map(item => <p key={item}><Check size={13}/>{item}</p>) : <p><AlertTriangle size={13}/>暂无额外升档证据</p>}</div><div><h4>缺失证据</h4>{risk.missingEvidence?.length ? risk.missingEvidence.map(item => <p key={item}><AlertTriangle size={13}/>{item}</p>) : <p><Check size={13}/>当前规则所需证据完整</p>}</div></div>
        </section>

        <section className="event-detail-section model-evidence sanxia-evidence">
          <h3>SANXIA 模型检测事实 <em>{unknown ? '未知攻击判定' : '已知类别判定'}</em></h3>
          <p><strong>模型标签：</strong>{unknown ? '未知攻击（具体类型待人工确认）' : event.attackLabel || event.eventType || '未记录'}。模型分数只表示检测判定，不代表物理影响已经确认。</p>
          <div className="event-detail-facts">
            <span>匹配数据包<b>{evidence.sampleCount ?? details.length}</b></span><span>运行批次<b>{event.pipelineRunId || '未记录'}</b></span><span>关联资产<b>{components.join('、') || '未绑定资产信息'}</b></span><span>跳过数据包<b>{evidence.skippedPackets ?? '未记录'}</b></span>
            {unknown ? <><span>未知分数（平均）<b>{percent(evidence.unknownScore?.average)}</b></span><span>未知分数（最高）<b>{percent(evidence.unknownScore?.max)}</b></span><span>判定阈值<b>{percent(evidence.unknownScore?.threshold)}</b></span><span>超阈值包数<b>{evidence.unknownScore?.aboveThresholdCount ?? '未记录'}</b></span></> : <><span>平均置信度<b>{percent(evidence.knownConfidence?.average)}</b></span><span>最低置信度<b>{percent(evidence.knownConfidence?.min)}</b></span><span>最高置信度<b>{percent(evidence.knownConfidence?.max)}</b></span><span>置信度范围<b>{evidence.knownConfidence ? `${percent(evidence.knownConfidence.min)}—${percent(evidence.knownConfidence.max)}` : '未记录'}</b></span></>}
          </div>
          {unknown && evidence.unknownScore && <EvidenceMeter value={evidence.unknownScore.max} threshold={evidence.unknownScore.threshold} label="最高未知分数"/>}
          {!unknown && evidence.knownConfidence && <EvidenceMeter value={evidence.knownConfidence.average} label="平均置信度"/>}
          {((unknown && !evidence.unknownScore) || (!unknown && !evidence.knownConfidence)) && <div className="event-evidence-missing">该历史事件未保存模型分数，仅保留检测标签和通信记录。</div>}
        </section>

        <section className="event-detail-section communication-scope">
          <h3>通信范围 <em>{details.length} 条</em></h3>
          <div className="event-detail-facts"><span>匹配包数<b>{evidence.sampleCount ?? details.length}</b></span><span>源地址数量<b>{comms.sources}</b></span><span>目标地址数量<b>{comms.targets}</b></span><span>持续时间<b>{comms.duration}</b></span></div>
          <div className="event-route-ranking">{comms.routes.map(([route, count]) => <div key={route}><b>{route}</b><span>{count} 包</span></div>)}</div>
          {!!representativeDetails.length && <div className="event-representative-list"><h4>代表性通信记录</h4>{representativeDetails.map((item, index) => <div key={(item.timestamp || 'sample') + index}><span>#{String(index + 1).padStart(2, '0')}</span><b>{item.source_ip || item.source || '未记录'} → {item.destination_ip || item.target || '未记录'}</b><time>{displayTime(item.timestamp)}</time></div>)}</div>}
          <details className="event-collapsible"><summary>查看通信明细 <em>{details.length} 条</em></summary>{details.length ? <div className="event-communication-list">{details.map((item, index) => <div key={(item.timestamp || 'detail') + index}><span>#{String(index + 1).padStart(2, '0')}</span><time>{displayTime(item.timestamp)}</time><b>{item.source_ip || item.source || '未知源'} → {item.destination_ip || item.target || '未知目标'}</b><small>{item.component || item.target || '未标注组件'}</small></div>)}</div> : <p>该事件没有可展示的通信明细。</p>}</details>
        </section>

        <section className="event-detail-section judgement-summary">
          <button type="button" className="event-judgement-regenerate" onClick={onRegenerate}><RefreshCw size={13}/>重新生成规则研判</button>
          <h3>规则辅助研判 <em className={mapped ? 'source-rule' : 'source-manual'}>{mapped ? '规则推测' : '待人工确认'}</em></h3>
          <p>{mapped ? judgement.cause || judgement.attackInfo?.description || '暂无规则化研判摘要' : '当前事件未匹配已有攻击—故障规则，需要结合设备日志、同期流量和现场状态人工确认。'}</p>
          <div className="event-detail-facts"><span>攻击类型映射<b>{mapped ? judgement.attackInfo?.name || judgement.label : '未匹配'}</b></span><span>风险参考<b>{mapped ? severityNames[judgement.attackInfo?.severity] || '待确认' : '待人工确认'}</b></span><span>源地址<b>{primarySource}</b></span><span>目标地址<b>{primaryTarget}</b></span></div>
        </section>

        <section className="event-detail-section">
          <h3>影响与历史关联 <em>{mapped ? '规则推测' : '人工确认'}</em></h3>
          {mapped ? <><p><strong>影响子系统（规则推测）：</strong>{judgement.affectedSubsystem || '暂无法确认'}</p><p><strong>可能物理后果（规则推测）：</strong>{judgement.physicalConsequence || '暂无法确认'}</p></> : <div className="event-unverified-impact"><AlertTriangle size={17}/><span>当前事件未匹配攻击—故障规则，暂无法确认受影响子系统和物理后果，请勿将告警等级解释为已确认的设备影响。</span></div>}
          <div className={'event-history-status ' + (faultHistory?.matched ? 'matched' : '')}><b>{faultHistory?.matched ? '已匹配历史故障' : '未匹配历史故障'}</b><span>{faultHistory?.matched ? `共 ${faultHistory.totalMatchingRecords || 0} 条记录，${faultHistory.uniqueFaultModes || 0} 种故障模式` : faultHistory?.reason || '暂无历史匹配信息'}</span></div>
          {(faultHistory?.topFaults || []).slice(0, 3).map((fault, index) => <div className="event-history-fault" key={(fault.fault_mode || 'fault') + index}><b><em>历史关联</em>{fault.fault_mode || '未知故障模式'}</b><span>{fault.typical_response || '暂无典型处置措施'}</span></div>)}
        </section>

        <section className="event-detail-section">
          <h3>预防与处置建议 <em>规则建议</em></h3>
          {recommendations.length ? <div className="event-recommendation-groups">{['立即处置', '设备核验', '持续观察'].map(group => recommendationGroups[group]?.length ? <div key={group}><h4>{group}</h4><div className="event-recommendation-list">{recommendationGroups[group].slice(0, 3).map((item, index) => <div key={(item.action || 'recommendation') + index}><span>{item.source === 'historical' ? '历史措施' : item.priority || '规则建议'}</span><p>{item.action}</p><small>{item.domain || '安全运营'}</small></div>)}</div>{recommendationGroups[group].length > 3 && <details className="event-collapsible"><summary>更多{group}建议 <em>{recommendationGroups[group].length - 3} 条</em></summary><div className="event-recommendation-list">{recommendationGroups[group].slice(3).map((item, index) => <div key={(item.action || 'recommendation-more') + index}><span>{item.source === 'historical' ? '历史措施' : item.priority || '规则建议'}</span><p>{item.action}</p><small>{item.domain || '安全运营'}</small></div>)}</div></details>}</div> : null)}</div> : <p>暂无规则化建议，请转人工研判。</p>}
        </section>

        <section className="event-detail-section disposition-history"><h3>处置时间线 <em>{event.dispositionHistory?.length || 0} 条</em></h3>{event.dispositionHistory?.length ? [...event.dispositionHistory].reverse().map((item, index) => <div className="disposition-history-item" key={(item.createdAt || 'history') + index}><i/><div><b>{item.actorName || '未知用户'} · {dispositionLabels[item.fromStatus] || item.fromStatus} → {dispositionLabels[item.toStatus] || item.toStatus}</b><time>{displayTime(item.createdAt)}</time>{item.confirmedAttackType && <small>人工确认：{item.confirmedAttackType}</small>}{item.actualImpact && <small>实际影响：{item.actualImpact}</small>}<p>{item.note || item.conclusion || '未填写备注'}</p></div></div>) : <p>尚无人工处置记录。</p>}</section>

        <form className="event-disposition-form" onSubmit={submitDisposition}><h3>人工结论与处置 <em>人工确认</em></h3><div className="event-disposition-fields"><label>处置状态<select value={form.status} disabled={finalLocked} onChange={change => setForm(current => ({ ...current, status: change.target.value }))}>{allowedStatuses.map(status => <option key={status} value={status}>{dispositionLabels[status]}</option>)}</select></label><label>负责人<input value={form.assignee} readOnly={!isAdmin} placeholder={user?.username || '当前用户'} onChange={change => setForm(current => ({ ...current, assignee: change.target.value }))}/></label>{isAdmin && <><label>人工确认等级<select value={form.eventSeverity} onChange={change => { setManualSeverityTouched(true); setForm(current => ({ ...current, eventSeverity: Number(change.target.value), severityLocked: true })) }}>{severityLabels.map((label, index) => <option value={index} key={label}>{label}</option>)}</select></label><label className="event-severity-lock"><span>锁定人工等级</span><input type="checkbox" checked={form.severityLocked} onChange={change => { setManualSeverityTouched(true); setForm(current => ({ ...current, severityLocked: change.target.checked })) }}/></label></>}<label className="wide">人工确认攻击类型<input value={form.confirmedAttackType} maxLength={160} placeholder="例如：授权扫描、未知异常、寄存器写入攻击" onChange={change => setForm(current => ({ ...current, confirmedAttackType: change.target.value }))}/></label><label className="wide">实际影响<textarea value={form.actualImpact} maxLength={2000} placeholder="记录经设备日志或现场核验确认的实际影响；未确认时保持为空" onChange={change => setForm(current => ({ ...current, actualImpact: change.target.value }))}/></label><label className="wide">人工结论<textarea value={form.conclusion} maxLength={2000} placeholder="记录已核验的攻击性质和最终结论" onChange={change => setForm(current => ({ ...current, conclusion: change.target.value }))}/></label><label className="wide">本次备注<textarea value={form.note} maxLength={2000} placeholder="记录本次操作、核验依据或后续计划" onChange={change => setForm(current => ({ ...current, note: change.target.value }))}/></label></div>{saveError && <p className="event-disposition-error">{saveError}</p>}<button type="submit" disabled={saving}><Save size={14}/>{saving ? '正在保存…' : '保存处置记录'}</button></form>
      </div>}
    </aside>
  </>
}
function WlanStatus({ pipeline, sourceState, connected, user }) {
  const sampling = pipeline?.sampling || {}
  const interfaces = sourceState?.interfaces || []
  const selectedInterface = sourceState?.selectedInterface || ''
  const simulated = sampling.source === 'replay'
  const currentName = simulated
    ? sampling.sourceFileName || 'PCAP 回放文件'
    : sampling.interfaceName || interfaces.find(item => item.deviceId === selectedInterface)?.name || '未选择网卡'
  const isRunning = Boolean(pipeline?.running)
  const status = user?.demo ? 'DEMO' : simulated ? isRunning ? (sampling.running ? '正在回放' : '正在推理') : 'SIMULATED' : isRunning ? (sampling.running ? '正在采集' : '正在推理') : '未启动'
  const statusClass = user?.demo ? 'demo' : simulated ? 'simulated' : isRunning ? 'running' : 'idle'
  return <div className="wlan-monitor-strip event-channel-inline">
    <div className="wlan-monitor-title"><div className="wlan-monitor-icon"><Wifi size={18}/></div><div><b>实时数据通道</b><small>{user?.demo ? '演示数据' : simulated ? '模拟 WLAN · PCAP 回放' : sampling.source === 'interface' ? 'WLAN 网卡采集' : sampling.source === 'pcap' ? 'PCAP 回放' : '文件检测'}</small></div><span className={`wlan-status ${statusClass}`}><i/>{status}</span></div>
    <div className="wlan-readonly-fact"><span>{simulated ? '回放文件' : '网卡'}</span><b>{user?.demo ? 'DEMO WLAN' : currentName}</b></div>
    <div className="wlan-readonly-fact"><span>推理引擎</span><b>SANXIA 实时检测</b></div>
    <div className="wlan-monitor-metrics"><span><b>{pipeline?.processedSamples ?? 0}</b><small>已处理流量</small></span><span className="attack"><b>{pipeline?.attackSamples ?? 0}</b><small>攻击样本</small></span><span><b>{pipeline?.runtimeAlerts ?? 0}</b><small>实时告警</small></span><span><b>{pipeline?.eventsCreated ?? 0}</b><small>新增归档</small></span><span><b>{pipeline?.duplicateAlerts ?? 0}</b><small>去重告警</small></span></div>
    <div className="wlan-readonly-connection"><i className={connected ? 'connected' : ''}/><span>SSE {connected ? '已连接' : user?.demo ? '演示模式' : '未连接'}</span></div>
  </div>
}

export default function EventCenterScreen({ user, onNavigate, onLogout }) {
  const [data, setData] = useState({ events: demoEvents, total: demoEvents.length, summary: { total: demoEvents.length, bySeverity: {} } })
  const [live, setLive] = useState(false)
  const [streamEvents, setStreamEvents] = useState([])
  const [runtimeAlerts, setRuntimeAlerts] = useState([])
  const [runtimeAlertPage, setRuntimeAlertPage] = useState({ total: 0, returned: 0 })
  const [connected, setConnected] = useState(false)
  const [filter, setFilter] = useState('全部')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [eventDetail, setEventDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const detailRequest = useRef(0)
  const [pipeline, setPipeline] = useState(null)
  const [sourceState, setSourceState] = useState({ sources: [], interfaces: [] })
  const [highlightIds, setHighlightIds] = useState(() => new Set())
  const [archivePage, setArchivePage] = useState(1)
  const [archiveData, setArchiveData] = useState({ events: demoEvents.slice(0, ARCHIVE_PAGE_SIZE), total: demoEvents.length })
  const [archiveLoading, setArchiveLoading] = useState(false)
  const [archiveError, setArchiveError] = useState('')
  const archivePageRef = useRef(archivePage)
  const runtimeRunRef = useRef(null)
  const sourceContextRef = useRef(null)
  const highlightTimersRef = useRef(new Map())

  const clearHighlights = () => {
    highlightTimersRef.current.forEach(timer => window.clearTimeout(timer))
    highlightTimersRef.current.clear()
    setHighlightIds(new Set())
  }

  const cancelHighlightTimers = () => {
    highlightTimersRef.current.forEach(timer => window.clearTimeout(timer))
    highlightTimersRef.current.clear()
  }

  const highlightAlert = alert => {
    const id = String(`runtime:${alert?.alertId || ''}`)
    if (id === 'runtime:') return
    const previous = highlightTimersRef.current.get(id)
    if (previous) window.clearTimeout(previous)
    setHighlightIds(current => new Set(current).add(id))
    const timer = window.setTimeout(() => {
      highlightTimersRef.current.delete(id)
      setHighlightIds(current => {
        const next = new Set(current)
        next.delete(id)
        return next
      })
    }, 6000)
    highlightTimersRef.current.set(id, timer)
  }

  useEffect(() => { archivePageRef.current = archivePage }, [archivePage])

  useEffect(() => {
    if (user.demo) return undefined
    let active = true
    const refreshEvents = () => api.events(1, 30).then(value => { if (active) { setData(value); setLive(true) } }).catch(() => {})
    refreshEvents()
    const refreshTimer = window.setInterval(refreshEvents, 5000)
    const close = stream('/api/v1/events/stream', event => {
      if (!event || !isSanxiaEvent(event)) return
      setStreamEvents(current => [event, ...current].slice(0, 20))
      setArchiveData(current => {
        const exists = (current.events || []).some(item => item._id && item._id === event._id)
        const total = exists ? current.total : Number(current.total || 0) + 1
        if (archivePageRef.current !== 1) return { ...current, total }
        const events = [event, ...(current.events || []).filter(item => !event._id || item._id !== event._id)].slice(0, ARCHIVE_PAGE_SIZE)
        return { ...current, events, total }
      })
    }, () => setConnected(false), () => setConnected(true))
    const closeAlerts = stream('/api/v1/pipeline/alerts/stream', alert => {
      if (!alert || !runtimeRunRef.current || alert.runId !== runtimeRunRef.current) return
      setRuntimeAlerts(current => mergeRuntimeAlerts(current, [alert]))
      highlightAlert(alert)
    })
    return () => { active = false; window.clearInterval(refreshTimer); close?.(); closeAlerts?.(); cancelHighlightTimers() }
  }, [user.demo])

  useEffect(() => {
    if (user.demo) {
      const start = (archivePage - 1) * ARCHIVE_PAGE_SIZE
      setArchiveData({ events: demoEvents.slice(start, start + ARCHIVE_PAGE_SIZE), total: demoEvents.length })
      return undefined
    }
    let active = true
    const refreshArchive = async () => {
      setArchiveLoading(true)
      try {
        const value = await api.events(archivePage, ARCHIVE_PAGE_SIZE)
        if (active) { setArchiveData(value); setArchiveError('') }
      } catch (reason) {
        if (active) setArchiveError(reason?.message || '历史事件档案加载失败')
      } finally {
        if (active) setArchiveLoading(false)
      }
    }
    refreshArchive()
    const timer = window.setInterval(refreshArchive, 5000)
    return () => { active = false; window.clearInterval(timer) }
  }, [user.demo, archivePage])

  const refreshPipeline = async () => {
    if (user.demo) return
    try {
      const [nextPipeline, nextSources] = await Promise.all([api.pipelineStatus(), api.pipelineSources()])
      const nextRunId = nextPipeline?.runId || null
      const nextContextId = nextPipeline?.sourceContextId || null
      const contextChanged = sourceContextRef.current !== null && sourceContextRef.current !== nextContextId
      if (contextChanged || runtimeRunRef.current !== nextRunId) {
        sourceContextRef.current = nextContextId
        runtimeRunRef.current = nextRunId
        setRuntimeAlerts([])
        setRuntimeAlertPage({ total: 0, returned: 0 })
        clearHighlights()
        if (contextChanged) {
          detailRequest.current += 1
          setSelectedEvent(null)
          setEventDetail(null)
          setDetailLoading(false)
          setDetailError('')
        }
      } else {
        sourceContextRef.current = nextContextId
      }
      setPipeline(nextPipeline)
      setSourceState(nextSources)
      if (nextRunId) {
        const alertPage = await api.pipelineAlertPage(nextRunId, 200)
        if (runtimeRunRef.current === nextRunId) {
          setRuntimeAlerts(current => mergeRuntimeAlerts(current, alertPage.items))
          setRuntimeAlertPage({ total: alertPage.total, returned: alertPage.returned })
        }
      }
    } catch { /* status-only panel tolerates an offline pipeline */ }
  }

  useEffect(() => {
    if (user.demo) return undefined
    refreshPipeline()
    const timer = window.setInterval(refreshPipeline, 3000)
    return () => window.clearInterval(timer)
  }, [user.demo])


  const closeEventDetail = () => {
    detailRequest.current += 1
    setSelectedEvent(null)
    setEventDetail(null)
    setDetailLoading(false)
    setDetailError('')
  }

  useEffect(() => {
    if (!selectedEvent) return undefined
    const onKeyDown = event => { if (event.key === 'Escape') closeEventDetail() }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [selectedEvent])

  const openEventDetail = async event => {
    if (!isSanxiaEvent(event)) return
    const requestId = detailRequest.current + 1
    detailRequest.current = requestId
    setSelectedEvent(event)
    setEventDetail(null)
    setDetailError('')
    setDetailLoading(true)
    try {
      const result = user.demo ? buildDemoEventDetail(event) : await api.eventDetail(event._id)
      if (detailRequest.current === requestId) setEventDetail(result)
    } catch (reason) {
      if (detailRequest.current === requestId) setDetailError(reason?.message || '无法加载该告警的详情与研判内容')
    } finally {
      if (detailRequest.current === requestId) setDetailLoading(false)
    }
  }
  const regenerateEventJudgement = async () => {
    if (!selectedEvent || user.demo) return openEventDetail(selectedEvent)
    setDetailLoading(true); setDetailError('')
    try { const judgement = await api.regenerateEventJudgement(selectedEvent._id); setEventDetail(current => ({ event: current?.event || selectedEvent, judgement })) }
    catch (reason) { setDetailError(reason?.message || '重新生成研判失败') } finally { setDetailLoading(false) }
  }
  const updateEventDisposition = async changes => {
    if (!selectedEvent) return
    const result = user.demo
      ? {
          ...(eventDetail || buildDemoEventDetail(selectedEvent)),
          event: {
            ...(eventDetail?.event || selectedEvent),
            disposition: { status: changes.status, assignee: changes.assignee || user.username || 'demo', confirmedAttackType: changes.confirmedAttackType, actualImpact: changes.actualImpact, conclusion: changes.conclusion, updatedAt: new Date().toISOString(), updatedBy: user.username || 'demo' },
            dispositionHistory: [...(eventDetail?.event?.dispositionHistory || []), { fromStatus: eventDetail?.event?.disposition?.status || 'pending', toStatus: changes.status, assignee: changes.assignee || user.username || 'demo', confirmedAttackType: changes.confirmedAttackType, actualImpact: changes.actualImpact, conclusion: changes.conclusion, note: changes.note, actorName: user.username || 'demo', createdAt: new Date().toISOString() }],
          },
        }
      : await api.updateEventDisposition(selectedEvent._id, changes)
    setEventDetail(result)
    setSelectedEvent(result.event)
    const replace = current => ({ ...current, events: (current.events || []).map(item => item._id === result.event._id ? result.event : item) })
    setData(replace)
    setArchiveData(replace)
    setStreamEvents(current => current.map(item => item._id === result.event._id ? result.event : item))
  }

  const all = useMemo(() => {
    const merged = new Map()
    const rows = [...runtimeAlerts.map(runtimeAlertEvent), ...streamEvents, ...(data.events || [])].filter(isSanxiaEvent)
    rows.forEach((event, index) => {
      const key = String(event._id || event.runtimeAlertId || index)
      const current = merged.get(key)
      if (!current) merged.set(key, event)
      else if (event.archiveStatus) merged.set(key, { ...current, archiveStatus: event.archiveStatus, runtimeAlertId: event.runtimeAlertId })
    })
    return [...merged.values()]
  }, [streamEvents, data.events, runtimeAlerts])
  const currentRunEvents = useMemo(() => user.demo
    ? (data.events || []).filter(isSanxiaEvent)
    : (runtimeRunRef.current ? runtimeAlerts : [])
      .filter(alert => alert.runId === runtimeRunRef.current)
      .map(runtimeAlertEvent), [user.demo, data.events, runtimeAlerts])
  const queue = currentRunEvents.filter(event => filter === '全部' || severityLabels[event.eventSeverity] === filter)
  const archiveLinkCounts = useMemo(() => currentRunEvents.reduce((counts, event) => {
    if (event.formalEventId) counts.set(event.formalEventId, Number(counts.get(event.formalEventId) || 0) + 1)
    return counts
  }, new Map()), [currentRunEvents])
  const runtimeAlertTotal = user.demo ? currentRunEvents.length : Math.max(Number(runtimeAlertPage.total || 0), Number(pipeline?.runtimeAlerts || 0), currentRunEvents.length)
  const queueBadge = filter !== '全部'
    ? `${filter} ${queue.length} / 本轮 ${runtimeAlertTotal}`
    : currentRunEvents.length < runtimeAlertTotal
      ? `最近 ${currentRunEvents.length} / 共 ${runtimeAlertTotal}`
      : `本轮 ${runtimeAlertTotal} 条`
  const archiveEvents = (archiveData.events || []).filter(isSanxiaEvent)
  const archiveTotal = Number(archiveData.total || 0)
  const archivePageCount = Math.max(1, Math.ceil(archiveTotal / ARCHIVE_PAGE_SIZE))
  const safeArchivePage = Math.min(archivePage, archivePageCount)
  const archivePageNumbers = useMemo(() => {
    const start = Math.max(1, Math.min(safeArchivePage - 2, archivePageCount - 4))
    return Array.from({ length: Math.min(5, archivePageCount) }, (_, index) => start + index)
  }, [safeArchivePage, archivePageCount])
  useEffect(() => {
    if (archivePage > archivePageCount) setArchivePage(archivePageCount)
  }, [archivePage, archivePageCount])
  const targets = useMemo(() => Object.entries(all.reduce((map, event) => {
    const detail = event.detail?.[0] || {}
    const target = detail.target || detail.destination_ip || detail.destinationIp || detail.component || event.target || event.destinationIp || '未知目标'
    map[target] = (map[target] || 0) + 1
    return map
  }, {})).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value), [all])
  const trend = [...all].reverse().slice(-12).map((event, index) => ({ time: String(event.start_timestamp || index).split(' ').pop()?.slice(0, 5), 风险级别: 4 - Math.min(3, Math.max(0, Number(event.eventSeverity))) }))
  const pipelineView = user.demo ? { running: false, insertedSamples: 0, batchesProcessed: 0, sampling: { source: 'interface', capturedSamples: 0, bufferedSamples: 0 } } : pipeline
  const defaultEventSource = user.demo ? 'DEMO' : sourceLabels[pipelineView?.sampling?.source] || '未知来源'

  return <BigScreenShell page="events" pageTitle="事件中心" subtitle="实时事件流、风险走势与历史档案" live={live || connected} user={user} onNavigate={onNavigate} onLogout={onLogout}>
    <div className="screen-page screen-page-events event-center-page">
      <div className="event-center-grid">
        <ScreenPanel title="告警级别分布" icon={Gauge} badge="SANXIA EVENT" className="event-severity-panel"><div className="donut-with-legend"><SeverityDonut events={all} summary={data.summary}/><div className="screen-legend">{severityLabels.map((label, index) => <div key={label}><i style={{ background: severityColors[index] }}/><span>{label}</span><b>{Number(data.summary?.bySeverity?.[index] ?? all.filter(item => item.eventSeverity === index).length)}</b></div>)}</div></div></ScreenPanel>
        <ScreenPanel title="事件风险走势" icon={Activity} badge="LATEST" className="event-risk-trend"><ResponsiveContainer width="100%" height="100%"><LineChart data={trend} margin={{ top: 14, right: 14, left: -18, bottom: 0 }}><CartesianGrid stroke="#164b7c" strokeDasharray="2 3" vertical={false}/><XAxis dataKey="time" tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis domain={[0, 4]} tick={{ fill: '#8db9d4', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={CHART_TOOLTIP}/><Line type="monotone" dataKey="风险级别" stroke="#ff565f" strokeWidth={2.6} dot={{ r: 3, fill: '#ff565f', stroke: '#ffd0d4' }}/></LineChart></ResponsiveContainer></ScreenPanel>
        <ScreenPanel title="受影响目标排行" icon={Network} badge="TOP TARGET" className="event-target-ranking"><ResponsiveContainer width="100%" height="100%"><BarChart data={targets.slice(0, 6)} layout="vertical" margin={{ top: 10, right: 32, left: 6, bottom: 6 }} barCategoryGap="22%"><CartesianGrid stroke="rgba(38,124,183,.28)" strokeDasharray="3 8" horizontal={false}/><XAxis type="number" allowDecimals={false} tick={{ fill: '#789fbd', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis type="category" dataKey="name" width={142} interval={0} tickMargin={8} tick={{ fill: '#c2e4f3', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={CHART_TOOLTIP}/><Bar dataKey="value" fill="#19d3ff" maxBarSize={24} radius={[0, 10, 10, 0]}/></BarChart></ResponsiveContainer></ScreenPanel>
        <ScreenPanel title="本轮实时告警队列" icon={Bell} badge={queueBadge} className="event-queue" action={<div className="screen-segmented">{['全部', '严重', '高危', '中危', '低危'].map(item => <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)}>{item}</button>)}</div>}><div className="screen-event-queue-layout"><WlanStatus pipeline={pipelineView} sourceState={sourceState} connected={connected} user={user}/><div className="event-queue-scope-note">本轮队列为即时告警；历史事件档案为累计正式事件，多条告警可能聚合为同一事件。</div><CompactEventList events={queue} highlightIds={highlightIds} defaultSource={defaultEventSource} archiveLinkCounts={archiveLinkCounts} onOpen={openEventDetail}/></div></ScreenPanel>
        <ScreenPanel title="历史事件档案" icon={ShieldCheck} badge={`共 ${archiveTotal} 条`} className="screen-table-panel event-archive-table">
          <div className="screen-table-scroll"><table><thead><tr><th>级别</th><th>事件类型</th><th>开始时间</th><th>结束时间</th><th>目标</th><th>操作</th></tr></thead><tbody>{archiveEvents.map((event, index) => <tr key={(event._id || 'event') + index}><td><span className={'screen-severity s' + event.eventSeverity}>{severityLabels[event.eventSeverity]}</span></td><td><b>{event.eventType}</b></td><td>{event.start_timestamp}</td><td>{event.end_timestamp}</td><td>{event.detail?.[0]?.target}</td><td><button type="button" className="table-action" onClick={() => openEventDetail(event)}>详情</button></td></tr>)}{!archiveEvents.length && <tr><td colSpan="6">{archiveLoading ? '正在加载历史事件…' : archiveError || '暂无历史事件'}</td></tr>}</tbody></table></div>
          <div className="screen-pagination"><span>{archiveError || `共 ${archiveTotal} 条 · 第 ${safeArchivePage}/${archivePageCount} 页`}</span><button type="button" disabled={safeArchivePage <= 1 || archiveLoading} onClick={() => setArchivePage(current => Math.max(1, current - 1))}>‹</button>{archivePageNumbers.map(number => <button type="button" key={number} className={number === safeArchivePage ? 'active' : ''} disabled={archiveLoading} onClick={() => setArchivePage(number)}>{number}</button>)}<button type="button" disabled={safeArchivePage >= archivePageCount || archiveLoading} onClick={() => setArchivePage(current => Math.min(archivePageCount, current + 1))}>›</button></div>
        </ScreenPanel>
      </div>
    </div>
    <EventDetailDrawer selectedEvent={selectedEvent} payload={eventDetail} loading={detailLoading} error={detailError} onClose={closeEventDetail} onRetry={() => openEventDetail(selectedEvent)} onRegenerate={regenerateEventJudgement} onDisposition={updateEventDisposition} user={user}/>
  </BigScreenShell>
}
