import { useEffect, useLayoutEffect, useState } from 'react'
import { Bell, CircleUserRound, FileSearch, LayoutDashboard, LogOut, Shield, UserCog } from 'lucide-react'
import PipelineControl from './PipelineControl'
import './BigScreenShell.css'

export const SCREEN_NAV = [
  ['overview', '\u6001\u52bf\u603b\u89c8', LayoutDashboard],
  ['detect', '\u68c0\u6d4b\u63a8\u7406', FileSearch],
  ['events', '\u4e8b\u4ef6\u4e2d\u5fc3', Bell],
  ['settings', '\u7cfb\u7edf\u8bbe\u7f6e', UserCog],
]
export const CHART_TOOLTIP = { background: '#061b37', border: '1px solid #27bde8', borderRadius: 8, color: '#e8f8ff', fontSize: 14, padding: '10px 12px', boxShadow: '0 8px 24px rgba(0, 8, 28, .45)' }
export const SCREEN_COLORS = ['#19d3ff', '#2374ff', '#ff565f', '#ffae43', '#8a73ff', '#27d6a2', '#b7d7ff']
const SCREEN_WIDTH = 1920
const SCREEN_HEIGHT = 1080

export function ScreenPanel({ title, subtitle, icon: Icon, badge, className = '', children, action }) {
  return <section className={`bs-panel ${className}`}>
    <div className="bs-panel-head"><div>{Icon && <Icon size={15}/>}<span>{title}</span>{subtitle && <small>{subtitle}</small>}</div><div className="bs-panel-actions">{badge && <em>{badge}</em>}{action}</div></div>
    <div className="bs-panel-body">{children}</div><i className="bs-corner tl"/><i className="bs-corner br"/>
  </section>
}

export function ScreenKpi({ label, value, unit, icon: Icon, tone = 'cyan', note }) {
  return <div className={`screen-kpi ${tone}`}><div className="screen-kpi-icon"><Icon size={19}/></div><div><span>{label}</span><strong>{value}<small>{unit}</small></strong><em>{note}</em></div><i/></div>
}

export default function BigScreenShell({ page, pageTitle, subtitle, user, onNavigate, onLogout, live = false, children }) {
  const [now, setNow] = useState(new Date())
  const [scale, setScale] = useState({ x: 1, y: 1 })
  useEffect(() => { const timer = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(timer) }, [])
  useLayoutEffect(() => {
    const resize = () => setScale({ x: window.innerWidth / SCREEN_WIDTH, y: window.innerHeight / SCREEN_HEIGHT })
    resize()
    window.addEventListener('resize', resize)
    return () => window.removeEventListener('resize', resize)
  }, [])
  const demo = Boolean(user?.demo)
  return <div className="big-screen-viewport"><main className={`big-screen screen-${page}`} style={{ '--screen-scale-x': scale.x, '--screen-scale-y': scale.y }}>
    <header className="bs-header">
      <div className="bs-brand"><div><Shield size={25}/></div><span><b>中国三峡</b><small>CHINA THREE GORGES</small></span></div>
      <div className="bs-title"><i/><div><h1>三峡网络安全监控中心</h1><p>{pageTitle} · {subtitle}</p></div><i/></div>
      <div className="bs-header-right"><div className="bs-pipeline">{!demo && <PipelineControl/>}</div><div className="bs-clock"><span>{now.toLocaleDateString('zh-CN').replaceAll('/', '-')}</span><strong>{now.toLocaleTimeString('zh-CN', { hour12: false })}</strong></div><button onClick={onLogout}><CircleUserRound size={15}/>{user?.username}<LogOut size={13}/></button><em className={live ? 'live' : ''}>{demo ? 'DEMO 数据' : live ? '数据链路正常' : '数据服务检查中'}</em></div>
    </header>
    <section className="screen-stage">{children}</section>
    <footer className="bs-footer"><div className="bs-footer-note"><span className={live ? 'live' : ''}/>{demo ? '当前展示演示数据' : live ? '安全防护运行中 · 数据链路正常' : '实时数据连接检查中'}</div><nav>{SCREEN_NAV.map(([id, label, Icon]) => <button key={id} className={id === page ? 'active' : ''} onClick={() => onNavigate(id)}><Icon size={17}/><span>{label}</span></button>)}</nav><div className="bs-footer-meta">SECURITY OPERATIONS · V2.6.0</div></footer>
  </main></div>
}
