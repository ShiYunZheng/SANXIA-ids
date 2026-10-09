import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, ArrowRight, Eye, EyeOff, LockKeyhole, Shield, ShieldCheck, UserRound, Wifi } from 'lucide-react'
import { api } from './api/services'
import BigScreenOverview from './components/BigScreenOverview'
import { SettingsScreen } from './components/BigScreenPages'
import DetectInferenceScreen from './components/DetectInferenceScreen'
import EventCenterScreen from './components/EventCenterScreen'
import { clearCurrentDetectionSession, DetectionSessionProvider } from './state/DetectionSessionContext'
import './login.css'

const text = {
  appName: '\u4e09\u5ce1\u7f51\u7edc\u5b89\u5168\u76d1\u63a7\u4e2d\u5fc3',
  appDesc: '\u9762\u5411\u5de5\u4e1a\u63a7\u5236\u7f51\u7edc\u7684\u5b9e\u65f6\u6001\u52bf\u611f\u77e5\u4e0e\u653b\u51fb\u68c0\u6d4b\u5e73\u53f0',
  livePlatform: '\u5b9e\u65f6\u5b89\u5168\u8fd0\u8425\u5e73\u53f0',
  monitorCenter: '\u76d1\u63a7\u4e2d\u5fc3',
  auth: '\u8eab\u4efd\u9a8c\u8bc1 / AUTHENTICATION',
  welcome: '\u6b22\u8fce\u56de\u6765',
  loginHint: '\u767b\u5f55\u4ee5\u8bbf\u95ee\u5b89\u5168\u8fd0\u8425\u63a7\u5236\u53f0',
  username: '\u7528\u6237\u540d',
  password: '\u5bc6\u7801',
  usernamePlaceholder: '\u8f93\u5165\u7528\u6237\u540d',
  passwordPlaceholder: '\u8f93\u5165\u5bc6\u7801',
  hidePassword: '\u9690\u85cf\u5bc6\u7801',
  showPassword: '\u663e\u793a\u5bc6\u7801',
  checking: '\u6b63\u5728\u9a8c\u8bc1\u2026',
  login: '\u767b\u5f55\u63a7\u5236\u53f0',
  demo: '\u8fdb\u5165\u6f14\u793a\u6a21\u5f0f',
  demoUser: '\u6f14\u793a\u7528\u6237',
  authNote: '\u767b\u5f55\u51ed\u8bc1\u7531\u4e3b\u670d\u52a1 /api/v1/auth/login \u6821\u9a8c',
  backendDown: '\u670d\u52a1\u6682\u4e0d\u53ef\u7528\uff0c\u8bf7\u786e\u8ba4\u540e\u7aef\u5df2\u542f\u52a8',
  booting: '\u6b63\u5728\u9a8c\u8bc1\u5b89\u5168\u4f1a\u8bdd\u2026',
}

function Login({ onLogin }) {
  const [form, setForm] = useState({ username: '', password: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  const submit = async event => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const data = await api.login(form)
      localStorage.removeItem('sg_demo')
      localStorage.setItem('sg_token', data.accessToken)
      onLogin({ username: form.username, demo: false })
    } catch (reason) {
      setError(reason?.message || text.backendDown)
    } finally {
      setBusy(false)
    }
  }

  return <main className="login-shell">
    <div className="login-backdrop" aria-hidden="true"/>
    <section className="login-art"><div className="login-brand"><div className="brand-mark"><Shield size={22}/></div><div><b>{text.appName}</b><small>{text.appDesc}</small></div></div><div className="login-copy"><p className="eyebrow"><span className="live-dot"/>{text.livePlatform}</p><h1>{'\u4e09\u5ce1\u7f51\u7edc\u5b89\u5168'}<br/><span>{text.monitorCenter}</span></h1><p className="muted">{text.appDesc}</p><div className="signal-line"><i/><i/><i/><i/><i/><i/><i/><i/></div></div><div className="login-foot"><span><Wifi size={14}/> SECURE CHANNEL</span><span><Activity size={13}/> SYSTEM READY · v2.6.0</span></div></section>
    <form className="login-panel" onSubmit={submit}><div className="login-panel-head"><p className="eyebrow">{text.auth}</p><h2>{text.welcome}</h2><p className="muted">{text.loginHint}</p></div><label><span>{text.username} <em>USERNAME</em></span><div className="login-input"><UserRound size={16}/><input autoFocus value={form.username} onChange={event => setForm({ ...form, username: event.target.value })} placeholder={text.usernamePlaceholder} autoComplete="username"/></div></label><label><span>{text.password} <em>PASSWORD</em></span><div className="login-input"><LockKeyhole size={16}/><input type={showPassword ? 'text' : 'password'} value={form.password} onChange={event => setForm({ ...form, password: event.target.value })} placeholder={text.passwordPlaceholder} autoComplete="current-password"/><button type="button" className="password-toggle" aria-label={showPassword ? text.hidePassword : text.showPassword} onClick={() => setShowPassword(value => !value)}>{showPassword ? <EyeOff size={16}/> : <Eye size={16}/>}</button></div></label>{error && <div className="error-note"><AlertTriangle size={15}/>{error}</div>}<button className="primary full login-submit" disabled={busy}>{busy ? text.checking : text.login}<ArrowRight size={17}/></button><button type="button" className="ghost full login-demo" onClick={() => onLogin({ username: text.demoUser, demo: true })}>{text.demo}</button><small className="muted center login-note">{text.authNote}</small></form>
  </main>
}

export default function App() {
  const [user, setUser] = useState(null)
  const [booting, setBooting] = useState(true)
  const [page, setPage] = useState('overview')

  useEffect(() => {
    const demo = localStorage.getItem('sg_demo') === '1'
    if (demo) {
      setUser({ username: text.demoUser, demo: true })
      setBooting(false)
      return undefined
    }
    if (!localStorage.getItem('sg_token')) {
      setBooting(false)
      return undefined
    }
    api.tokenCheck().then(() => Promise.all([api.userinfo(), api.rights()])).then(([info, rights]) => setUser({ ...info, rights, demo: false })).catch(() => {
      localStorage.removeItem('sg_token')
      void clearCurrentDetectionSession()
      setUser(null)
    }).finally(() => setBooting(false))
    const expire = () => { void clearCurrentDetectionSession(); setUser(null); setBooting(false) }
    window.addEventListener('sg:token-expired', expire)
    return () => window.removeEventListener('sg:token-expired', expire)
  }, [])

  const login = nextUser => {
    if (nextUser.demo) localStorage.setItem('sg_demo', '1')
    setUser(nextUser)
  }
  const logout = () => {
    localStorage.removeItem('sg_token')
    localStorage.removeItem('sg_demo')
    void clearCurrentDetectionSession()
    setUser(null)
    setPage('overview')
  }

  if (booting) return <div className="boot-screen"><ShieldCheck size={30}/><span>{text.booting}</span></div>
  if (!user) return <Login onLogin={login}/>

  const props = { user, onNavigate: setPage, onLogout: logout }
  const screen = page === 'overview' ? <BigScreenOverview {...props}/>
    : page === 'detect' ? <DetectInferenceScreen {...props}/>
      : page === 'events' ? <EventCenterScreen {...props}/>
        : <SettingsScreen {...props}/>
  return <DetectionSessionProvider user={user}>{screen}</DetectionSessionProvider>
}