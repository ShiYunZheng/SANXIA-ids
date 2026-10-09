import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/services'

const DB_NAME = 'sanxia-ui-cache'
const DB_VERSION = 1
const STORE_NAME = 'detectionSessions'
const SESSION_ID_KEY = 'sg_detection_session_id'
const RECORD_VERSION = 1
const MAX_AGE_MS = 24 * 60 * 60 * 1000

const initialState = {
  report: null,
  fileMeta: null,
  busy: false,
  runStartedAt: null,
  error: '',
  view: 'sanxia',
  resultFilter: 'all',
  associationCache: {},
  completedAt: null,
  hydrated: false,
  persistenceNotice: '',
}

const DetectionSessionContext = createContext(null)
let memorySessionId = null
const ownerKey = user => String(user?._id || user?.id || user?.username || (user?.demo ? 'demo' : 'anonymous'))

function currentSessionId() {
  try {
    let value = sessionStorage.getItem(SESSION_ID_KEY)
    if (!value) {
      value = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`
      sessionStorage.setItem(SESSION_ID_KEY, value)
    }
    memorySessionId = value
    return value
  } catch {
    memorySessionId ||= globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`
    return memorySessionId
  }
}

const uiKey = sessionId => `sg_detection_ui_${sessionId}`

function openDatabase() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error('IndexedDB unavailable'))
      return
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const database = request.result
      if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME, { keyPath: 'sessionId' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'))
  })
}

async function withStore(mode, action) {
  const database = await openDatabase()
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, mode)
      const store = transaction.objectStore(STORE_NAME)
      const request = action(store)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error || new Error('IndexedDB request failed'))
      transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed'))
    })
  } finally {
    database.close()
  }
}

const readRecord = sessionId => withStore('readonly', store => store.get(sessionId))
const writeRecord = record => withStore('readwrite', store => store.put(record))
const deleteRecord = sessionId => withStore('readwrite', store => store.delete(sessionId))

async function cleanupExpiredRecords() {
  const records = await withStore('readonly', store => store.getAll())
  const expired = records.filter(record => Date.now() - Number(record.savedAt || 0) > MAX_AGE_MS)
  await Promise.all(expired.map(record => deleteRecord(record.sessionId)))
}

function readUiState(sessionId) {
  try {
    const value = JSON.parse(sessionStorage.getItem(uiKey(sessionId)) || '{}')
    return {
      view: ['sanxia', 'standalone', 'diff'].includes(value.view) ? value.view : 'sanxia',
      resultFilter: ['all', 'abnormal', 'normal'].includes(value.resultFilter) ? value.resultFilter : 'all',
    }
  } catch {
    return { view: 'sanxia', resultFilter: 'all' }
  }
}

function writeUiState(sessionId, state) {
  try { sessionStorage.setItem(uiKey(sessionId), JSON.stringify({ view: state.view, resultFilter: state.resultFilter })) } catch { /* Memory state remains available. */ }
}

export async function clearCurrentDetectionSession() {
  let sessionId = memorySessionId
  try {
    sessionId = sessionStorage.getItem(SESSION_ID_KEY) || sessionId
    if (sessionId) sessionStorage.removeItem(uiKey(sessionId))
    sessionStorage.removeItem(SESSION_ID_KEY)
  } catch { /* Best-effort session cleanup. */ }
  memorySessionId = null
  if (!sessionId) return
  try { await deleteRecord(sessionId) } catch { /* Best-effort logout cleanup. */ }
}

export function DetectionSessionProvider({ user, children }) {
  const [state, setState] = useState(initialState)
  const [file, setFile] = useState(null)
  const sessionIdRef = useRef(null)
  const ownerRef = useRef(ownerKey(user))
  const busyRef = useRef(false)
  const activeRef = useRef(true)
  const clearPromiseRef = useRef(Promise.resolve())

  useEffect(() => {
    let active = true
    activeRef.current = true
    const sessionId = currentSessionId()
    const owner = ownerKey(user)
    sessionIdRef.current = sessionId
    ownerRef.current = owner
    setFile(null)
    busyRef.current = false
    setState({ ...initialState, ...readUiState(sessionId) })
    readRecord(sessionId).then(record => {
      if (!active) return
      const valid = record && record.version === RECORD_VERSION && record.owner === owner && Date.now() - Number(record.savedAt || 0) <= MAX_AGE_MS
      setState(current => valid ? {
        ...current,
        report: record.report || null,
        fileMeta: record.fileMeta || null,
        completedAt: record.completedAt || null,
        hydrated: true,
      } : { ...current, hydrated: true })
      if (record && !valid) void deleteRecord(sessionId).catch(() => {})
    }).catch(() => {
      if (active) setState(current => ({ ...current, hydrated: true, persistenceNotice: '浏览器缓存不可用，检测结果仅在当前页面会话保留，刷新后可能无法恢复。' }))
    })
    void cleanupExpiredRecords().catch(() => {})
    return () => { active = false; activeRef.current = false }
  }, [user])

  const updateField = useCallback((field, value) => {
    setState(current => {
      const nextValue = typeof value === 'function' ? value(current[field]) : value
      const next = { ...current, [field]: nextValue }
      if (field === 'view' || field === 'resultFilter') writeUiState(sessionIdRef.current || currentSessionId(), next)
      return next
    })
  }, [])

  const selectFile = useCallback((nextFile, { clearReport = true } = {}) => {
    setFile(nextFile)
    if (!clearReport) return
    const fileMeta = nextFile ? { name: nextFile.name, size: nextFile.size, type: nextFile.type || '' } : null
    setState(current => ({
      ...current,
      report: null,
      fileMeta,
      error: '',
      view: 'sanxia',
      resultFilter: 'all',
      associationCache: {},
      completedAt: null,
    }))
    const sessionId = sessionIdRef.current || currentSessionId()
    writeUiState(sessionId, { view: 'sanxia', resultFilter: 'all' })
    clearPromiseRef.current = deleteRecord(sessionId).catch(() => {
      setState(current => ({ ...current, persistenceNotice: '浏览器缓存不可用，检测结果仅在当前页面会话保留，刷新后可能无法恢复。' }))
    })
  }, [])

  const runDetection = useCallback(async () => {
    if (!file || busyRef.current) return null
    busyRef.current = true
    const startedAt = Date.now()
    setState(current => ({ ...current, busy: true, runStartedAt: startedAt, error: '' }))
    try {
      await clearPromiseRef.current
      const report = await api.validationCompare(file)
      if (!activeRef.current) return null
      const completedAt = new Date().toISOString()
      const fileMeta = { name: file.name, size: file.size, type: file.type || '' }
      busyRef.current = false
      setState(current => ({ ...current, report, fileMeta, busy: false, runStartedAt: null, completedAt, error: '' }))
      const sessionId = sessionIdRef.current || currentSessionId()
      try {
        await writeRecord({ sessionId, owner: ownerRef.current, version: RECORD_VERSION, report, fileMeta, completedAt, savedAt: Date.now() })
      } catch {
        setState(current => ({ ...current, persistenceNotice: '浏览器缓存不可用，检测结果仅在当前页面会话保留，刷新后可能无法恢复。' }))
      }
      return report
    } catch (reason) {
      if (!activeRef.current) return null
      busyRef.current = false
      setState(current => ({ ...current, busy: false, runStartedAt: null, error: reason?.message || '并行检测失败' }))
      return null
    }
  }, [file])

  const value = useMemo(() => ({
    ...state,
    file,
    selectFile,
    runDetection,
    setError: value => updateField('error', value),
    setView: value => updateField('view', value),
    setResultFilter: value => updateField('resultFilter', value),
    setAssociationCache: value => updateField('associationCache', value),
  }), [state, file, selectFile, runDetection, updateField])

  return <DetectionSessionContext.Provider value={value}>{children}</DetectionSessionContext.Provider>
}

export function useDetectionSession() {
  const value = useContext(DetectionSessionContext)
  if (!value) throw new Error('useDetectionSession must be used inside DetectionSessionProvider')
  return value
}