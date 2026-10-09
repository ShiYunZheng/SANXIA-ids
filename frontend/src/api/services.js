import { request } from './client'

export const api = {
  health: () => request('/api/v1/health'),
  login: credentials => request('/api/v1/auth/login', { method: 'POST', body: JSON.stringify(credentials) }),
  me: () => request('/api/v1/auth/me'),
  tokenCheck: () => request('/api/v1/auth/me'),
  userinfo: () => request('/api/v1/auth/me'),
  rights: async () => ({ rights: (await request('/api/v1/auth/me')).rights || {} }),
  users: role => request(`/api/v1/users${role === undefined ? '' : `?role=${role}`}`),
  createUser: user => request('/api/v1/users', { method: 'POST', body: JSON.stringify(user) }),
  updateUser: (id, changes) => request(`/api/v1/users/${id}`, { method: 'PATCH', body: JSON.stringify(changes) }),
  overview: () => request('/api/v1/dashboard/summary'),
  trend: (intervalMs, points = 12) => request(`/api/v1/dashboard/history?intervalMs=${intervalMs || 3600000}&points=${points}`),
  dashboardRealtime: (intervalMs, points = 12) => request(`/api/v1/dashboard/realtime?intervalMs=${intervalMs || 3600000}&points=${points}`),
  component: name => request(`/api/v1/dashboard/components/${encodeURIComponent(name)}`),
  records: async (page = 1, pageSize = 20, range = {}) => {
    const query = new URLSearchParams({ page, pageSize })
    if (range.startAt) query.set('startAt', range.startAt)
    if (range.endAt) query.set('endAt', range.endAt)
    const data = await request(`/api/v1/records?${query}`)
    return { records: data.items, attack_types: data.attackTypes, total: data.page.totalTotal, page: data.page }
  },
  events: async (page = 1, pageSize = 20, filters = {}) => {
    const query = new URLSearchParams({ page, pageSize })
    if (filters.pipelineRunId) query.set('pipelineRunId', filters.pipelineRunId)
    const data = await request(`/api/v1/events?${query}`)
    return { events: data.items, total: data.page.totalTotal, summary: data.summary || { total: data.page.totalTotal, bySeverity: {} }, page: data.page }
  },
  eventDetail: eventId => request('/api/v1/events/' + encodeURIComponent(eventId)),
  updateEventDisposition: (eventId, disposition) => request('/api/v1/events/' + encodeURIComponent(eventId) + '/disposition', { method: 'PATCH', body: JSON.stringify(disposition) }),
  regenerateEventJudgement: eventId => request('/api/v1/events/' + encodeURIComponent(eventId) + '/judgement', { method: 'POST' }),
  eventJudgements: async (limit = 5) => {
    const data = await request(`/api/v1/events/judgements?limit=${limit}`)
    return data.items || []
  },
  detect: file => {
    const body = new FormData()
    body.append('file', file)
    return request('/api/v1/detections', { method: 'POST', body, timeout: 120000 })
  },
  validationCompare: file => {
    const body = new FormData()
    body.append('file', file)
    return request('/api/v1/validation/compare', { method: 'POST', body, timeout: 300000 })
  },
  validationAssociation: (window, force = false) => request('/api/v1/validation/association', { method: 'POST', body: JSON.stringify({ window, force }), timeout: 30000 }),
  inferenceEngines: () => request('/api/v1/inference/engines'),
  inferenceJobs: async (page = 1, pageSize = 20) => {
    const data = await request('/api/v1/inference/jobs?page=' + page + '&pageSize=' + pageSize)
    return { jobs: data.items || [], page: data.page, total: data.page?.totalTotal || 0 }
  },
  createInferenceJob: (file, engine = 'auto') => {
    const body = new FormData()
    body.append('file', file)
    body.append('engine', engine)
    return request('/api/v1/inference/jobs', { method: 'POST', body, timeout: 180000 })
  },
  inferenceResults: async (jobId, filters = {}, page = 1, pageSize = 80) => {
    const query = new URLSearchParams({ page, pageSize })
    Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value) })
    const data = await request('/api/v1/inference/jobs/' + jobId + '/results?' + query)
    return { results: data.items || [], page: data.page, total: data.page?.totalTotal || 0 }
  },
  associateInferenceResult: resultId => request('/api/v1/inference/results/' + resultId + '/association', { method: 'POST' }),  metrics: () => request('/api/v1/detections/metrics'),
  pipelineStatus: () => request('/api/v1/pipeline'),
  pipelineAlertPage: async (runId, limit = 100) => {
    const query = new URLSearchParams({ limit })
    if (runId) query.set('runId', runId)
    const data = await request('/api/v1/pipeline/alerts?' + query)
    const items = data.items || []
    return { items, total: Number(data.total ?? items.length), returned: Number(data.returned ?? items.length), runId: data.runId || runId || null }
  },
  pipelineAlerts: async (runId, limit = 100) => (await api.pipelineAlertPage(runId, limit)).items,
  realtimeModbusWindows: async (limit = 5) => {
    const data = await request('/api/v1/pipeline/modbus/windows?limit=' + limit)
    return data.items || []
  },
  pipelineSources: () => request('/api/v1/pipeline/sources'),
  pipelineStart: (options = {}) => request('/api/v1/pipeline/start', { method: 'POST', body: JSON.stringify(options) }),
  pipelineStop: () => request('/api/v1/pipeline/stop', { method: 'POST' }),
  pipelineSource: (source, options = {}) => request('/api/v1/pipeline/source', { method: 'POST', body: JSON.stringify({ source, ...options }) }),
  pipelinePcap: (file, source = 'pcap', options = {}) => {
    const body = new FormData()
    body.append('file', file)
    body.append('source', source)
    if (options.machineName) body.append('machineName', options.machineName)
    return request('/api/v1/pipeline/pcap', { method: 'POST', body, timeout: 120000 })
  },
  samples: () => request('/api/v1/sampling/samples'),
  attackSamples: () => request('/api/v1/attack/samples'),
}
