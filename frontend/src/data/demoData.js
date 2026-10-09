export const attackTypes = ['Normal', 'MITM', 'nmap扫描', 'SYN泛洪', 'msf-detect', '电机开关故障', '未知攻击']
export const components = ['监控主机', '以太网交换机', '数据服务器', '左阀门', '右阀门']
export const demoOverview = {
  list_data: components.map((name, i) => ({ name, Normal: 420 - i * 28, MITM: 18 + i * 4, 'nmap扫描': 32 + i * 7, 'SYN泛洪': 24 + i * 5, 'msf-detect': 8 + i * 3, '电机开关故障': 5 + i * 2, '未知攻击': 3 + i })),
  pie_data: attackTypes.map((name, i) => ({ name, total: [8661, 533, 8936, 2470, 10469, 9900, 0][i] })),
  percentage_data: { MITM: .2, 'nmap扫描': .3, 'SYN泛洪': .23, 'msf-detect': .13, '电机开关故障': .08, '未知攻击': .06 }
}
const demoTrendEnd = Date.now()
const demoTrendAttackTypes = ['Modbus模糊测试', '功能码读取攻击', '线圈读取攻击', '寄存器读取攻击', 'UID枚举攻击', '寄存器写入攻击', 'msf-detect', '功能码爆破', 'nmap扫描', 'ARP投毒', 'DDoS', 'DNS劫持', 'ICMP泛洪', 'MAC溢出', 'MITM', 'SYN泛洪', '电机开关故障', '未知攻击']
export const demoTrend = Array.from({ length: 6 }, (_, bucket) => ({
  time: new Date(demoTrendEnd - (5 - bucket) * 61 * 24 * 60 * 60 * 1000).toISOString(),
  ...Object.fromEntries(demoTrendAttackTypes.map((name, index) => [name, 2 + ((bucket * 3 + index * 5) % 22)])),
}))
export const demoEvents = [
  { _id: 'e1', eventType: '右阀门 SYN泛洪', eventSeverity: 0, start_timestamp: '2026-09-02 19:42:08', end_timestamp: '2026-09-02 19:42:21', detail: [{ timestamp: '19:42:08', target: '右阀门', source: '192.168.11.45' }] },
  { _id: 'e2', eventType: '数据服务器 nmap扫描', eventSeverity: 1, start_timestamp: '2026-09-02 19:38:17', end_timestamp: '2026-09-02 19:38:34', detail: [{ timestamp: '19:38:17', target: '数据服务器', source: '10.0.4.18' }] },
  { _id: 'e3', eventType: '以太网交换机 MITM', eventSeverity: 2, start_timestamp: '2026-09-02 19:31:02', end_timestamp: '2026-09-02 19:31:29', detail: [{ timestamp: '19:31:02', target: '以太网交换机', source: '172.16.0.22' }] },
  { _id: 'e4', eventType: '左阀门 电机开关故障', eventSeverity: 1, start_timestamp: '2026-09-02 19:26:43', end_timestamp: '2026-09-02 19:27:04', detail: [{ timestamp: '19:26:43', target: '左阀门', source: '192.168.11.70' }] }
]
export const demoRecords = Array.from({ length: 7 }, (_, i) => ({ timestamp: `2026-09-02 19:${String(42 - i * 3).padStart(2, '0')}:08`, total: 520 + i * 24, benign: 420 - i * 8, attack_total: 100 + i * 32, MITM: 10 + i, 'nmap扫描': 28 + i * 2, 'SYN泛洪': 22 + i * 3, 'msf-detect': 14, '电机开关故障': 8, '未知攻击': 4 }))
export const demoMetrics = [{ name: 'accuracy', value: .964 }, { name: 'precision', value: .942 }, { name: 'recall', value: .931 }, { name: 'f1', value: .936 }]
