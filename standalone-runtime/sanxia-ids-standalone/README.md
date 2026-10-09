# SANXIA-IDS · 独立集成包

> 三峡工控安全检测平台（Modbus/TCP 攻击检测）
> 本包为**解压即用**的最小集，可直接嵌入其他平台。

---

## 一、快速开始（3 步）

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

> ⚠️ **必须使用 Python ≥ 3.10**。Python 3.9 会因 click 版本冲突直接报错。

### 2. 启动服务

```bash
cd sanxia-ids/backend
python app.py
```

### 3. 打开浏览器

```
http://127.0.0.1:5000
```

**后端同时服务 API 和前端页面**，只需启动这一个进程，无需额外起前端服务器。

---

## 二、目录结构

```
sanxia-ids-standalone/
├── requirements.txt            # Python 依赖
├── README.md                   # 本文件
│
├── sanxia-ids/                 # 平台主体
│   ├── backend/                #   Flask 后端（API + 静态服务）
│   │   ├── app.py              #     主应用，25 个 REST 端点
│   │   ├── config.py           #     路径配置
│   │   ├── detection_service.py#     检测流水线（解析 + 特征 + 分类）
│   │   ├── fault_service.py    #     故障关联服务
│   │   └── uploads/            #     上传文件暂存
│   └── frontend/               #   Vue 3 前端（零构建，自带第三方库）
│       ├── index.html          #     入口
│       ├── lib/                #     Vue / Element Plus / ECharts（无需 npm）
│       ├── css/dark-theme.css  #     暗色工业主题
│       └── js/                 #     8 页面 / 16 组件
│
├── sanxia/                     # 后端依赖的核心模块与数据（勿删）
│   ├── data_preprocessing.py   #   Modbus 解析 + 滑动窗口特征提取
│   ├── fault_association.py    #   故障关联引擎（倒排索引 + 建议生成）
│   ├── prototype_classifier.py #   两级级联分类器（hybrid 模式用）
│   ├── dataset/
│   │   ├── features.csv        #     11,576 条带标签特征（CSV 检测演示用）
│   │   └── fault_index_cache.json #  故障索引缓存
│   ├── model_output/
│   │   └── prototypes.pkl      #     特征原型库（hybrid 模式用）
│   └── 附件3历史故障清单.docx    #   199 条历史故障记录
│
└── demo_pcap/                  # 演示用流量文件（6 个 pcapng，共 23MB）
    ├── fuzzing_2700.pcapng
    ├── getfunc_3000_3times.pcapng
    ├── readCoils_3000.pcapng
    ├── readHoldingRegister_200.pcapng
    ├── uid_700.pcapng
    └── writeSingleRegister_3300.pcapng
```

---

## 三、演示流程

1. 打开 `http://127.0.0.1:5000`
2. 进入 **流量检测** 页
3. 拖入 `demo_pcap/` 下任意 pcapng 文件
4. 选择检测模式（建议先用 **快速规则引擎**）
5. 点击「开始检测」
6. 检测完成后：
   - **检测结果** 页：按攻击类型/功能码/源IP 筛选
   - **分析详情** 页：查看 24 维特征 + 6 步 CoT 推理链
   - **故障关联**：查看物理后果评估 + 199 条历史故障匹配 + 处置建议

---

## 四、集成到你自己的平台

### 方式 A：整站嵌入（最省事）

本包就是一个完整 Web 应用。你的平台可以直接：
- **iframe 嵌入**：`<iframe src="http://127.0.0.1:5000" />`
- **反向代理**：Nginx 把 `/sanxia/` 转发到 `http://127.0.0.1:5000`

### 方式 B：仅调用后端 API

如果你已有自己的前端，只需调用 REST 接口。所有接口统一返回：

```json
{ "code": 200, "data": { ... } }
```

失败时：

```json
{ "code": 500, "detail": "错误信息" }
```

**核心接口**：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/statistics` | 仪表板聚合统计 |
| POST | `/api/upload/pcap` | 上传 pcapng（multipart `file`） |
| POST | `/api/upload/features-csv` | 上传特征 CSV |
| POST | `/api/detect` | 执行检测 `{file_id, mode, sample_count}` |
| GET | `/api/results` | 结果列表（分页/筛选） |
| GET | `/api/results/<id>` | 单条详情（含 CoT 推理链） |
| POST | `/api/associate/<id>` | 单条故障关联 |
| GET | `/api/faults` | 故障知识库（199 条） |
| GET | `/api/models` | 模型列表 |
| GET | `/api/performance` | 性能指标 |

**检测模式** `mode` 三个取值：

| 值 | 说明 | 速度 |
|----|------|------|
| `fast` | 纯规则引擎 | ~2ms/窗口 |
| `hybrid` | 规则 + 原型匹配（需 scikit-learn） | ~2ms/窗口 |
| `llm` | 大模型逐条推理 | ⚠️ 当前不可用，见下方限制 |

### 方式 C：仅复用检测算法

```python
import sys
sys.path.insert(0, "sanxia-ids-standalone/sanxia")

from data_preprocessing import parse_modbus_tcp, extract_window_features

# 你的原始包 → 特征
records = [...]                       # 自行解析出的 Modbus 记录列表
features = extract_window_features(records[:10])

# 特征 → 判定
from prototype_classifier import rule_based_classify
label, confidence = rule_based_classify(features)
```

---

## 五、已知限制（重要，请先看）

### 1. `llm` 模式当前不可用

后端 `detection_service.py` 尝试 `from infer import InferModel`，但 `infer.py` 中**并未定义 `InferModel` 类**，因此必然抛 `ImportError`，随后**静默降级到规则引擎**。

- 界面会显示「(规则引擎 — LLM 不可用)」
- 如需真正的 LLM 推理，需另行修复（建议改用 Ollama HTTP API 对接）
- **演示请使用 `fast` 或 `hybrid` 模式**

### 2. 准确率数值仅供参考

数据集的地真标签是**按文件名**给的（一个 pcapng 文件整体标为一种攻击）。但实际抓包文件里混有大量正常流量，例如 `fuzzing_2700.pcapng` 的 24,371 个 Modbus 包中只有 8,281 个是攻击包。

因此界面上显示的「准确率」会偏低，**这不代表检测能力差**。演示时建议重点展示：
- 攻击类型分布
- 分析详情页的 CoT 推理链
- 故障关联的处置建议

### 3. 故障分类的固有重叠

`fuzzing` / `uid_scan` / `read_coils` 在特征空间中高度重叠（都表现为 0x01 功能码主导），规则引擎无法可靠区分，三者准确率约 71%。这是数据特性决定的，需要更复杂的模型或人工复核。

### 4. 环境隔离建议

如果嵌入你的平台，建议用独立虚拟环境或 Docker 容器，避免依赖冲突：

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "sanxia-ids/backend/app.py"]
```

---

## 六、常见问题

| 现象 | 原因与处理 |
|------|-----------|
| `TypeError: unsupported operand type(s) for \|` | Python 版本过低，请用 3.10+ |
| `ModuleNotFoundError: data_preprocessing` | `sanxia/` 目录被移动或删除；它必须与 `sanxia-ids/` 同级 |
| 界面数据为空 | 后端未启动；前端会自动降级到 Mock 数据（此时显示的是演示假数据） |
| 端口 5000 被占用 | 修改 `backend/config.py` 中的 `PORT` |
| `hybrid` 模式退化为规则 | 未安装 scikit-learn，`pip install scikit-learn` |

---

## 七、联系方式

集成过程中遇到问题，请附上：
1. Python 版本（`python --version`）
2. 完整报错堆栈
3. 复现步骤
