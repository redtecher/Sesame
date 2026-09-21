# Sesame

[English](README.md) | [简体中文](README_zh.md)

Sesame 是一个面向可测试性提升的 rehosted IoT 固件分析系统。固件被重托管到模拟环境（如 QEMU）后，其 Web 攻击面——管理页面、CGI 端点、API——大部分都被认证门槛阻断，无法进行后续分析与 fuzzing。

Sesame 利用 LLM 驱动的智能体**恢复认证依赖状态**（登录流程、默认凭据、会话 Cookie/Token），使被认证门槛阻断的页面和服务重新进入可测试状态，从而提升 rehosting 指标、扩大后续 fuzzing 的有效覆盖面。打穿认证本身不是目的——恢复可测试性才是。

## 工作原理

Sesame 实现了一条 4 阶段流水线，由配备文件系统工具（`search_files`、`read_file`、`grep_files`）和运行时工具（`http_request`、`browser_navigate`）的 LLM 智能体驱动：

| 阶段 | 内容 |
|------|------|
| **预处理** | 自动反编译 Fate/Z 加密 Lua 文件（小米/MIWiFi），内置 `unluac_miwifi` |
| **1 · 攻击面发现** | 基于 rootfs 静态分析：Web 二进制、CGI 处理器、前端资源、配置源、JavaScript 分发表（如 `topicurl.js`），以及厂商认证模式知识库（TOTOLINK、小米、D-Link、TP-Link 等） |
| **2 · 语义分析** | 3 阶段 LLM 流水线：**Stage 1** 用文件系统工具探索固件，识别认证架构、登录 URL/方法/参数、会话机制和凭据存储；**Stage 2** 推理认证门控阻断可测试性的原因，将失配分类为 source / representation / transfer / consumption 四层；**Stage 3** 用运行时工具自主执行恢复——登录尝试、凭据重置、会话 Token 捕获、浏览器驱动流程 |
| **3 · 失配定位** | 将 LLM 识别的失配与启发式 fallback 发现相结合，对恢复假设排序 |
| **4 · 验证与 Fuzz 使能** | 以恢复出的会话状态重新评估目标可达性，生成带 Cookie/Token 种子的 fuzz 产物；执行智能体可在 QEMU 虚拟机内重放恢复计划 |

每个发现的目标按可达性阶梯评级：`unreachable → login_page → post_auth_page → api_ready → fuzz_ready`。

## 安装

环境要求：Python ≥ 3.10、[Java 运行时](https://adoptium.net/)（仅反编译小米固件 Lua 时需要）。

```bash
pip install -e .
playwright install chromium   # 浏览器驱动的认证恢复需要
```

## 快速开始

1. 配置 LLM 访问（可选——不配置 Key 时系统自动降级为启发式分析）：

```bash
cp .env.example .env
# 编辑 .env，填入 SESAME_DEEPSEEK_API_KEY
```

2. 将 Sesame 指向已由你的重托管环境提供 Web 服务的解包固件 rootfs：

```bash
python -m sesame audit \
  --rootfs /path/to/squashfs-root \
  --web http://10.10.10.2
```

加 `--json` 输出机器可读结果，或使用安装后的入口命令（`sesame audit …`）。

Sesame 会输出前/后 rehosting 指标对比、逐目标可达性与阻断原因、失配假设、恢复计划以及生成的 fuzz 产物；结构化运行摘要会追加写入 `logs/`。

## 配置项

所有配置均为环境变量（从 `.env` 加载，全部可选）：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SESAME_DEEPSEEK_API_KEY` | *(空)* | DeepSeek API Key；为空时仅启用启发式分析 |
| `SESAME_DEEPSEEK_API_BASE` | *(空)* | 自定义 API Base URL |
| `SESAME_DEEPSEEK_MODEL` | `deepseek-v4-pro` | 模型名 |
| `SESAME_DEEPSEEK_TEMPERATURE` | `0.0` | 采样温度 |
| `SESAME_DEEPSEEK_THINKING` | `true` | 启用深度思考模式 |
| `SESAME_HTTP_TIMEOUT` | `8.0` | HTTP 探测超时（秒） |
| `SESAME_MAX_CONTEXT_CHARS` | `8000` | 单文件读入 LLM 上下文的最大字符数 |
| `SESAME_MAX_TARGETS` | `128` | 单次运行分析的目标上限 |
| `SESAME_DEBUG` | `false` | 详细日志 |

## 实测结果

### TOTOLINK NR1800X（MIPS，lighttpd + cstecgi.cgi）

| 指标 | 恢复前 | 恢复后 |
|------|--------|--------|
| 可达页面 | 1 | 17 |
| 认证后目标 | 0 | 137 |
| Fuzz-ready 目标 | 0 | 12 |

### 小米 BE3600 Pro（ARM，nginx + uhttpd/LuCI）

| 指标 | 结果 |
|------|------|
| 发现目标总数 | 21 |
| 反编译 Fate/Z Lua 文件数 | 228 |

## 项目结构

```text
sesame/
├── browser/           # Playwright 驱动 + 固件 Web UI 分析器
├── connectors/        # HTTP 探测 + QEMU Shell 连接器（SSH/串口/telnet）
├── discovery/         # 攻击面发现、厂商认证知识库、Lua 反编译器
├── domain/            # 数据模型（surface、report、mismatch、llm_result）
├── execution/         # 恢复计划执行智能体（QEMU 虚拟机、重试逻辑）
├── primitives/        # 恢复原语
├── reasoning/         # 失配定位、假设排序、计划组装
├── semantics/         # LLM 智能体流水线（orchestrator、stages、agent tools）
├── utils/             # 日志、缓存、unluac_miwifi Lua 反编译器
├── verification/      # 可达性评估 + fuzz 产物生成
├── bootstrap.py       # 配置（.env 加载）
├── cli.py             # Typer CLI（Rich 输出）
├── config.py          # RuntimeBundle 工厂
└── pipeline.py        # 主流水线入口
```

## 文档

- [docs/design_zh.md](docs/design_zh.md) — 研究框架、创新点、评测设计
- [docs/implementation_zh.md](docs/implementation_zh.md) — 架构、流水线、模型与工程细节

## 合规使用

Sesame 是一款安全研究工具，仅用于分析**你本人拥有或获得授权测试的本地模拟环境中的固件**。未经设备/服务所有者明确许可，请勿对在线设备或服务使用本工具。

## 第三方组件

- [unluac](https://sourceforge.net/projects/unluac/)（内置为 `sesame/utils/unluac_miwifi`，MIT 协议）——经修改支持 Fate/Z 加密 Lua，见其 `license.txt`

## 许可证

以 [MIT License](LICENSE) 开源发布。
