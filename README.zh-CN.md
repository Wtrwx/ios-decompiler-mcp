# iOS Decompiler MCP

[English](README.md) | [简体中文](README.zh-CN.md)

面向操作者控制的越狱 iPhone，提供 iOS 运行时检查、逆向分析和 Theos/Logos Tweak 开发能力的 MCP 服务。

iOS Decompiler MCP 将 MCP 客户端与 SSH、Frida 及可选的正版 IDA 连接起来，通过结构化工具完成 UIKit 界面检查、Objective-C 元数据查询、方法调用追踪和应用级 Tweak 构建。设备变更通过独立的本地审批流程执行。

## 目录

- [功能](#功能)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [Demo](#demo)
- [项目结构](#项目结构)
- [开发](#开发)
- [安全与能力边界](#安全与能力边界)
- [文档](#文档)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

## 功能

| 模块 | 能力 | 工具示例 |
| --- | --- | --- |
| 设备管理 | SSH/SFTP、设备信息、应用与进程枚举 | `device_connect`、`device_info`、`device_list_apps` |
| UIKit 检查 | 窗口与场景、视图树、坐标命中、约束、响应链、截图 | `ui_snapshot`、`ui_inspect_view`、`ui_screenshot` |
| Objective-C | 类、方法、属性、实例变量、IMP、对象元数据、头文件生成 | `objc_dump_class`、`objc_get_methods`、`objc_generate_header` |
| 动态分析 | 持久 Frida 会话、观察型 Hook、有界事件与调用栈 | `frida_attach`、`frida_trace_method`、`frida_get_events` |
| 静态分析 | 可选无界面 IDA、反汇编、Hex-Rays 伪代码、交叉引用、运行时地址关联 | `ida_open_binary`、`ida_decompile`、`ida_resolve_runtime_address` |
| Tweak 开发 | 可编辑 Logos 项目、ABI 校验、Theos 构建、审批部署、验证与回滚 | `tweak_create_project`、`tweak_build`、`tweak_deploy` |
| 工作流 | 按钮标题修改、持久化报告、后台任务与取消 | `develop_tweak`、`job_status`、`job_cancel` |

完整工具与必填字段见[工具参考](docs/TOOLS.md)。

## 环境要求

| 组件 | 要求 |
| --- | --- |
| 主机 | macOS 或 Linux，Python 3.11+，[uv](https://docs.astral.sh/uv/) |
| 设备 | 操作者控制的越狱 iPhone，支持 SSH 公钥认证 |
| Frida | Frida 17.x，最低 17.5；主机客户端与设备服务端版本必须完全一致 |
| Tweak 构建 | [Theos](https://theos.dev/)、Logos、`make`、兼容的 iOS SDK、编译链接器与签名工具 |
| Tweak 部署 | 兼容的注入框架，以及具备 `dpkg` 安装权限的 SSH 账户 |
| 静态分析 | 可选：正版 IDA Pro 9+、官方 `idapro` 支持和兼容的 Python 解释器；伪代码需要 Hex-Rays |
| Agent 开发 | Node.js 与 npm，仅在重新构建 TypeScript Agent 时需要 |

Python 包已包含编译后的 Frida Agent。基础 SSH、界面和运行时检查不依赖 Node.js、Theos 或 IDA。项目优先面向 Rootless 越狱；ARM64e Tweak 构建需要 macOS 上适用的 Apple 工具链。SDK、商业工具和设备端服务由操作者准备。

## 快速开始

### 1. 安装主机依赖

在仓库根目录执行：

```sh
uv sync --frozen --all-extras --no-editable
cp -n examples/ios-decompiler-mcp.toml ios-decompiler-mcp.local.toml
chmod 600 ios-decompiler-mcp.local.toml
```

锁文件固定 Python 依赖版本。非 editable 安装也适用于不加载 editable `.pth` 文件的受管环境。

### 2. 配置设备

编辑 `ios-decompiler-mcp.local.toml`，设置工作区绝对路径、SSH 地址、密钥、经过核验的 SSH 主机密钥、允许访问的应用 Bundle ID 和 Frida 连接方式。

```toml
workspace = "/absolute/path/to/ios-decompiler-mcp"
state_dir = ".flex-mcp"

[devices.test]
host = "127.0.0.1"
port = 2222
username = "root"
client_keys = ["~/.ssh/id_ed25519"]
known_hosts = "~/.ssh/known_hosts"
allowed_apps = ["dev.flex.fixture"]
frida_device_id = "replace-with-observed-device-id"
```

示例地址假定已建立本地 SSH 转发，请按设备实际连接方式修改。连接前应核验并固定 SSH 主机密钥。使用 `frida_list_devices` 返回的准确设备 ID。如果使用已有的安全 Frida SSH 隧道，将 `frida_device_id` 替换为 `frida_remote = "127.0.0.1:27043"`；每台设备只配置一种 Frida 连接方式。

构建 Tweak 时，设置 `THEOS` 环境变量或配置中的 `theos` 路径。使用 IDA 时，先完成官方许可与 Python 环境配置，再设置 `ida_directory` 和 `ida_python`。更多选项见[示例配置](examples/ios-decompiler-mcp.toml)中的注释。

### 3. 连接 MCP 客户端

```sh
.venv/bin/ios-decompiler-mcp --config /absolute/path/to/ios-decompiler-mcp/ios-decompiler-mcp.local.toml
```

在 MCP 客户端中使用绝对路径启动此命令。标准输出用于 MCP 协议，诊断信息写入标准错误。Codex、Claude Code 和 Cursor 的示例见[客户端配置](docs/CLIENTS.md)。

同一状态目录只运行一个服务进程。未配置设备时，仍可使用 `server_status` 等主机工具。服务本身不需要模型 API Key。

## Demo

### 检查正在运行的应用

解锁 iPhone，打开白名单内的应用。先以 `{"device_id":"test"}` 调用 `device_connect` 和 `device_list_apps`，再调用 `frida_attach`：

```json
{
  "device_id": "test",
  "bundle_id": "dev.flex.fixture"
}
```

将返回的 `session_id` 用于 `ui_snapshot`：

```json
{
  "device_id": "test",
  "session_id": "process_SESSION_ID",
  "depth": 8,
  "max_nodes": 500,
  "limit": 100,
  "include_text": false
}
```

请将占位 ID 替换为实际返回值。使用 `ui_inspect_view` 可继续查看视图所属控制器和 Target-Action 映射。需要文字时显式设置 `include_text: true`。结束后调用 `frida_detach`；分离、进程退出或服务重启后，原对象与会话 ID 失效。

### 读取当前应用窗口截图

附加应用后，调用 `ui_screenshot`：

```json
{
  "device_id": "test",
  "session_id": "process_SESSION_ID"
}
```

工具将已附加应用的 UIKit 窗口渲染为 PNG，默认选择 Key Window。也可以传入 `ui_get_windows` 返回的 `window_id` 指定窗口。响应同时包含原生 MCP 图片块，以及 `mime_type`、`local_path`、`bytes`、`window_id` 等结构化信息；支持图片的 MCP 客户端可直接展示。

图片保存在 `<state_dir>/screenshots/`。截图范围是所选应用可渲染的窗口；系统浮层、部分受保护内容或 GPU 渲染内容可能不会出现在图片中。

### 构建并验证按钮标题 Tweak

[UIKit 示例应用](examples/UIKitFixture/README.md)包含标识为 `fixture.button` 的按钮及 Objective-C Action。按照该指南构建、安装并打开示例应用后，调用 `develop_tweak`：

```json
{
  "device_id": "test",
  "bundle_id": "dev.flex.fixture",
  "accessibility_identifier": "fixture.button",
  "replacement_title": "Hello iOS Decompiler MCP"
}
```

工作流检查按钮、校验实际观测到的控制器生命周期方法、生成可编辑的 Logos 项目并构建安装包。目标必须是唯一匹配的 `UIButton`，且方法签名受支持。任务默认在后台运行，通过返回的 `job_id` 调用 `job_status` 获取报告。

到达审批阶段后，由操作者在独立终端审阅具体操作。使用报告中的审批 ID 和服务实际使用的状态目录绝对路径：

```sh
.venv/bin/ios-decompiler-mcp-approve --state-dir /absolute/path/to/ios-decompiler-mcp/.flex-mcp approval_ID
```

随后以 `workflow_id` 和已授权的 `approval_id` 再次调用 `develop_tweak` 继续执行。部署验证检查加载的构建标识、Hook 调用、实际按钮标题和可读取的崩溃证据。卸载或独立执行回滚需要单独审批。

完整的“检查 → 构建 → 审批安装 → 验证 → 审批卸载 → 恢复”交互演示：

```sh
PYTHONPATH=src .venv/bin/python examples/demo.py --config ios-decompiler-mcp.local.toml --device test
```

## 项目结构

```text
ios-decompiler-mcp/
├── src/flex_mcp/
│   ├── server.py        # MCP stdio 入口
│   ├── config.py        # 配置与校验
│   ├── core/            # 会话、状态、审批、任务和证据
│   ├── adapters/        # SSH、Frida、IDA、Mach-O 与 Theos 集成
│   ├── tools/           # 结构化 MCP 工具
│   ├── workflows/       # Tweak 开发与部署
│   └── assets/          # Frida Agent 产物及许可证声明
├── agents/frida/        # 设备端 TypeScript 源码
├── examples/            # 配置、UIKit 示例应用与 Demo
├── scripts/             # 构建、文档和验证脚本
├── tests/
├── docs/
├── pyproject.toml
└── uv.lock
```

为兼容已有使用方式，保留 Python 命名空间 `flex_mcp`、默认状态目录 `.flex-mcp` 和旧命令别名 `flex-mcp` / `flex-mcp-approve`。已有配置文件继续有效。

## 开发

```sh
uv sync --frozen --all-extras --no-editable
npm ci --ignore-scripts
npm run typecheck
npm run build
.venv/bin/ruff check src tests scripts examples/demo.py
.venv/bin/mypy
.venv/bin/pytest -q
uv build
```

Agent 使用 Frida Python 提供的官方编译器构建，并打包 `frida-objc-bridge`。修改 Python 源码或重新构建 Agent 后，在使用已安装的启动命令前更新非 editable 安装：

```sh
uv sync --frozen --all-extras --no-editable --reinstall-package ios-decompiler-mcp
.venv/bin/python scripts/smoke_stdio.py
```

直接从源码运行：

`PYTHONPATH=src .venv/bin/python -m flex_mcp.server --config /absolute/config.toml`

重新生成工具文档：

`PYTHONPATH=src .venv/bin/python scripts/document_tools.py`

单元和集成测试按需替换设备、编译器及 IDA 等外部边界；SSH/SFTP 集成测试使用本地回环服务。真机 Demo 需要已配置的设备；可选工具链检查脚本为 `scripts/verify_theos.py` 和 `scripts/verify_ida.py`。

## 安全与能力边界

- 设备和应用白名单限制访问目标。默认进行检查；安装、应用重启等影响设备的操作需要本地审批。
- 审批绑定具体操作参数和产物，具有有效期且只能使用一次。MCP 客户端不能自行授予审批。
- 工具具有操作限额、结构化错误、审计记录和清理机制。MCP 不开放任意 Shell 命令或注入 JavaScript 的入口。
- UIKit 操作在主队列执行。对象 ID 属于当前会话，持有对象可能使其延迟到分离后释放。
- 主要目标为 UIKit 和 Objective-C。Swift 可见性取决于 Objective-C 互操作性；完整 Swift 元数据与 SwiftUI 重建不在当前能力范围内。
- 运行时与静态地址关联要求镜像身份、架构及段范围证据匹配。推断类型与伪代码会明确标记。

请妥善保管本地配置、密钥、状态数据库、追踪记录和截图。审批与回滚行为见[安全与恢复](docs/SECURITY.md)。

## 文档

| 指南 | 内容 |
| --- | --- |
| [客户端配置](docs/CLIENTS.md) | 通过 stdio 连接 MCP 客户端 |
| [工具参考](docs/TOOLS.md) | 工具分类、必填参数与行为 |
| [UIKit 示例应用](examples/UIKitFixture/README.md) | 构建示例应用并运行完整 Demo |
| [安全与恢复](docs/SECURITY.md) | 权限、审批范围和故障恢复 |
| [故障排查](docs/TROUBLESHOOTING.md) | 设备、Frida、IDA 与构建诊断 |
| [上游项目调研](docs/EXISTING_PROJECTS.md) | 复用决策、兼容性与许可证 |
| [第三方声明](THIRD_PARTY_NOTICES.md) | 打包代码和外部依赖的许可证 |

## 参与贡献

欢迎提交 Issue 和 Pull Request。反馈问题时，请附上相关主机、iOS、越狱环境、Frida 和工具链版本，并移除敏感信息。保持修改聚焦，为行为变更补充有意义的测试，运行相关开发检查；用户可见行为变化时同步更新中英文 README，新增工具时更新生成的工具文档。

## 许可证

iOS Decompiler MCP 原创代码使用 [MIT 许可证](LICENSE)。打包代码和各项依赖保留各自许可证，详见[第三方声明](THIRD_PARTY_NOTICES.md)。

项目基于 [Frida](https://frida.re/)、[Theos](https://theos.dev/) 和 [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)，界面与运行时检查思路参考 [FLEX](https://github.com/FLEXTool/FLEX)。
