# App 自动化与实例参数

这组入口用于操作员控制的测试设备和白名单 App，复用已有 Frida 会话和进程验证。
不需要安装新的设备服务。支持 Objective-C 以及暴露给 Objective-C 的 Swift 类型。

## 批量操作

`ui_automate(device_id, bundle_id, steps, after_capture="none")` 将整批步骤放在一次 MCP 调用、
一次 Frida RPC 中执行。每次 UIKit 访问均调度到主线程；等待通过异步定时器完成，避免阻塞主线程。
默认不等待、不截图、不读取文字。已验证会话会复用，没有隐式应用启动或重启。

| action | 主要参数 | 实际行为 |
| --- | --- | --- |
| `tap` | `target`，可选 `event` | 最近的 UIControl 发送 touch-up-inside/primary-action；UISwitch 切换状态并发 value-changed；或 accessibility activation |
| `back` | `mode=auto/navigation/dismiss`，`animated=false` | 当前导航栈 pop，或关闭模态控制器；根页面不能返回时明确报错 |
| `input_text` | `target`、`text`，`focus=false` | 设置 UITextField/UITextView 的文本，并发送 editing-changed/文本变更通知 |
| `scroll` | `target`、`dx/dy`，`animated=false` | 找到 UIScrollView，按 UIKit 点调整并约束 contentOffset |
| `assert` | `target` | 检查一个可见目标存在，返回匹配 ID |
| `wait_for` | `target`、`timeout_ms=1000`、`poll_ms=100` | 在设备端有界轮询；一次 MCP/RPC，无模型往返；超时即停止 |

`target` 三种形式互斥：

```json
{"view_id":"process_SESSION:object_N"}
{"accessibility_identifier":"fixture.button"}
{"x":200,"y":400}
```

选择器可以组合 `accessibility_identifier`、`class_name`、`text`。`text` 只用于显式匹配，
不自动回传控件文字。多个匹配默认报错，使用 `match_index` 明确选择。坐标以所选窗口 UIKit
点为单位，可指定 `window_id`。已有 `view_id` 和坐标命中可避免再次遍历 UI 树。
隐藏、透明、禁用或离开窗口的目标不能执行操作。

最多 20 步，总等待预算（wait_for 超时加 settle_ms）最多 10 秒。需要固定等待时显式指定
`settle_ms`（每步 0..500ms）。优先用匹配当前状态的 `wait_for`，避免固定睡眠。
`after_capture` 可选 `none/summary/screenshot/both`；摘要、PNG 在同一次 RPC 内采集，
文字仍须 `include_text=true`。摘要默认最多回传 20 行，其余通过 `ui_snapshot` 的游标读取。

以下是仓库 fixture 的点击及结果检查，需先部署、允许并打开 fixture：

```json
{
  "device_id":"test",
  "bundle_id":"dev.iosdecompiler.fixture",
  "steps":[
    {"action":"tap","target":{"accessibility_identifier":"fixture.button"}},
    {"action":"wait_for","target":{"accessibility_identifier":"fixture.status","text":"Tapped"},"timeout_ms":1000}
  ],
  "after_capture":"summary"
}
```

返回逐步执行状态、耗时和 `completed`。失败立即停止，前面已完成的步骤不会自动回滚；
超时/断线可能使最后一步结果不确定，调用方应重新读取状态，禁止盲目重试修改操作。
取消或 dispose 会阻止后续步骤，已完成的操作保留。会话及输入对象在等待期间保持引用。

本后端执行 UIKit 语义操作。自定义 UIView 可使用其 accessibility activation；仅依赖原始
触摸/手势的视图会明确返回不支持。滚动不会产生 pan 触摸序列，文本设置不会模拟键盘/IME，
返回不会合成边缘手势。系统主屏幕、跨 App、任意 HID 触摸不在此次选择的 Frida 部署范围内。
动画结束、异步网络请求、tweak hook 生效仍需根据实际状态检查。

## 具体实例参数

`objc_query_instances` 一次完成会话复用、实例发现、指定字段读取及结果缓存。对仓库 fixture：

```json
{
  "device_id":"test",
  "bundle_id":"dev.iosdecompiler.fixture",
  "class_name":"DecompilerFixtureViewController",
  "field_names":["_tapCount","_button"],
  "max_instances":5,
  "limit":5
}
```

返回实例 `object_id`、类名、`values` 及截断标记。返回的对象引用可再次传入 `object_ids`，
在一批中读取不同类对象；此路径不扫描堆。已有会话的 `objc_inspect_object` 也支持
`include_values=true` 或 `field_names`。默认仍返回元数据。

```json
{"device_id":"test","bundle_id":"dev.iosdecompiler.fixture","object_ids":["process_SESSION:object_N"],"field_names":["_tapCount"]}
```

字段名称应取自实际类的 `objc_get_ivars`/`objc_inspect_object` 元数据或自己的源码。
UIKit 的私有 ivar 会随系统变化；例如 iOS 16 的 UIView 不能假设存在 `_tag`。
字段不存在/布局不支持时返回 `unavailable`，不猜测偏移或调用同名 getter。

默认最多 20 个实例、前 8 个 ivar、每页 10 行。可选 `max_string_length=128`、
`max_depth=1`、`max_items=5`。整个查询另有 1000 个值节点、32768 个字符串字符的硬预算。
NSString/NSNumber、NSArray/NSDictionary、NSData 长度按需有界序列化；其他对象返回租约引用。
64 位整数/指针使用字符串表示以避免精度丢失，不解引用原始指针。
敏感 ivar 名、字典键在读取前检查，返回 `[REDACTED]`；结果还通过既有脱敏层。

`snapshot_id` 的后续分页只读主机中的同一份不可变结果，不重新枚举实例、读取字段或访问设备。
分页只接受设备、App、snapshot_id、offset、limit；需要新值时不传 snapshot_id。
实例/UI 快照共享配置中的 TTL、数量、字节预算；进程退出或会话失效会同步清理。
活动操作保护输入句柄，过期、淘汰后应重新获取。2048 对象上限保持不变。

堆发现仍调用 Frida 的 allocator 扫描，可能暂停应用；限制结果数量不等于限制底层扫描时间。
已知对象优先使用 `object_ids`，已采集结果优先使用游标。并发修改的字段不能保证跨对象原子一致。
纯 Swift、计算属性、任意 getter/description 和无限制内存读取不支持。

## 参考与验证

参考了 [frida-objc-bridge 的 choose/ivar 实现](https://github.com/frida/frida-objc-bridge/blob/main/index.js)
及 [WebDriverAgent 的元素操作接口](https://github.com/appium/WebDriverAgent/blob/master/WebDriverAgentLib/Commands/FBElementCommands.m)。
前者的 choose 回调同步执行，因此采集及 retain 保持在同一主线程租约内；后者使用 XCTest，
本实现沿用用户选择的 Frida 方案，没有引入 XCTest/WDA 设备依赖。

`npm test` 执行生产 TypeScript 的对象租约、UIKit 操作、等待/取消及值读取逻辑；Python 测试覆盖
会话复用、进程变化、MCP 原生图片、单 RPC 批次和缓存分页。真机只读验证脚本：

```sh
PYTHONPATH=src .venv/bin/python scripts/verify_runtime.py \
  --config vesper.local.toml --device test --bundle dev.iosdecompiler.fixture \
  --samples 20 --output .vesper/benchmarks/runtime.json
```

当前实测覆盖具体 ivar、堆发现、混合对象、零 RPC 分页、只读断言/等待和原生图片。
点击/输入/滚动/导航的 UIKit 行为使用生产代码单元测试验证。真机验证结果与性能详情见
[采集性能报告](CAPTURE_PERFORMANCE.md)。
