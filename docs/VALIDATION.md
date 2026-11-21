# BMC DHCP 1.9.0 — 验证记录

日期：2026-11-21（Asia/Shanghai）。本地环境为 Apple Silicon / macOS 26.6.2。原始输出保留在本机 `build/macos/`，不进入公开源码；下表只记录实际运行结果。

## 本地结果

| 检查 | 结果 | 方式 |
| --- | --- | --- |
| Python 3.13.3 本地回归 | 430 项通过，1 项跳过 | 跳过项只接受真实 Windows Winsock；其余物理网口操作由 mock 隔离 |
| Python 3.11 / 3.13 / 3.15 在线回归 | 全部通过 | GitHub Actions `macos-tests` 矩阵，运行 [44865823351](https://github.com/wiswawa/bmc-dhcp/actions/runs/44865823351) |
| 在线质量检查 | 通过 | pyflakes、公开内容审计、UI 冒烟、shell 语法、wheel 构建与源码目录外安装 |
| 前端函数冒烟 | 35/35 通过 | 超时、重试、空网口与错误呈现 |
| 静态与语法检查 | pyflakes、Bash、YAML 通过 | GitHub 工作流及问题表单可解析，动作引用为完整 SHA |
| DHCP 自检 | 11 项通过 | 真实环回 UDP DORA、Session 启停、网口枚举；使用临时端口 |
| 可靠性与边界 | 通过 | 原子写失败保留原文件；备份失败不改网口；恢复失败不覆盖旧记录；清理可重试；不分配保留地址 |
| 本地控制 API | 通过 | 非环回监听拒绝、Origin 端口校验、客户端不能改写启动配置中的保存路径 |
| Python wheel / sdist | 构建与 twine 元数据检查通过 | wheel 在源码目录外无依赖安装；CLI 版本与包版本一致，HTML 资源存在 |
| Mac 分发包 | 通过 | ZIP 解压至中文/空格路径，系统 PATH、错误代理下运行，校验版本、HTML、Scapy、启动和退出 |
| 对应源码与许可证 | 通过 | GPL 文本、项目/Scapy 源码摘要、依赖与原生库许可文件存在 |
| 公开内容 | 通过 | 公开清单逐项复核；源码与安装包未发现检查规则覆盖的个人路径、凭据或私有评估材料 |
| 源码包可重复性 | 通过 | 同样输入生成相同摘要；归一化时间、属主与权限，排除本地材料及生成的 egg-info |
| 缓存防漂移 | 通过 | 篡改冻结后端指纹时，`--skip-freeze` 拒绝继续构建 |
| 原生窗口 | 通过 | 默认设置、诊断、静态 IP 页面与退出确认；新截图来自本次实际应用 |
| 原生退出清理 | 通过 | 测试窗口和后台进程退出，会话文件删除 |
| Windows x64 便携包 | 通过 | Windows 2025 runner 上实际运行 GUI 包校验、CLI 自检、迁移路径、环回 API 与退出 |
| 三平台候选包 | 全部通过 | [运行 44865830860](https://github.com/wiswawa/bmc-dhcp/actions/runs/44865830860) 中 arm64、Intel、Windows x64 三个作业均为 success |
| 发布包内容审计 | 通过 | 解压并检查文件名、签名、许可证、对应源码、系统 DLL 排除、无内部记录/日志/令牌/个人路径；SHA-256 sidecar 可跨平台校验 |

Native QA 使用 `--no-elevate`、独立后台数据目录和临时 WebKit 存储，不读取/覆盖用户真实保存的表单。截图显示普通权限、空租约，不代表真实 BMC 分配成功。

## 重现命令

开发环境安装 `.[dev]` 后执行：

```bash
NO_PROXY='*' no_proxy='*' python -m unittest discover -s tests -v
python -m pyflakes src/bmcdhcp tests tools app.py app_win.py
node tools/ui_smoke.mjs --quiet
bash -n bmcd install.sh tools/make_app.sh
python tools/check_release.py
python -m build
python tools/verify_wheel.py
python tools/verify_macos.py
```

Mac 包使用独立、固定依赖的构建环境。Scapy 2.8.0 源码包已按 PyPI 提供的 SHA-256 校验；许可与对应源码纳入分发。当前签名为 ad-hoc，验证通过不等同于 Apple 公证。

## 明确未验证的部分

- **真实 BMC、物理二层链路与管理员网口改配/恢复尚未实机验证。** 环回与 mock 不能替代这些结果。
- **没有 Developer ID 签名或公证。** 跨机器首次启动可能需要用户允许打开。
- **Windows 包已在 Windows 2025 GitHub runner 上实际启动和验证，但仍未接物理 BMC。** Npcap、防火墙、UAC 交互以及不同 OEM 网卡/驱动仍需目标机验证。
- **Intel 和 Apple Silicon 包均已在 GitHub runner 上完成构建和包内验证，但 runner 验证不等同于目标 Mac 的物理网口改配与恢复。**

因此本版本仍标为 **Beta**。完整发布步骤见 [发布指南](RELEASING.md)，接线操作见 [快速上手](QUICKSTART.md)。
