# GitHub 开源准备

本次工作以“可审阅、可构建、可验证”为目标，上传前排除运行数据及本机材料。

## 已准备

- GPL-2.0-only 许可证与第三方声明；Mac 包内附依赖许可证、对应项目/Scapy 源码和依赖清单。
- 中英文 README、快速使用、架构、CLI、贡献、安全、社区规范和更新记录。
- 问题表单、PR 模板、Dependabot、SHA 固定的 GitHub Actions；工作流默认只读权限。
- 自动化回归、原生窗口/分发包验证工具、wheel 安装验证和公开源码检查。
- 公开文件白名单与可重复生成的源码包；本地评估记录、环境、抓包、运行状态和二进制产物不进入源码仓库。
- 版本号从 `src/bmcdhcp/__init__.py` 单一位置读取，减少元数据漂移。

最新实际结果见 [验证记录](VALIDATION.md)。本地 Git 使用 `main`，公开文件按清单审阅；提交身份使用已确认 GitHub 账号的 noreply 地址，避免公开个人邮箱。

## 当前上传目标

已通过 GitHub 插件确认账号，创建公开仓库 [zyf18195378233/bmc-dhcp](https://github.com/zyf18195378233/bmc-dhcp)。代码、工作流和发布资产由本次检查后上传；最终 CI 与资产结果在发布页及验证记录中核实。

仓库所有者应维护私密漏洞报告、联系方式及分支保护。应用仍以 Beta 发布，真实 BMC 与管理员网口恢复结果不能由构建成功替代。

## 建议仓库信息

- 名称：`bmc-dhcp`
- 描述：`Temporary DHCP and BMC discovery for directly connected management interfaces on macOS.`
- Topics：`macos`, `dhcp`, `bmc`, `ipmi`, `idrac`, `ilo`, `system-administration`, `python`, `swift`

仓库创建后再添加实际的仓库 URL、状态徽章、Releases 下载链接及维护者信息；当前不使用虚构链接或未经运行的绿色 CI 徽章。
