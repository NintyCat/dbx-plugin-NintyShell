# NintyShell (com.nintycat.shell)

DBX 插件：在工作台里打开本地 Shell 终端，输入并执行 shell 命令。

## 功能

- **两种连接类型**：
  - **本地 Shell**：连接名称、Shell 路径、初始目录；Shell 路径留空时按平台自动选择（Windows: `powershell.exe`，macOS: `/bin/zsh`，Linux: `/bin/bash`）；
  - **SSH / SFTP**：主机、端口、用户名，支持密码或私钥（含口令）认证，可从表单直接测试连接。
- **终端工作台**（本地与 SSH 通用）：
  - 流式输出 —— 命令输出通过后端事件实时推送到界面；
  - 工作目录跨命令持久化（`cd` 之后提示符与后续命令的目录保持一致）；
  - `↑` / `↓` 翻看命令历史，`Ctrl+C` 中断当前命令（中断按钮同样有效），`Ctrl+L` 清屏；
  - `Tab` 补全：命令位置优先推荐常用命令，参数位置补全文件/子目录（`cd` 只补目录，`$` 开头补环境变量）；
  - 每条命令显示退出码（非零时），输出超过 4 MB 自动截断。
- **SFTP 文件面板**（SSH 连接）：浏览/导航远程目录、上传（分块）、下载到本地、新建目录、重命名、递归删除；同时声明了 filesystem-provider（`sftp://` scheme），在真实 DBX 中可接入通用文件管理器。
- **操作记录**（文件面板底部）：无记录时整块隐藏；有记录后默认折叠为一条标题栏（含条数角标），点击展开/收起，「清空」移除全部记录；上传进行中或出错时自动展开。
- **终端工作台**：
  - 流式输出 —— 命令输出通过后端事件实时推送到界面；
  - 工作目录跨命令持久化（`cd` 之后提示符与后续命令的目录保持一致）；
  - `↑` / `↓` 翻看命令历史，`Ctrl+C` 中断当前命令（中断按钮同样有效），`Ctrl+L` 清屏；
  - `Tab` 补全：命令位置补全 PATH 可执行文件与内建命令，参数位置补全文件/子目录（`cd` 时只补目录，`$` 开头补环境变量）；多候选时弹出候选列表，再按 `Tab` 循环选择，`Esc` 关闭；
  - 每条命令显示退出码（非零时），输出超过 4 MB 自动截断。
- **实现方式**：Go Sidecar 为每条命令启动 `shell -c` 子进程（Windows 上 PowerShell 经 `-EncodedCommand` 执行，退出码与工作目录经临时文件回传），POSIX 平台通过额外的 fd 3 管道回传退出码与新工作目录（不污染终端输出）；输出以 `shell/output` 事件、命令结束以 `shell/exit` 事件推送。中断通过向进程组发 `SIGINT`（3 秒后升级为 `SIGKILL`）实现。

## 已知限制（待优化）

- 无 PTY：交互式程序（vim、sudo 密码输入等）不可用；`export`/环境变量、alias、shell 函数不跨命令持久化（目录会持久化）。
- SSH 主机密钥未做校验（v1 使用 InsecureIgnoreHostKey，后续加入 known_hosts 校验）；SSH 中断通过关闭会话通道实现，远端进程的清理依赖 sshd。
- 不支持 fish（元数据语法不同）；POSIX 平台支持 bash / zsh / sh；Windows 本地 Shell 使用 PowerShell（`powershell.exe`/`pwsh`，支持 `cd` 持久化）或显式指定的 `cmd.exe`（无 `cd` 持久化）。无 ANSI 颜色渲染（界面会剥离转义序列）。
- 开发宿主不模拟 `host.openFilesystem`，filesystem-provider 需在真实 DBX 中验证。
- **拖拽上传依赖宿主放开 HTML5 拖放**：DBX 桌面端基于 Tauri，默认 `dragDropEnabled: true` 会在窗口层拦截原生文件拖放，插件沙箱 iframe 收不到 `drop` 事件，因此拖拽在真实客户端中可能无效（dev 宿主浏览器中可用）。此时请使用「上传」按钮（系统文件选择器）。插件侧已把 drop 监听挂到 document 级并阻止默认导航，宿主未来放开限制后即可生效；根治需要在 DBX 宿主侧设置 `dragDropEnabled: false` 或把 `tauri://drag-drop` 事件转发给插件。

## 开发

需要 Node.js 22+ 与 Go 工具链：

```bash
dbx-plugin dev --path . --port 5190
```

打包（在目标平台上执行，产出未签名候选包）：

```bash
dbx-plugin package .
```
