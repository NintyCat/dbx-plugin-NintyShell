# NintyShell (com.nintycat.shell)

DBX 插件：在工作台里打开本地 Shell 终端，输入并执行 shell 命令。

## 功能

- **两种连接类型**：
  - **本地 Shell**：连接名称、Shell 路径、初始目录；Shell 路径留空时按平台自动选择（Windows: `powershell.exe`，macOS: `/bin/zsh`，Linux: `/bin/bash`）；
  - **SSH / SFTP**：主机、端口、用户名，支持密码或私钥（含口令）认证，可从表单直接测试连接。
- **终端工作台**（本地与 SSH 通用）：
  - **交互式真终端（PTY）**：连接后直接进入 xterm.js 终端，提示符、历史、Tab 补全、ANSI 颜色都由 shell 自己负责，行为与真实终端一致；
  - 交互式程序可用：vim、top、fzf、`sudo` 密码输入，也可以在本地终端里直接 `ssh` 到其他机器；
  - 同一 shell 进程贯穿整个会话：`export`、alias、shell 函数、`cd` 全部自然持久；
  - 终端尺寸随窗口自适应；会话结束（输入 `exit` 或断开）会提示从连接列表重连。
  - **兼容回退**：无法创建 PTY 时（旧版 Windows、受限沙箱）自动回到逐命令执行模式：输入框提交、命令分块输出、非零退出码提示、超 4 MB 截断、`↑`/`↓` 历史与 `Tab` 补全由插件实现。
- **SFTP 文件面板**（SSH 连接）：浏览/导航远程目录、上传（分块）、下载到本地、新建目录、重命名、递归删除；同时声明了 filesystem-provider（`sftp://` scheme），在真实 DBX 中可接入通用文件管理器。文件面板仅对 SSH 会话显示。
- **设置面板**（标题栏 ⚙）：
  - **文件面板跟随终端路径**：终端里 `cd` 后 SFTP 面板自动跟随刷新（依赖 shell 的 OSC 7 路径上报；本地 bash/zsh/PowerShell 已内置上报，远程 SSH 自动注入 reporter——注入行会短暂显示后自动清屏，可在设置关闭）；
  - **终端字号**：xterm 与兼容模式实时生效；
  - 设置保存在插件沙箱的 localStorage 中（不可用时退回默认值）。
- **操作记录**（文件面板底部）：无记录时整块隐藏；有记录后默认折叠为一条标题栏（含条数角标），点击展开/收起，「清空」移除全部记录；上传进行中或出错时自动展开。
- **实现方式**：本地会话默认以登录 shell 跑在伪终端上（POSIX 使用 `creack/pty`，Windows 10 1809+ 使用 ConPTY），注入 `TERM=xterm-256color`，按键经 `shell/input` 流入、输出经 `shell/output` 原样流出（SSH 相同，走 `golang.org/x/crypto`）；PTY 不可用时回退为每条命令 `shell -c` 子进程的模式（Windows 上 PowerShell 经 `-EncodedCommand` 执行，退出码与工作目录经临时文件回传，POSIX 通过额外的 fd 3 管道回传，不污染终端输出）。中断：PTY 模式下 Ctrl+C 直接作为按键传入；回退模式向进程组发 `SIGINT`（3 秒后升级为 `SIGKILL`）。

## 已知限制（待优化）

- SSH 主机密钥未做校验（v1 使用 InsecureIgnoreHostKey，后续加入 known_hosts 校验）；SSH 中断通过关闭会话通道实现，远端进程的清理依赖 sshd。
- 回退模式（无 PTY 环境）下交互式程序仍不可用，`export`/alias/shell 函数不跨命令持久化（目录会持久化）；不支持 fish（元数据语法不同）。POSIX 平台支持 bash / zsh / sh；Windows 本地 Shell 使用 PowerShell（`powershell.exe`/`pwsh`）或显式指定的 `cmd.exe`、git-bash。
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
