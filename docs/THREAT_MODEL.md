# 威胁模型、设计取舍与安全边界

## 1. 关注的核心威胁（对应 OWASP Agentic / LLM Top 10）

1. **间接提示词注入导致的工具劫持**：智能体通过网页抓取或文档读取摄入恶意指令，试图在后续轮次诱导调用写文件、执行命令或向外部上传敏感文件。
   - 缓解：`injection_guard`（含 Unicode Tag 隐藏字符还原、NFKC 折叠与 Base64 解码）检测注入并激活会话污点窗口（`taint_ttl_calls`），直接封锁标记为 `taint_sensitive=True` 的危险汇工具，并在 `McpSecurityProxy` 层通过请求串行屏障防止流水线并发竞态绕过。
2. **工作区逃逸与凭据探测**：路径穿越 `../`、路径前缀匹配误差（`/work` vs `/work_evil`）、目录符号链接逃逸以及直接读取 `.env` / `.ssh/id_rsa` / `.git/config`。
   - 缓解：`path_guard` 基于 `os.path.realpath` 规范化与 `Path.is_relative_to()` 容器检查，在执行前于代理层直接拒绝，不触发上游文件读取。
3. **非典型命令注入与 GTFOBins 提权**：双引号内 `$(id)` 命令替换、`env`/`sudo`/`timeout` 包装穿透、以及 `python3 -c`、`find -exec`、`tar --to-command`、`git -c core.sshCommand`、`curl -d` 等免 Metachar 注入。
4. **混淆编码与 DNS 重绑定 SSRF**：`127.0.0.1` 的十进制/十六进制/八进制/缩写变形、`[::ffff:169.254.169.254]`、NAT64/6to4 隧道 IP、userinfo `@` 混淆与解析落入内网段。
5. **敏感凭据在上下游之间双向泄露**：工具输出意外带出 API Key / PEM 私钥进入模型上下文，或智能体试图把秘钥写入外部记忆库 / 远程 URL。

## 2. 关键工程取舍

| 取舍项 | 选择 | 代价与原因 |
| :--- | :--- | :--- |
| 零依赖纯标准库检测 vs 本地小模型分类器 | 规则引擎 + 编码还原 + 熵值检测 + 动态污点 | P95 延迟仅约 0.84ms（无需 GPU/PyTorch/模型下载），可确定性审计；代价是对纯自然语言语义诱导且不含任何角色分隔、覆盖词、外传词与编码混淆的攻击召回有限 |
| 代理层阻塞串行 `tools/call` | 串行化单客户端待决调用 | 牺牲了同一客户端并行扇出多个慢速工具调用的吞吐，换取严格的因果污点传递保证 |
| 应用层检查 DNS vs 内核网络策略 | `ssrf_guard` 解析校验 + `resolve_dns` 开关 | 可独立于 Docker/root 权限运行；但在未做底层 socket IP 固定（Socket Pinning）的情况下，极端场景仍可能存在 DNS 检查与上游实际发起 TCP 连接之间的毫秒级 TOCTOU 窗口 |
| 仅记录 `args_sha256` 到审计库 | 审计表不保存明文参数 | 彻底避免审计日志本身成为二次秘钥泄露源；排障时需结合应用侧请求 ID 定位具体参数 |

## 3. 明确的非目标与残余风险 (Non-Goals & Limitations)

- **不是操作系统沙箱的替代品**：`mcp-tool-guard` 属于应用层/协议层工具防火墙。如果上游工具运行了恶意本地二进制或自行通过裸系统调用发起网络请求，必须配合容器（Docker / gVisor / Firecracker / Linux namespaces + seccomp）和出站网络防火墙实现纵深防御。
- **不拦截高置信度纯白盒语义社工话术**：对于完全不使用指令覆盖、角色标签、外传词汇、隐匿提示或编码混淆的温和诱导语句，静态规则引擎无法像语义 LLM 裁判那样识别。
- **单向 stdio 协议假设**：当前 `McpSecurityProxy` 围绕标准按行分隔的 JSON-RPC 2.0 stdio MCP 传输设计，暂不直接代理 SSE / Streamable HTTP 远端 MCP 端点。
