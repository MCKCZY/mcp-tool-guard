# 系统架构说明

`mcp-tool-guard` 在模型/智能体客户端与底层工具/MCP Server 之间插入一道独立的进程级（或函数级）安全网关。与把安全要求写进 System Prompt 不同，所有规则裁决、符号解析、秘钥脱敏和动态污点拦截均在模型推理上下文之外确定性执行。

## 1. 双向拦截流水线

```text
  [Agent / LLM Client]
          |
          |  JSON-RPC 2.0 (tools/list, tools/call)  或 Python SDK 调用
          v
+-------------------------------------------------------------------------+
| mcp-tool-guard (McpSecurityProxy + ToolGuardEngine)                     |
|                                                                         |
|  [1] tools/list 过滤: 按 allowed_tools / denied_tools 隐藏高危工具      |
|  [2] Ingress 入口检查 (check_call):                                     |
|      Policy & Schema -> Dynamic Taint Sink -> Rate & Loop Breaker       |
|      -> path_guard (realpath 逃逸与前缀碰撞)                             |
|      -> command_guard (双引号内 $()、包装器穿透、GTFOBins 参数)         |
|      -> ssrf_guard (十进制/八进制/十六进制/IPv4-mapped/NAT64/6to4/DNS)   |
|      -> dlp_guard (禁止敏感凭据随出站参数泄露)                           |
|  [3] Pipelined Causal Barrier (wait_for_inflight_calls):                |
|      确保第 N 次调用的 Egress 污点状态更新先于第 N+1 次 Ingress 检查     |
|  [4] Egress 出口净化 (filter_result):                                   |
|      字节截断 -> dlp_guard 脱敏 -> injection_guard 检测 & 激活污点 TTL  |
|  [5] AuditLog (SQLite WAL + SHA-256 前向哈希链, 只存参数 SHA256 摘要)   |
+-------------------------------------------------------------------------+
          |                                           ^
          |  仅放行通过校验的请求                      |  原始响应文本
          v                                           |
  [Upstream Stdio MCP Server / Python Tool Callable]
```

## 2. 六大安全守卫模块 (`src/mcp_tool_guard/guards/`)

1. **`path_guard.py`**:
   - 对相对路径与用户目录 `~` 展开后通过 `os.path.realpath()` 规范化（即便目标叶子文件尚不存在，也会沿现有目录符号链接逐级解析真实落点）。
   - 使用 `Path.is_relative_to()` 校验根目录包含关系，彻底消除 `/tmp/work` 与 `/tmp/work_evil` 之间的字符串前缀碰撞漏洞。
   - 同时检查逻辑路径与真实解析路径是否命中 `.env`、`.ssh`、`id_rsa`、`*.pem`、`.git/config`、`/etc/passwd` 等敏感模式。

2. **`command_guard.py`**:
   - 按引号状态机扫描字符串命令：单引号外（包括双引号内部）出现 `$(...)`、`$` + `{` 或反引号一律拦截（因为 POSIX Shell 在双引号内仍会展开命令替换）；引号外出现 `;`、`|`、`&`、`>`、`<`、`(`、`)` 与控制符换行即拒绝，同时允许如 `grep -rn "foo|bar" src/` 这类安全带引号正则。
   - 通过 `shlex.split` 解析 argv 并穿透 `env`、`nohup`、`timeout`、`nice`、`xargs` 等包装器提取底层可执行文件，阻断 `sudo`/`sh`/`bash`/`zsh`/`powershell` 包装及 `python -c`、`find -exec`、`tar --to-command`、`git -c core.sshCommand=...`、`curl -d`、`awk system()` 等常见 GTFOBins 提权与外传参数。

3. **`ssrf_guard.py`**:
   - 拦截非白名单协议（`file://`、`gopher://`、`ftp://`、`data:`）与 `@` 用户凭据权威混淆（`http://trusted.com@127.0.0.1/`）。
   - `_parse_obfuscated_ip()` 统一解码十进制整数（`2130706433`）、十六进制（`0x7f000001`）、八进制（`0177.0.0.1`）、两/三段缩写（`127.1`、`169.254.43518`）、IPv4 映射 IPv6（`[::ffff:127.0.0.1]`）、NAT64（`64:ff9b::/96`）及 6to4（`2002::/16`）内嵌 IPv4 地址。
   - 启用 `resolve_dns=True` 或注入自定义解析器时，对返回的全部 A/AAAA 记录复检内网、环回、CGNAT（`100.64.0.0/10`）与云元数据 IP（`169.254.169.254` 等），阻断 DNS 重绑定攻击。

4. **`dlp_guard.py`**:
   - 结合前缀特征规则（OpenAI/Anthropic/GitHub/AWS/Google/Slack/JWT/PEM/带密码数据库 URI/Bearer Token）与上下文赋值式高熵检测（Shannon 信息熵 >= `4.3` bits/char，过滤 UUID 与占位符），统一替换为不可逆摘要占位符 `[REDACTED:<KIND>:<sha256[:6]>]`。

5. **`injection_guard.py`**:
   - 先对不可见控制字符进行解码与折叠：识别并还原 Unicode Tag 区块（`U+E0000..U+E007F`）隐藏文本、清理零宽字符与双向控制符、应用 NFKC 规范化，并尝试严格解码嵌入的 Base64 UTF-8 载荷。
   - 对原文与还原文本运行多类别中英双语加权规则（指令覆盖、角色边界劫持、凭据外传诱导、隐匿执行、混淆加权），输出 `[0.0, 1.0]` 置信分并在命中时激活会话污点窗口。

6. **`rate_guard.py`**:
   - 维护 60 秒滑动窗口 RPM 计数器与工具调用参数规范哈希序列，检测连续重复或窗口高频循环调用。

## 3. 管道串行化防竞态与防篡改审计

- **管道串行屏障 (`McpSecurityProxy.wait_for_inflight_calls`)**：若客户端连续打包发送两条 `tools/call`（例如先读外部网页再调 `run_cmd`），代理层会等待前一次 `tools/call` 完成响应扫描与污点状态更新后再放行下一条入站检查，避免并发流水线竞态绕过动态污点追踪。
- **SHA-256 哈希链审计账本 (`audit.py`)**：所有入口与出口裁决写入 SQLite WAL `audit_events` 表，仅记录规范参数的 SHA-256 摘要与脱敏后的命中元数据，绝不落盘原始秘钥；`audit-verify` 可随时检验日志是否被截断或篡改。
