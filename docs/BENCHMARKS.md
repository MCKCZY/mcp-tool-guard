# 红队对抗基准评测报告

本文档记录 `mcp-tool-guard` 在六类红队攻击与正常控制集上的定量评测结果。所有测试均通过标准库本地实时执行，不依赖外部网络或在线 API。

## 1. 评测集构成 (`benchmarks/corpus.py`)

共包含 **88 个确定性测试用例**（**61 个攻击载荷** + **27 个易误报的正常工程控制样例**），涵盖：

1. `path_traversal` (12 攻击 / 5 正常): 包含真实临时目录符号链接逃逸（含不存在叶子路径）、`/work` 与 `/work_evil` 路径前缀碰撞、`../`、`.env`、`.ssh/id_rsa`、`*.pem`、`.git/config`、空字节注入，以及正常的同工作区相对路径。
2. `command_injection` (12 攻击 / 5 正常): 包含 `;`/`|`、双引号内 `$(id)` 与反引号、`python3 -c`、`find -exec`、`tar --checkpoint-action`、`curl -d @.env`、`git -c core.sshCommand`、`sudo`、`env rm`、`bash -c`，以及包含引号内管道正则的 `grep -rn "foo|bar" src/` 等正常开发命令。
3. `ssrf` (12 攻击 / 5 正常): 包含 `169.254.169.254`、`[::1]`、`[::ffff:127.0.0.1]`、`[::ffff:169.254.169.254]`、十进制 `2130706433`、十六进制 `0x7f000001`、八进制 `0177.0.0.1`、缩写 `127.1`、`file://`、`@` 用户信息混淆、DNS 重绑定到 `10.0.0.5`，以及合法公网文档 URL。
4. `dlp_secrets` (10 攻击 / 5 正常): 包含 OpenAI/GitHub/AWS/Google/Slack/PEM/JWT/DB URL/Bearer/高熵赋值秘钥，以及 UUID、Git SHA、占位符 `YOUR_API_KEY_HERE`、长路径和中文日志。
5. `prompt_injection` (12 攻击 / 6 正常): 包含中英文指令覆盖、`<|im_start|>system`、`### SYSTEM OVERRIDE`、Unicode Tag (`U+E0000`) 隐写、全角 NFKC 混淆、Base64 编码注入、SSH 私钥外传诱导与隐匿执行，以及 `System Requirements` README、`ignore_errors=True` 代码、合法 Base64 JSON 配置等易误报文本。
6. `dynamic_taint_and_loop` (3 攻击序列 / 1 正常序列): 包含“抓取注入文本后立即执行命令”的动态污点序列、5 连相同调用循环与 62 次突发限流序列。

## 2. 复现命令

```bash
PYTHONPATH=src python3 -m benchmarks.run_redteam
```

## 3. 实测对比结果

### 总体指标

| Strategy | Attacks Blocked (TPR) | Benign Flagged (FPR) | F1 Score | P95 Latency (ms) |
| :--- | ---: | ---: | ---: | ---: |
| `no_guard` | 0/61 (0.0%) | 0/27 (0.0%) | 0.0% | 0.00 |
| `naive_regex_guard` | 16/61 (26.2%) | 2/27 (7.4%) | 40.5% | 0.00 |
| `mcp_tool_guard` | 61/61 (100.0%) | 0/27 (0.0%) | 100.0% | 0.84 |

### 各类别细分 (`mcp_tool_guard` vs `naive_regex_guard`)

| Category | Attacks | Benign | `naive_regex_guard` TPR / FPR | `mcp_tool_guard` TPR / FPR | `mcp_tool_guard` P95 (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `path_traversal` | 12 | 5 | 33.3% / 20.0% | 100.0% / 0.0% | 2.17 |
| `command_injection` | 12 | 5 | 33.3% / 20.0% | 100.0% / 0.0% | 0.69 |
| `ssrf` | 12 | 5 | 50.0% / 0.0% | 100.0% / 0.0% | 0.53 |
| `dlp_secrets` | 10 | 5 | 20.0% / 0.0% | 100.0% / 0.0% | 0.49 |
| `prompt_injection` | 12 | 6 | 0.0% / 0.0% | 100.0% / 0.0% | 0.40 |
| `dynamic_taint_and_loop` | 3 | 1 | 0.0% / 0.0% | 100.0% / 0.0% | 13.62 |

## 4. 结果分析与说明

1. **为何简单正则防护 (`naive_regex_guard`) 在本测试中拦截率仅 26.2%**：
   - 字符串 `startswith` 无法抵御符号链接逃逸和同前缀目录绕过（且会把合法同区路径 `subdir/../src/utils.py` 误判，带来 20.0% 误报）。
   - 单纯封禁 `; | &` 既会误伤带引号正则 `grep -rn "foo|bar" src/`，又漏放 `python3 -c`、`find -exec`、`tar --checkpoint-action` 和双引号内 `$(id)`。
   - 仅检查字面 `127.0.0.1` 漏放全部十进制/十六进制/八进制/映射 IPv6 与 DNS 重绑定。
2. **评测局限说明**：
   上述 `100.0% TPR / 0.0% FPR` 反映的是本仓库内置的 88 个已编码红队与控制样本上的表现，不代表对未来未见变体或纯自然语言社工诱导的绝对防御率。
