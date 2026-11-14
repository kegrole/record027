# corsaudit — CORS 规则 / 请求 / 预检响应一致性审计器

只使用 Python 标准库，把分散在框架默认值、环境变量、手写中间件里的 CORS 策略
统一成一份规则文件，与请求、预检响应放在一起审计，输出可核对的判定报告。

## 运行

```bash
python -m unittest test_corsaudit -v          # 在 tests/ 目录下运行全部测试
python -m corsaudit.cli --rules demo/cors_rules.json --requests demo/requests.json --out out/report.json
```

demo 命令跑完会在 stdout 打印一行摘要（规则数、请求数、评估数、问题数、拒绝数），
并把完整报告写入 `--out` 指定的 JSON 文件。

## 配置项

每条规则（`demo/cors_rules.json`）包含：

| 字段 | 含义 |
| --- | --- |
| `rule_id` | 规则标识，报告按它字典序排序 |
| `allowed_origins` | 允许的 origin 列表，支持五种形态（见下） |
| `allowed_methods` | 允许的方法，大小写不敏感 |
| `allowed_headers` | 允许的请求头，大小写不敏感 |
| `exposed_headers` | 暴露给前端的响应头 |
| `allow_credentials` | 是否允许携带凭证 |
| `max_age` | 预检缓存秒数，参与边界校验 |

请求（`demo/requests.json`）字段：`origin`、`method`、`request_headers`（预检想用的头）、
`headers`（实际请求头，如 Cookie）、`response.headers`（模拟的预检响应头）。

## Origin 五种形态的匹配语义

所有匹配基于 **(scheme, host, port) 三元组** 与 **通配分量对齐** 实现，
不做任何字符串前后缀比较。scheme 与 host 统一小写后比较。

1. **精确匹配**：`https://app.example.com`。scheme、host、有效端口三项全等才命中。
2. **子域通配**：`*.example.com`。`*` 只占一个分量，规则与请求的 host 按 `.`
   切分后分量数必须相等，再逐分量比对（`*` 匹配任意单个分量）。
   可带 scheme（`https://*.example.com`）与端口（`*.example.com:8443`）。
3. **任意星号**：`*`，命中任何非 null 的 origin。
4. **null**：`null`，只与请求 origin 为字符串 `null` 的情形配对（见 null 三态）。
5. **正则表达式**：两种写法——前缀写法 `^https://app\\.example\\.com$`（`re.match` 语义），
   包裹写法 `/^https:\\/\\/app\\.example\\.com$/`（`re.fullmatch` 语义）。
   正则作用于请求 origin 的**原始字符串**，**默认大小写敏感**：
   请求 `HTTPS://APP.EXAMPLE.COM` 能命中精确/通配规则（解析后统一小写），
   但**不会**命中正则规则，除非正则自带 `(?i)` 标志。

## 通配分量对齐

- `*.example.com` 命中 `app.example.com`，**不**命中 `example.com`（少一个分量）、
  `a.b.example.com`（多一个分量）、`evil.example.com.attacker.net`（跨点域名，分量对不齐）。
- `*.*.example.com` 命中 `a.b.example.com`，**不**命中 `a.example.com`。

## 默认端口等价

端口按 scheme 补默认值（http→80、https→443、ws→80、wss→443）后再比较：

- `https://app.example.com` 与 `https://app.example.com:443` 视为同一 origin。
- `http://app.example.com:443` 与 `https://app.example.com:443` **不**匹配——
  端口相同不能抵消 scheme 不同。

## 凭证与星号互斥的三种情形

规则 origin 配 `*` 时，按三种情形分别报告：

- `wildcard_with_credentials`：星号 + `allow_credentials: true`，危险配置。
- `wildcard_with_cookie_request`：星号 + 请求携带 `Cookie` 头。
- `wildcard_without_vary`：星号 + 响应缺少 `Vary: Origin`。

## null 三态

请求 origin 为 `null` 时：

- 规则允许凭证 → 一律拒绝（`null_with_credentials`）。
- 规则为 `null` 且不允许凭证 → 允许，reason 注明 `null_origin_allowed`。
- 规则为 `*` → 拒绝，报 `null_with_wildcard`。
- 规则为精确/通配/正则 → 拒绝，报 `null_with_exact`。

## 预检回显与 Vary 的四种组合

规则允许凭证时检查预检响应的 `Access-Control-Allow-Origin` 回显与 `Vary`：

| 回显 | Vary: Origin | 结果 |
| --- | --- | --- |
| 精确 origin | 有 | 通过 |
| `*` | 有 | `echo_wildcard_with_credentials` |
| 精确 origin | 缺 | `missing_vary` |
| `*` | 缺 | 两条都报 |

## 缓存秒数边界

`Access-Control-Max-Age`（响应头与规则配置 `max_age` 都校验）：

- `> 86400` → `max_age_too_large`
- `< 0` → `max_age_negative`
- 无法解析为数字 → `max_age_invalid`
- 缺省不报；`86400` 本身合法。

## 方法与请求头判定

- 大小写不敏感：配置写 `post` 与请求写 `POST` 是同一项。
- 两个维度拆开判定：方法不在允许列表报 `method_not_allowed`；
  请求头有超集报 `header_not_allowed` 并在理由里点名具体的头；
  两者都越界时报两条独立问题。

## 报告格式、排序与去重

`out/report.json` 含 `summary`、`evaluations`、`issues` 三段。

- 每条评估含 `rule_id`、`request_origin`、`allowed_methods`、`credentials`、
  `decision`（allow/deny）、`reason`、`issues`。
- `reason` 为空串只允许出现在无问题的评估上；有问题时是排序后的问题类型列表；
  null 放行时注明 `null_origin_allowed`。
- 评估按 `(rule_id, request_origin)` 字典序排序；
  问题清单按 `(rule_id, request_origin, issue_type)` 字典序排序。
- 同一 `(rule_id, request_origin, issue_type)` 只出现一次，重复命中的理由合并。
- 每条问题都带人可读的理由。

## 目录结构

```
corsaudit/    config.py origin.py rules.py preflight.py report.py cli.py __main__.py
demo/         cors_rules.json requests.json
tests/        test_corsaudit.py
```

