# 持有证明登录服务（P-256 挑战签名 + 并发密码猜测限制）

FastAPI + SQLite(WAL) + argon2-cffi + cryptography 实现的登录演示。两个独立 Web
进程共享同一 SQLite 数据库，同时提供两层防护：

1. **密码猜测限额（原能力保留）**：同一员工账号 60 秒窗口内「已完成错误 + 在途
   核验」合计上限 5，核验前原子占位，满额立即 429 且不做哈希，客户端断连不能绕过。
2. **Cookie 冒用防护（新增）**：浏览器持有不可导出的 ECDSA P-256 私钥，登录时
   提交公钥并绑定会话；`/api/me`、`/api/logout` 必须先领随机挑战再提交 ECDSA
   签名。只复制到 Cookie、或重放别人的签名，都无法通过。

## 快速启动（Docker Compose）

```bash
docker compose up --build
```

启动后浏览器打开：

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 主入口（Nginx 轮询两个进程） | http://localhost:8080 | 推荐，请求在 web1/web2 间轮询 |
| 直连进程 1 | http://localhost:8001 | 响应头 `X-Served-By: web1` |
| 直连进程 2 | http://localhost:8002 | 响应头 `X-Served-By: web2` |

预置账号（数据库中**只存 argon2id 哈希**，页面展示明文仅为演示方便）：

- `alice` / `alice-pass-2026`
- `bob` / `bob-pass-2026`

停止与清理：

```bash
docker compose down          # 停止；命名卷 login-db 保留，会话/挑战/窗口错误持久存在
docker compose down -v       # 连数据库卷一起删除，下次启动重新预置
```

## 持有证明（PoP）协议

### 密钥与登录

1. 页面加载时用 Web Crypto 生成 `ECDSA P-256` 密钥对，**私钥 `extractable=false`**，
   私钥句柄存入 **IndexedDB**（同源标签页共用，刷新页面不重新生成；JS 无法读出私钥字节）。
2. `POST /api/login` 的 JSON 增加 `public_key`（Web Crypto raw 导出的 65 字节未压缩
   点，base64url）。密码核验通过后，新会话行与该公钥在**同一事务**中写入并绑定。
3. 旧版本遗留的、未绑定公钥的会话行（`bound=0`）在所有鉴权接口上一律 401，必须重新登录。

### 签名请求（/api/me、/api/logout）

```text
POST /api/challenge   { "purpose": "me" | "logout" | "demo_token" }
  → { challenge, purpose, method, path, expires_at, ttl_seconds: 60 }
GET  /api/me          头: X-Auth-Challenge: <挑战>
                           X-Auth-Signature:  <base64url ECDSA r||s>
POST /api/logout      头: X-Auth-Challenge / X-Auth-Signature（purpose=logout）
```

- 挑战为 256 位 CSPRNG 随机数，**绑定会话 + 用途 + 方法 + 路径**，有效期 **60 秒**。
- 挑战 id 与签名通过请求头传输，因此受保护接口保持自然的 HTTP 方法，
  签名覆盖的（方法, 路径）与实际请求行完全一致。
- 签名消息为长度前缀拼装，覆盖挑战、HTTP 方法与路径：

  ```text
  len(challenge):challenge|len(METHOD):METHOD|len(path):path|
  例如 64:<256bit挑战>|3:GET|7:/api/me|
  ```

- 签名算法 `ECDSA-SHA256`，线格式为 Web Crypto 原生的 64 字节 `r||s`（base64url）。
- 裸 `GET /api/me`（只有 Cookie、没有 `X-Auth-*` 头）始终返回 401。

### 服务端裁决要点（与需求逐条对应）

| 需求 | 实现 |
| --- | --- |
| 只有 Cookie 或重放签名均拒绝 | 裸 GET 401；签名接口要求挑战一次性消费，重放 401 |
| 挑战 60 秒有效、随机、绑定会话及用途 | `auth_challenges` 表；`purpose` 仅允许 `me`/`logout`，各自固定 (method, path) |
| 多标签互不覆盖 | 领挑战只 `INSERT` 新行，从不动其它未消费挑战；两个标签各拿各的挑战，各自可用 |
| 同挑战并发仅一次成功（两个 Web 进程共享状态） | 消费在单个 `BEGIN IMMEDIATE` 事务内 `UPDATE ... WHERE consumed_at IS NULL`，WAL 写锁跨进程串行裁决，`rowcount!=1` 即失败 |
| 验签不持数据库写锁 | 先只读查挑战，再在事务外做 ECDSA 验签；通过后才开短写事务消费 |
| 提交时重新检查会话仍有效 | 消费事务内再次 `SELECT ... sessions ... expires_at > now AND bound=1`，会话已注销则拒绝且不消费 |
| 挑战消费与身份授权/注销一起提交 | 同一个事务内更新挑战、（logout 时）删会话及该会话全部挑战 |
| 验签失败不消费挑战 | 签名错误直接 401，不进入写事务；同一挑战随后用正确签名仍可成功 |
| 注销后迟到验签不得恢复访问 | 注销事务删除会话行；之后任何请求在会话重检处即 401，已删挑战也无法复活 |
| 新会话及挑战重启保留 | 会话/挑战是普通已提交行，启动钩子不清理；只惰性删除**已过期**挑战与在途占位 |
| 旧的未绑定会话拒绝使用 | 迁移把无公钥行标记 `bound=0`；会话查询与挑战发放都只接受 `bound=1` |

### 数据库结构（SQLite，WAL）

```text
accounts         id, username UNIQUE, password_hash(argon2id), created_at
login_errors     account_id, created_at            -- 按完成时刻记录，窗口外惰性清理
login_inflight   slot_id PK, account_id, acquired_at  -- 原子占位，重启清空
sessions         token PK, account_id, created_at, expires_at,
                 public_key(P-256 未压缩点 hex), bound(1=已绑定)
auth_challenges  id PK, session_token, purpose, method, path,
                 created_at, expires_at, consumed_at  -- 一次性，过期惰性清理
```

## HTTP 接口

- `GET /` — 演示网页（密钥状态、签名登录/刷新/注销、Cookie 复制演示、并发重放演示、密码限额演示）
- `POST /api/login` — body `{username, password, public_key, delay}`；成功 200 下发 HttpOnly Cookie；失败 401；满额 429（`Retry-After`）；非法公钥 400 且不占名额
- `POST /api/challenge` — body `{purpose}`（`me` / `logout` / `demo_token`）；需有效绑定会话 Cookie，返回 60 秒随机挑战
- `GET /api/me` — 头 `X-Auth-Challenge` / `X-Auth-Signature`；消费 `me` 挑战后返回身份；缺头或仅 Cookie → 401
- `POST /api/logout` — 同样两个签名头（purpose=`logout`）；消费挑战并在同一事务注销
- `GET /api/demo/session-token` — 经 `demo_token` 签名校验后返回当前 Cookie 明文，供复制 Cookie 演示
- `GET /api/stats` — 每个账号的窗口错误数、在途数、剩余名额

所有响应带 `X-Served-By`（web1/web2）与 `X-Process-Time-ms`。

## 网页演示

页面上有两个内置安全演示面板：

- **演示 A（复制 Cookie）**：登录后点「签名取回我的 Cookie」→ 把值粘到「无密钥客户端」。
  点 GET /api/me 得到 401；领挑战后用随机伪造签名调注销同样 401，且同一挑战可反复尝试
  （验签失败不消费）。面板还生成可直接粘贴到另一台机器的 `curl` 命令。
- **演示 B（并发重放）**：领取**一个**挑战、生成**一份**签名，一键并发提交 8 份到
  `/api/me`，预期恰好 1 个 200、7 个 401；请求经 Nginx 轮询落到 web1/web2，验证跨进程
  原子消费。

密码限额演示保持原样：6 并发错误密码第 6 个立即 429、AbortController 中途断开后服务端
仍完成核验与结算。

## 本地无 Docker 时运行（开发/测试）

```bash
pip install -r requirements.txt
export LOGIN_DB_PATH=/tmp/login.db
uvicorn app.main:app --port 8001                 # 终端 A
PROCESS_NAME=web2 uvicorn app.main:app --port 8002   # 终端 B，同一 DB 文件
```

## 测试

```bash
python tests/smoke_pop.py          # 单进程 PoP 协议冒烟测试（15 组）
python tests/run_integration.py    # 双进程完整集成测试（11 组，含原限额与断连结算）
```

集成测试在本机拉起两个共享同一 SQLite 文件的 uvicorn 进程，覆盖：原子占位/429 不哈希、
滑窗恢复、断连结算、交错完成、重启语义（会话与未过期挑战保留、旧会话拒绝）、无明文存储、
Cookie-only 拒绝、挑战单次使用、跨进程并发重放仅一次成功、验签失败不消费、用途/密钥绑定、
注销原子性与多标签挑战隔离等。测试通过环境变量 `ERROR_WINDOW_SECONDS` / `MAX_SLOTS`
把窗口缩短为 5 秒以便验证；生产默认值为 60 秒 / 5，挑战 TTL 固定默认 60 秒。

## 可调环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `LOGIN_DB_PATH` | `/data/login.db` | SQLite 文件路径（两进程必须指向同一文件） |
| `ERROR_WINDOW_SECONDS` | `60` | 密码错误计数滑动窗口 |
| `MAX_SLOTS` | `5` | 每账号窗口错误 + 在途的合计上限 |
| `MAX_DELAY_SECONDS` | `10` | 演示用核验延迟上限 |
| `SESSION_TTL_SECONDS` | `3600` | 会话有效期 |
| `CHALLENGE_TTL_SECONDS` | `60` | PoP 挑战有效期（规格固定 60 秒） |
| `PROCESS_NAME` | `login` | 标识进程，体现在 `X-Served-By` |
