# Self VPN 团队管理后台

React + TypeScript + Vite 前端，FastAPI / Pydantic API，SQLAlchemy + SQLite 数据，Alembic 迁移。管理端在本机运行，通过既有 SSH 密钥连接三台 VPS。每位成员的 HTTPS 订阅静态托管在美国 VPS；管理端关闭不影响已部署节点、节点认证和已发布订阅。

## 运行

从项目根目录执行（Python 3.12+，Node 使用满足锁定 Vite 版本要求的版本）：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.lock
npm ci --prefix frontend
npm run build --prefix frontend
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 55139 --no-access-log
```

打开 `http://127.0.0.1:55139/#/overview`。首次启动从 `.secrets/aws-vps-20261103/inventory.json` 及各地区 `.env` 导入三台现有服务器，生成管理员和独立订阅，随后执行真实公网验收。首次管理员账号密码保存在 `.secrets/panel/管理员登录.txt`；登录后可在系统设置修改密码。一次性预览登录码仅用于本机预览交接，首次使用后失效，未使用时一小时过期。

前端开发可运行 `npm run dev --prefix frontend`。生产构建由 FastAPI 提供 `/` 和 `/assets/`，开发代理转发 `/api` 到本机 55139 端口。后台保持同源部署。

默认由 API 启动独立执行器进程。Linux 长期运行时可分别托管 API 与执行器：设置 `SELF_VPN_WORKER_EXTERNAL=1`，分别运行上述 Uvicorn 命令和 `.venv/bin/python -m backend.app.worker`，示例 systemd 单元见 `deploy/`。执行器通过文件锁保证唯一，启动时重新核对中断的持久化任务。

## 已接入的真实功能

- 管理员登录、成员登录、管理员/成员权限、密码修改与成员登录密码重置。
- 新建成员，按地区授权，成员独立订阅及各地区独立协议凭据。
- 单独停用、重新启用、删除成员；按服务器展示同步状态并重试。
- 重置链接仅更换订阅地址；重置全部凭据同时更换链接及全部节点凭据。
- 真实 SSH 服务诊断、内存/磁盘/负载/证书状态，每两分钟采集。
- 自动组优先各授权地区的 Hysteria2，再按地区顺序尝试 REALITY、Trojan、HTTP、SOCKS5；单地区组同样优先 Hysteria2。
- 分流规则可固定个人出口地区。固定美国时，个人订阅仅包含美国六个入口；自动回退和规则下载均限定美国。仅重新发布客户端订阅，不轮换凭据或重启服务器认证。选择固定地区后不能移除其授权，须先更改出口策略。
- 节点管理提供实际下载测速：管理员手动按全部或单地区启动，从管理后台物理网卡经各节点下载 Cloudflare 测试文件。每节点最多 3 MB、12 秒，全部 18 个入口最多 54 MB，串行采样，任务可查看进度及重试。Mbps 按已下载字节和总耗时计算，明确区分完整下载、限时采样和失败；保留每个管理员每节点最近一次结果。测速不改变客户端选择，不代表其他成员网络或长期带宽。
- 逐地区六入口公网验收、TLS、出口、DNS、国内直连；持久化任务和操作审计、CSV 导出。
- 成员只读取自己的订阅和任务；后台仅绑定回环地址，朋友通过公开 HTTPS 订阅使用节点。

## 同步与撤销语义

每个服务器成员记录对应独立 VLESS UUID、Trojan 密码、Hysteria2 认证串、HTTP/SOCKS5 账号密码。主/备用 REALITY 在同一服务器内共用该成员 UUID。REALITY 公钥、short ID、证书和 HY 混淆参数属于服务器公共参数。

每次更新持有服务器原有部署锁，备份管理文件、校验 Xray 配置，应用候选配置并从管理端物理网卡运行隔离 Mihomo 客户端。公网验收通过后发出提交，失败/SSH 中断恢复原文件与服务。每个地区独立提交，离线或未通过地区标记待同步；不会提前宣布撤销完成。管理端任务按顺序执行，数据库唯一索引阻止同成员并发覆盖。

两个 Xray 服务受控重启以落实所有协议的存量连接撤销，同地区其他连接可能短暂重连。HY 使用每台 VPS 本机的 `self-vpn-team-auth` 服务识别独立认证串；文件只保存高熵认证串的 SHA256。更新认证后通过仅监听回环地址、带独立管理密码的 Hysteria Traffic Stats `/kick` 断开被撤销或轮换成员的已有 QUIC 会话。

原单用户凭据和已分享测试订阅保留，后台不会把原 owner 密码或订阅令牌放进成员配置。成员规则使用公开 MRS 专用路径。更新自动策略可使用 `republish` 任务，仅重新验收并发布现有成员订阅；`team_agent` 的 `prioritize` 操作重排已存在的 owner 单区 / 三地订阅；可选 `restrict_automatic_exit` 将旧三地订阅的自动组及规则下载限制为当前 VPS，保留手动节点选择，失败自动回滚，均不重启代理服务。客户端须刷新订阅并选择自动组或地区组，手动选中的单个 TCP 节点不会因服务端更新自动切换。

团队服务器写入 `team-managed` 标记后，旧 CLI 的 `deploy/add-nodes/publish` 拒绝覆盖团队认证，`doctor/verify/export-current/update-rules/recover` 仍可使用。升级核心或改变端口须同时维护团队配置生成器。

## 私有数据与恢复

`.secrets/panel/`（目录 700）保存数据库（600）、加密主密钥（600）和初始登录信息。节点凭据、订阅令牌、旧凭据验收上下文均使用 Fernet 加密；登录密码使用带随机盐的 scrypt，登录 cookie 只存服务端摘要，使用 HttpOnly / SameSite=Strict，并校验变更请求 CSRF 和来源。HTTPS 托管时 cookie 自动设置 Secure。

备份必须同时保留 SQLite 一致性快照与 `master.key`，并保留各服务器私人配置/主机指纹/SSH 密钥。在线数据库请使用 SQLite backup API，不能只复制活动中的 `panel.db` 而遗漏 WAL。不要将私有数据复制到 `frontend/dist/`、Git 或公共站点。`.runtime/panel/tasks/` 保存每个任务的私人验收记录；服务器事务快照沿用 `/etc/self-vpn/backups/`。

后台关闭时，已发布订阅继续可下载。新增、撤销、轮换和定时采集需要管理进程与执行器运行。

## 验证

```sh
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python -m pytest backend/tests -q
npm run build --prefix frontend
```

离线 API 测试使用独立临时数据库，不启动真实执行器、不访问服务器。`backend/tools/live_acceptance.py` 为显式的真实验收脚本：创建两个临时成员，验证独立权限、三地连接、两种轮换、停用、其他成员和 owner 不受影响，最后撤销并删除临时成员；结果保存在私人 `.runtime/panel/live-acceptance-*/report.json`。它会更新三台真实服务器的成员配置，仅应在需要执行这套验收时运行。

界面源码在 `frontend/src/`；保留约 28–32px 大圆角，采用半透明玻璃表面与背景模糊，Lucide 图标使用扁平线性风格。历史 `designs/panel-html/` 保留为旧版交互原型。
