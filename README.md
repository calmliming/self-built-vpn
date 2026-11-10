# Self-built VPN

在自有 Ubuntu VPS 上部署供 FlClash / Mihomo 使用的 HTTPS 代理订阅。国内及局域网直连，其余流量通过代理组转发。

- **单机部署**使用 `scripts/manage.py`。初次部署主 VLESS + REALITY 入口，可再发布备用 REALITY、Trojan + TLS、Hysteria2，以及可选的 HTTP / SOCKS5 over TLS。配置和部署步骤见下文。
- **团队管理后台**接入香港、新加坡和美国三台已部署的 VPS。支持成员独立订阅和凭据、按地区同步、启停及撤销、固定出口、节点测速、诊断和操作审计。新成员默认每月 500 GB，按北京时间换月。支持累计额度和不限量。启用三地额度协调后，满额成员的代理会暂停，月度额度刷新后自动恢复。首次接入和运行步骤见 [后台运维说明](backend/README.md)。
- **HTML 交互原型**可直接在本地浏览器打开 [`designs/panel-html/dist/index.html`](designs/panel-html/dist/index.html)。原型使用示例数据和浏览器本地存储。也可运行 `python3 designs/panel-html/preview.py` 后打开终端打印的地址。构建和预览细节见 [原型说明](designs/panel-html/README.md)。

## 单机部署配置

仓库中的 `.env.example` 使用文档示例 IP。首次配置时，复制模板并填入实际参数。

```sh
cp .env.example .env
chmod 600 .env
```

`.env` 已加入 `.gitignore`，真实服务器地址、AWS 标识和 SSH 路径保存在这个文件中。UUID、REALITY 密钥、协议密码和订阅令牌在服务器首次部署时随机生成，重复部署沿用原有凭据。

| 配置项 | 用途 |
| --- | --- |
| `VPN_SERVER_IP` | 服务器公网 IPv4；同时用于 IP 证书、节点地址、订阅 URL 和直连规则 |
| `VPN_SSH_USER` / `VPN_SSH_KEY` / `VPN_SSH_PORT` | SSH 用户、私钥路径和连接端口；密钥保留在本机 |
| `VPN_AWS_REGION` / `VPN_AWS_SECURITY_GROUP_ID` / `VPN_AWS_INSTANCE_ID` | 私有部署记录及说明文档中的 AWS 信息；后两项可留空 |
| `VPN_NODE_PREFIX` | 节点名称前缀，支持中文；`protocol` 样式下额外节点包含对应端口 |
| `VPN_NODE_NAME_STYLE` | `protocol` 显示协议和额外入口的端口。`compact` 按入口从 01 开始编号，启用 HTTP / SOCKS5 时编号继续递增 |
| `VPN_AI_GROUP_NAME` / `VPN_AUTO_GROUP_NAME` / `VPN_RULES_GROUP_NAME` | 日常选择组、自动切换组和隐藏规则下载组的名称，支持中文 |
| `VPN_REALITY_PORT` | 主 REALITY 及 HTTPS 订阅入口，默认 TCP 443 |
| `VPN_REALITY_ALT_PORT` | 额外 REALITY 入口，默认 TCP 20001 |
| `VPN_TROJAN_PORT` | Trojan + TLS，默认 TCP 20002 |
| `VPN_HYSTERIA2_PORT` | Hysteria2，默认 UDP 20003 |
| `VPN_HYSTERIA2_OBFS` | 留空关闭混淆，或填 `salamander`；服务端随机生成并沿用混淆密码，订阅同步携带客户端参数 |
| `VPN_HTTP_PORT` / `VPN_SOCKS5_PORT` | 可选 HTTP / SOCKS5 的 TLS 监听端口；默认 `0` 关闭。启用时自动生成独立账号密码，SOCKS5 仅支持 TCP 转发 |
| `VPN_NGINX_TLS_PORT` | 内部 HTTPS 服务，默认仅监听 `127.0.0.1:8443` |
| `VPN_HEALTHCHECK_URL` / `VPN_HEALTHCHECK_INTERVAL` / `VPN_HEALTHCHECK_TIMEOUT_MS` | 自动切换的检查地址、间隔（秒）、超时（毫秒） |
| `VPN_VERIFICATION_INTERFACE` | 本机用于公网验收的物理网卡，如 `en0` 或 `eth0`。可用 `--interface` 临时覆盖 |
| `VPN_EXPECTED_EXIT_COUNTRY` | 期望出口国家，默认 `US`；留空则只核对出口 IP |
| `VPN_CERTIFICATE_WARNING_HOURS` | 证书剩余有效时间告警阈值，默认 48 小时 |

TCP 端口重复、无效 IPv4、未知变量名、重复赋值或非整数端口等会在执行远程操作前报错。主入口改为非 443 端口时，生成的订阅及规则 URL 自动附带端口。

本地读取顺序为：程序默认值 → `.env` 文件 → 同名 `VPN_*` 进程环境变量。数字会转换为整数后校验，最终参数在本地解析并校验后传输到服务器。也可只设置进程环境变量运行，至少需要 `VPN_SERVER_IP`；未指定文件且 `.env` 不存在时仍可使用这种方式。

支持 `KEY=value`、空值、单/双引号、注释和可选的 `export` 前缀。路径包含空格或 `#` 时使用引号；SSH 私钥路径可用 `~`。配置作为文本读取，不执行 shell 命令，也不展开 `$VAR` / `${VAR}`；不支持多行值。`.env` 的内容不会写入或覆盖进程的 `USER`、`HOME` 等系统变量。

## 本地检查

本地维护端使用 macOS / Linux、Python 3.10+、OpenSSH 和 curl。部署、准备额外入口、发布、规则更新及公网验收还需要 Mihomo。脚本依次查找 PATH 中的 `mihomo` 和 `.runtime/mihomo`，也可传入 `--mihomo /path/to/mihomo`。默认读取项目根目录的 `.env`。

```sh
python3 scripts/manage.py check
python3 -m unittest discover -s tests -v
```

可通过 `--env-file /path/to/private.env` 或 `SELF_VPN_ENV_FILE` 指定其他配置。使用其他文件名时，请自行添加相应 Git 忽略规则。

把 `VPN_VERIFICATION_INTERFACE` 填为本机实际的物理网卡；也可通过 `--interface` 临时指定。验收客户端会关闭自己的 TUN、绑定物理网卡、使用随机本地端口和随机控制接口密码，退出后清理进程及临时配置。

## 服务器准备

脚本面向专用 Ubuntu amd64 服务器，支持 Ubuntu 24.04 和 26.04。需要 Python 3、OpenSSL、systemd、支持 HTTP/2 的 Nginx，以及支持 IP 证书的 Certbot snap。部署时按 Nginx 版本选择 HTTP/2 配置语法，兼容 Ubuntu 24.04 的 Nginx 1.24。固定下载已校验 SHA256 的 Xray 和 Hysteria 版本。

在服务器安装前置软件：

```sh
sudo apt-get update
sudo apt-get install -y python3 nginx openssl snapd zstd
sudo snap install --classic certbot
```

Nginx、证书与系统服务的安装位置由脚本管理；现有网站服务器应先评估端口和 Nginx 默认站点的影响。首次 SSH 连接需先确认服务器主机指纹，用户需能执行 `sudo -n`。

规则校验使用 Python 3.14+ 的 `compression.zstd`；该模块不可用时使用 `zstd` 命令，检查解压完整性、MRS 版本、规则类型及非零规则数量。

按实际配置在服务器防火墙和云防火墙（如 AWS 安全组）放行 SSH、TCP 80、主入口及需要使用的额外入口。内部 Nginx 端口保持仅本机可达。`VPN_AWS_*` 变量仅用于记录部署信息，网络放行规则需单独配置。

## 部署与订阅

所有命令从本地项目目录运行。入口脚本通过 SSH 临时传送所需源文件和配置，远程工作目录结束后清理；部署参数保存为服务器上的 `/etc/self-vpn/deployment.env`，权限为 600。

已纳入团队后台管理的服务器应通过后台同步成员配置。服务器写入 `team-managed` 标记后，单机 CLI 会拒绝 `deploy`、`add-nodes` 和 `publish`，以保护现有成员凭据。

```sh
# 部署主入口、HTTPS 订阅和分流规则
python3 scripts/manage.py deploy

# 准备额外协议，候选订阅暂不公开
python3 scripts/manage.py add-nodes
```

额外节点候选配置位于服务器 `/etc/self-vpn/candidate.yaml`，只允许 root 读取。`add-nodes` 已自动进行公网验收，候选订阅会暂存供审阅。发布时再次验收，然后更新原订阅地址：

```sh
python3 scripts/manage.py publish
python3 scripts/manage.py fetch-client
python3 scripts/write_guide.py
```

完整私人链接保存在 `.secrets/client.json` 和生成的 `使用与维护说明.txt` 中。FlClash 导入链接，选择规则模式；多节点配置在 `US-AI` 中选择 `US-AUTO` 会优先使用 Hysteria2，不可用时依次尝试其他协议，手动选择具体节点也可使用。

节点和策略组可以在 `.env` 中改为中文，例如 `VPN_NODE_PREFIX=美国自建`、`VPN_AI_GROUP_NAME=美国AI`、`VPN_AUTO_GROUP_NAME=自动切换`、`VPN_RULES_GROUP_NAME=规则下载`。名称支持中英文、数字、空格、下划线、连字符和间隔号，长度为 1 至 40 个字符；策略组名称不能重复或使用内置策略名称。改名后执行 `deploy` 更新订阅，DNS、规则和组内引用会同步更新；FlClash 刷新原订阅后重新核对节点选择。仓库示例中的组名均以 `.env` 实际配置为准。

卡片名称过长时可设置 `VPN_NODE_PREFIX=弗州`、`VPN_NODE_NAME_STYLE=compact`，四个入口依次显示为“弗州01～弗州04”。启用或关闭 Hysteria2 混淆后须刷新订阅，让客户端与服务端配置一致；混淆不改变 IP、端口或出口属性，也无法解决所有 UDP 链路限制。

`deploy` 会更新服务，并根据内容变化决定是否重启相关进程。已启用多节点的服务器再次执行 `deploy` 时，会按新参数重建并发布已启用入口的配置。更换 IP 或端口前先调整网络入口，并在维护后重新验证。IP 改变时重新签发匹配的 IP 证书，客户端也需更新订阅地址。

已发布多节点后，更改地址或端口应使用 `deploy` 完成服务和订阅的整体切换；`add-nodes` 会拒绝单独改动这些已发布入口，避免留下旧订阅与新端口不一致的状态。

需要 HTTP 和 SOCKS5 时，将 `VPN_HTTP_PORT`、`VPN_SOCKS5_PORT` 设为两个未占用的 TCP 端口，并在 AWS 安全组放行。它们使用 TLS 和独立账号密码，FlClash 中仍显示为 HTTP / SOCKS5；只支持明文代理的软件可连接 FlClash 的本地混合端口。发布前除正常访问外，还会检查不带凭据和错误密码均被拒绝。

## 验证、回滚与诊断

部署流程为：保存私有快照并持有部署锁 → 校验候选配置 → 更新发生变化的服务 → 本机公网验收 → 发布订阅 → 再次下载核对证书及内容哈希 → 提交变更。

公网验收会逐个验证节点认证、HTTPS 连通性、出口 IP 和国家，并检查两份分流规则加载、DNS 响应及国内网站使用 DIRECT。进程处于 active 状态只是其中一项检查。验收不使用个人 AI API Key，也不验证 AI 账号权限。

校验、下载、证书申请、服务启动、发布前验收或发布后下载失败时，会恢复脚本管理的旧文件、权限及受影响的服务状态。SSH 中断、常规终止和等待验收超过 300 秒也会触发回滚。证书续期定时器在部署期间暂停，结束后恢复，避免同时改动证书文件。

生成的随机凭据会保留用于失败后重试。强制杀死进程或主机重启留下未提交日志时，先运行 `recover` 恢复，再运行 `doctor`；下一次变更操作也会先尝试恢复未提交状态。回滚范围为脚本管理的文件及服务；AWS 网络和公网 IP 的外部变更需要另外处理。

```sh
# 只读诊断：服务、端口、私有监听、证书、续期、部署日志、HTTPS 订阅
python3 scripts/manage.py doctor

# 通过独立客户端验证当前公开节点与分流
python3 scripts/manage.py verify

# 需要时单独复查尚未发布的候选节点
python3 scripts/manage.py verify --candidate

# 恢复上次中断或未完成的变更，再检查服务
python3 scripts/manage.py recover
python3 scripts/manage.py doctor

# 独立更新国内规则，并通过实际 Mihomo 加载和公网验收
python3 scripts/manage.py update-rules
```

内容和版本未变化时跳过程序重装与服务重启；独立规则更新不重启代理或 Nginx。规则更新会先下载并校验两份文件，再切换，并在客户端实际加载失败时恢复旧规则。上游不可达时保留现有规则。尚未安排无人值守的规则更新任务。

服务端私有快照与状态日志保存在 `/etc/self-vpn/backups/transaction-*/manifest.json`；本机 `.runtime/last-deployment.log`、`.runtime/last-verification.log` 及 `.secrets/last-verification.json` 保存维护记录，均被 Git 忽略。

所有入口共用同一服务器和出口 IP，整个 IP 不可达时会同时受影响。各入口的协议及端口差异不改变出口 IP 的信誉或机房属性。

多节点配置使用隐藏的 `US-RULES` 回退组下载分流规则，优先 Hysteria2，其次 Trojan、REALITY 和其他已启用入口；日常流量仍由 `US-AI` / `US-AUTO` 选择。这可避免较大的规则文件在慢速 TCP 链路上触发下载超时。当前配置检查读取服务器实际发布的订阅，不根据本地新代码替代重建旧配置。

## 提交前检查

仓库包含前后端源码、依赖锁文件、数据库迁移、部署脚本、测试和 HTML 原型。按本次改动选择需要暂存的文件。私有配置、`.env`、`.secrets/`、`.runtime/`、私钥、导出的订阅及生成的私人说明由 `.gitignore` 排除。

在现有 Git 仓库中启用提交钩子，并审阅暂存内容。

```sh
git config --local core.hooksPath .githooks
python3 scripts/check_public_files.py
git diff --cached --stat
git diff --cached
```

检查脚本扫描 Git 索引中的文件内容，检测已知私有配置值、非示例公网 IPv4、AWS 标识、私人订阅路径、UUID、私钥和个人主目录路径，并验证私有文件的忽略规则。首次发布到公共仓库前还应审阅将推送的提交历史。

提交钩子通过敏感信息扫描后，会在临时目录对 Git 索引快照运行 `tests/` 下的离线单元测试。也可直接运行 `.githooks/pre-commit` 检查待提交快照。后端测试和前端构建命令见 [后台验证说明](backend/README.md#验证)。

## 目录

```text
.env.example                   可公开的示例配置
.env                           本机真实配置（忽略）
frontend/                       React / TypeScript 管理界面
backend/                        FastAPI、数据库迁移、后台执行器和测试
designs/panel-html/              独立 HTML 交互原型
scripts/settings.py             参数读取、校验与公共配置接口
scripts/manage.py               本地 SSH 部署入口
scripts/operations.py           原子写入、部署锁、快照及恢复
scripts/server_agent.py         服务端发布握手与诊断
scripts/verification.py         本机独立客户端公网验收
scripts/routing_rules.py        分流规则下载、校验与独立更新
scripts/deploy_server.py        主节点、HTTPS 和分流部署
scripts/add_protocol_nodes.py   额外协议与候选订阅发布
scripts/team_agent.py           团队成员同步与订阅发布
scripts/traffic_stats.py        VPS 代理流量采样
scripts/quota_control.py        跨地区额度协调与限额执行
scripts/write_guide.py          生成私人使用说明
scripts/check_public_files.py   暂存区敏感信息检查
scripts/pre_commit.py           对暂存快照运行扫描和测试
.githooks/pre-commit            Git 提交钩子
tests/                         配置、故障恢复、发布握手和提交检查测试
.secrets/                      客户端备份与测试记录（忽略）
.runtime/                      临时运行文件（忽略）
```

## 参考资料

- [Certbot 官方安装说明](https://certbot.eff.org/instructions?ws=nginx&os=snap)
- [Let's Encrypt IP 地址证书说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- [Hysteria2 服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Xray 官方发布](https://github.com/XTLS/Xray-core/releases)
