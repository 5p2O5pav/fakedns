# DSDNS - 轻量级 DNS 权威服务器

一个基于 Go 语言的轻量级智能 DNS 系统，根据请求来源 IP 的地理位置（含运营商）返回不同的解析记录。支持 A/AAAA/CNAME 记录，内置 Web 管理界面，使用 SQLite 存储，可编译为单二进制文件运行。

## 功能特性

- 🌍 **按区域/运营商智能解析**：根据 ECS（EDNS Client Subnet）或源 IP 判断归属，返回定制记录。支持中国大陆三大运营商、广电、教育网、港澳台、各大洲共 15 个区域。
- 🧠 **IP 归属判断**：使用 `ip2region`，回退“默认”，并带有内存缓存。
- 📦 **单二进制部署**：使用 `modernc.org/sqlite`（纯 Go，无 CGO），前端静态资源通过 `embed` 嵌入，编译后只有一个可执行文件。
- 🔐 **用户系统**：首次启动自动开启管理员注册，之后管理员可添加普通用户，所有用户均可管理自己的域名。
- 🎛️ **Web 管理面板**：基于 Tailwind CSS 的响应式界面，支持域名增删改查、区域记录配置（A/AAAA/CNAME）、用户管理（管理员）。
- 🛡️ **防攻击**：只应答已配置的域名，否则返回 `NXDOMAIN`，避免 DNS 放大攻击。
- ⚙️ **灵活配置**：YAML 配置文件，指定监听端口、数据库路径、外部 IP 库文件、JWT 密钥等。

## 快速开始

### 前置要求
- Go 1.22 或更高版本（编译用）
- 一个 Linux 服务器（推荐 Debian/Ubuntu）
- 需要下载两个离线 IP 数据库文件：

```bash
cd /root/dsdns && \
wget -O ip2region_v4.xdb https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb && \
wget -O ip2region_v6.xdb https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb

```

### 编译
```bash
# 克隆仓库
git clone https://github.com/5p2O5pav/dsdns.git
cd dsdns

# 下载依赖
go mod tidy

# 编译（自动嵌入前端静态文件）
go build -o dsdns .
```

编译后得到二进制文件 `dsdns`，可直接运行。

### 运行
1. 修改配置文件 `config.yaml`（参见下方配置说明）。
2. 将 `ip2region.xdb` 和 `GeoLite2-Country.mmdb` 放到配置指定的路径（默认项目根目录）。
3. 启动服务：
   ```bash
   ./dsdns config.yaml
   ```

服务默认监听：
- DNS：UDP/TCP  `5353`（可通过 iptables 转发 53 端口）
- Web 管理：`8080`

### 端口转发（可选，使 DNS 监听 53 端口）
如果希望 DNS 直接使用标准 53 端口：
```bash
# 方法一：使用 setcap 赋予权限（推荐）
sudo setcap 'cap_net_bind_service=+ep' ./dsdns
# 然后将 config.yaml 中 dns.listen 改为 ":53"

# 方法二：通过 iptables 转发
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5353
```

## 配置文件详解 (`config.yaml`)

```yaml
dns:
  listen: ":5353"               # DNS 监听地址端口
web:
  listen: ":8080"               # Web 管理界面监听端口
db:
  path: "./dsdns.db"           # SQLite 数据库文件路径
geo:
  ip2region: "./ip2region.xdb"          # ip2region xdb 文件路径
  geoip2:   "./GeoLite2-Country.mmdb"   # MaxMind Country mmdb 文件路径
jwt:
  secret: "change-me-to-a-random-string"   # JWT 签名密钥（务必修改！）
  expire_hours: 24
cache:
  geo_ttl_sec: 300              # IP 地理结果缓存时间（秒）
```

## 使用指南

### 首次启动与注册
- 启动服务后，打开浏览器访问 `http://<服务器IP>:8080`。
- 如果系统中没有管理员，页面会自动显示管理员注册表单。
- 注册后自动跳转登录，登录后进入域名管理面板。

### 管理域名
- 点击 **“添加域名”**，输入完整域名（如 `example.com`）。
- 点击域名旁的 **“编辑记录”**，进入区域记录配置。
- **至少必须填写“其他/未知（默认）”区域**，作为全局默认解析。
- 其他区域（如中国移动、香港等）按需填写。
- 每个区域只能选择一种记录类型（A/AAAA/CNAME），但不同区域可不同。
- 保存后立即生效，无需重启服务。

### 添加用户（仅管理员）
- 管理员登录后，导航栏会显示 **“用户管理”** 按钮。
- 可以查看现有用户，并添加新的普通用户。
- 普通用户登录后可管理自己的域名，但不能管理用户。

### 托管域名到 dsdns
要让外部域名使用 dsdns 进行解析，需要将域名的 NS 记录指向运行 dsdns 的服务器。  
推荐做法：
1. 在域名注册商（如 Cloudflare）为你的服务器创建两条 A 记录，例如：
   - `ns1.yourcompany.com` → 服务器 IP
   - `ns2.yourcompany.com` → 同一 IP（单节点时可用相同 IP）
2. 将目标域名的 NS 记录修改为这两个主机名：
   - `customer.com NS ns1.yourcompany.com`
   - `customer.com NS ns2.yourcompany.com`
3. 在 dsdns 面板中添加域名 `customer.com` 并配置记录。

## 项目结构
```
.
├── main.go                 # 入口
├── config.yaml             # 配置文件示例
├── go.mod / go.sum
├── internal/
│   ├── config/             # 配置加载
│   ├── db/                 # 数据库初始化、查询接口
│   ├── dns/                # DNS 服务器（miekg/dns）
│   ├── geo/                # IP 归属解析（ip2region + GeoIP2）
│   ├── models/             # 数据结构与常量
│   └── web/
│       ├── static/         # 前端静态资源（嵌入二进制）
│       │   ├── login.html
│       │   ├── index.html
│       │   ├── js/
│       │   │   ├── api.js
│       ├── embed.go        # embed 声明
│       ├── router.go       # HTTP 路由
│       ├── auth.go         # JWT 工具
│       ├── handlers_*.go   # API 处理器
│       └── middleware.go   # JWT 中间件
```

## 部署注意事项

1. **JWT 密钥**：请务必修改 `config.yaml` 中的 `jwt.secret` 为随机字符串，否则安全无保障。
2. **数据库文件**：SQLite 文件 `dsdns.db` 会自动创建，建议定期备份。
3. **IP 库更新**：定期更新 `ip2region.xdb` 和 `GeoLite2-Country.mmdb`，替换后重启服务即可生效。
4. **DNS 反射防御**：服务仅应答已配置的域名，不响应未配置域名的查询（返回 NXDOMAIN），有效减少放大风险。但仍建议在防火墙层面限制 UDP 响应速率。
5. **内存缓存**：`geo_ttl_sec` 控制 IP 归属结果在内存中的缓存时间，不宜设得过大，避免 IP 归属变更后延迟生效。
6. **前端更新**：如需修改前端，直接编辑 `internal/web/static` 下的文件，重新编译即可。

## 构建最小二进制（可选）
项目已使用 `modernc.org/sqlite` 纯 Go 驱动，无 CGO 依赖，编译出的二进制仅约 15~20MB。  
可以通过 `upx` 进一步压缩：
```bash
upx --best dsdns
```

## 许可证
MIT License

## 贡献
欢迎提交 Issue 和 Pull Request。
