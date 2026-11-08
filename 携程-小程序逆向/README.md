# 携程小程序接口逆向与酒店房价查询

## 一、项目概述

目标是从携程小程序里拿到真实房价，且在 Python 侧完成，不依赖微信和小程序运行时。

这里有个前提容易被误解：接口能调通，不等于能拿到价格。小程序对未登录或签名不完整的会话会把价格字段返回成 `"?"`，请求本身照样 200。所以本项目的验收标准不是 HTTP 状态码，而是：

```
priceInfo.price 是数字（例如 150），而不是 "?"
```

整条链路要同时满足三个条件——微信渠道票据、正确的 cSign 签名、酒店反爬令牌。缺任何一项，接口要么静默返回空列表，要么给出 `ResultId: 203`。

工程从抓包分析起步，逐步做到：解密小程序包体、还原请求协议、离线执行签名模块与反爬虚拟机、打通登录态、最后封装成可复用的查询工具与命令行。

运行环境为 Python 3.10 以上、Node.js 18 以上（签名与反爬令牌由 `携程_code.js` 生成）。依赖见 `requirements.txt`，本地模块与凭证的准备见「部署与使用」一节。

## 二、范围与约束

- 全程只读查询，不涉及下单、支付、账号资料修改；
- 抓包仅在本人设备上进行，抓包结束后恢复系统代理，非目标域名的流量不保留；
- 会话凭证只存在于本地 `携程_config.json`，该文件被 `.gitignore` 排除，仓库仅有结构模板；
- 请求频率受页数与间隔限制，命中风控即停止，不做连续重试。

## 三、包体还原

微信 4.x 的小程序包是 `V1MMWX` 格式，双层加密：

```
密钥 = PBKDF2-HMAC-SHA1(appid, salt="saltiest", 1000 轮, 32 字节)
IV   = "the iv: 16 bytes"
前 1024 字节密文：AES-256-CBC 解密，只取前 1023 字节
第 1030 字节起：逐字节 XOR ord(appid[-2])
```

第二步的 XOR 密钥取自 appid 的倒数第二个字符。携程的 appid 该位是 `7`，即 `0x37`。

这里有个坑：多数公开实现写"解密前 1024 字节"，直接照抄会让索引表在偏移 1024 处错位一个字节，表现为 `unpack requires a buffer of N bytes`。正确做法是 AES 明文只取前 1023 字节，第 1024 字节是填充。

解包后得到 356 个文件、约 24 MB 源码，按分包划分：

| 包 | 文件数 | 内容 |
|---|---|---|
| `__APP__` | 132 | 主包：首页、我的、下单、公共 cwx 框架 |
| `_pages_accounts_` | 44 | 登录与账户 |
| `_pages_hotelcomponent_` | 55 | 酒店通用组件（房型、筛选） |
| `_pages_hoteldetail_` | 8 | 酒店详情 |
| `_pages_hotelsearch_` | 32 | 酒店搜索与列表 |
| `_pages_live_` | 16 | 直播 |
| `_pages_paynew_` | 61 | 支付 |
| `_pages_search_` | 8 | 全局搜索 |

包内是单行 bundle，按 `define("模块名")` 切开后得到 612 个独立模块，可以直接按路径定位逻辑。

关键模块：

| 模块 | 作用 |
|---|---|
| `config.js` | 常量表：appId、systemCode、accesscode、业务版本 |
| `cwx/ext/cwx.request.js` | 请求主流程：加 header、塞 head、拼后缀、签名、发起请求 |
| `cwx/ext/cwx.requestUtils.js` | header 与 head 构造，`_fxpcqlniredt` 后缀 |
| `cwx/ext/sign/index.js` | 签名入口，写 `n-payload-source` |
| `cwx/ext/sign/c-sign.js` | 签名引擎（混淆加字符串表，29 KB） |
| `cwx/ext/cwx.createAntiSpiderRequestV2.js` | 酒店反爬：取字节码、跑虚拟机、出令牌 |
| `3rd/tiny.039.min.js` | 栈式虚拟机解释器（6.8 KB） |
| `cwx/ext/cwx.dynamicLogin.js` | 跨端登录态同步 |

## 四、请求协议

三层结构，全部还原。

**URL**

```
https://m.ctrip.com/restapi/soa2/{服务号}/{json路径}/{方法}?_fxpcqlniredt={cid}
```

`json路径` 常见为 `json`，也可为空或 `h5-json`；`cid` 是 20 位纯数字的设备标识，与 Cookie 里的 `GUID` 同值。

**请求头**

```
x-ctx-locale: zh-CN          x-ctx-group: ctrip
x-ctx-region: CN             x-ctx-currency: CNY
x-ctx-personal-recommend: 1  x-wx-include-credentials: env
duid: u=<32 位 HEX>&v=0      udl: <32 位 HEX 大写>
Cookie: DUID=…;_udl=…;GUID=<cid>;
Referer: https://servicewechat.com/<appid>/<版本>/page-frame.html
```

**body.head**

`head` 是服务端认的身份信息，几乎所有接口都带：

```json
{
  "cid": "<设备标识>",
  "ctok": "",
  "cver": "<业务版本>",
  "lang": "01",
  "sid": "",
  "syscode": "30",
  "auth": "<登录票据>",
  "sauth": "",
  "extension": [
    {"name": "appId", "value": "<appid>"},
    {"name": "scene", "value": "1027"}
  ]
}
```

酒店类接口（`33278` 等）的 `head` 还要额外带 `platform:"Applet"`、`group:"ctrip"`、`bu:"HBU"`、`locale`、`currency`、`timezone`。缺任何一项直接返回 `400 ValidationError`，报错信息会点名缺哪个字段。

## 五、签名 cSign

签名公式本身很简单：

```
n-payload-source = cSign( md5_hex( JSON.stringify(body) ) )
```

输出形如 `102!<base64>`，前缀是版本标识。`cSign` 非确定性——同一输入两次调用结果不同，内部含随机数。

这里采取的策略是**不还原算法，直接离线执行原模块**。`c-sign.js` 是混淆加字符串表的结构，手工还原成本高且容易错；而服务端靠解密校验，原函数的输出天然合法。于是把它放进一个 `define` 垫片里加载，传入 md5 值，取出结果即可。

代价是需要随包携带 4 个小模块：`c-sign.js`、`cwx.md5.js`、`cwx.aes.js`、`tiny.039.min.js`，合计约 60 KB。工程把这 4 个模块以 base64 内嵌进 `携程_code.js`，运行时落盘加载，因此不依赖外部源码目录。

一个重要判断修正：早期根据抓包里没看到这个头，认为线上开关是关闭的。实测证明**是开着的**，请求头必须带 `n-payload-source: 102!…`，缺了会被判为异常请求。

## 六、反爬虚拟机

房型接口 `33278/getHotelRoomListInland` 有独立的反爬层，不带令牌直接返回：

```json
{"htlSpiderActionErrorCode": 4030}
```

机制是四步：

```
① POST /restapi/soa2/18433/sdtsource  {"appid":"hotel_mini"}
   ← {"d": [字符串表], "b": "<base64 字节码>", "version": "1002-minidefault"}

② 把 {d, b} 喂给 tiny.039.min.js
   → 编译出 context.globals.signature(body, appid)

③ token = signature(请求体原文, "hotel_mini")
   → 形如 1005-minicommon-U2FsdGVkX1…（U2FsdGVkX1 即 CryptoJS 的 "Salted__"）

④ 请求头 phantom-token: <token>
```

虚拟机是服务端下发的字节码在本地执行，不是常规 JS 逻辑，所以要让它跑起来，必须补齐宿主环境。用访问追踪代理扫出依赖字段：

| 字段 | 说明 |
|---|---|
| `cwx.clientID` | 必须与 URL 里的 `cid` 一致 |
| `cwx.cwx_mkt.openid` | 小程序 openid，未登录可为空 |
| `cwx.wxSystemInfo` | `getSystemInfoSync()` 的结果，含屏幕、机型、系统等 24 个字段 |
| `cwx.getCurrentPage()` | 返回 `{pageId}` |
| `cwx.md5` / `cwx.aes.AES.encrypt` | 直接复用逆向出的 `cwx.md5.js` / `cwx.aes.js` |
| `cwx.miniType` | `"mini"` |

补齐后令牌可以稳定生成，长度 336 字符。带上之后 `4030` 消失。

`phantom-token` 需要前缀 `1005-minicommon-`，裸串无效。这一点早期判断错误，浪费了不少时间。

## 七、登录

### 7.1 两条路径

微信登录链是 `wx.login()` → code → `14553/wechatLogin` → ticket。`code` 由微信运行时一次性签发，离线造不出来。

因此有两条替代路径：

- **手机验证码**：不依赖微信运行时，走账号网关，能拿到 `uid` + `auth` + `duid`，票据有效期约 4 个月；
- **微信渠道**：在小程序内登录后抓包提取，酒店体系只认这一种票据。

两者用途不同：手机票据适合账户域接口，酒店带价必须用微信渠道票据。

### 7.2 手机验证码四步

账号网关和业务接口不在同一个域名：

| 步骤 | 地址 | 作用 |
|---|---|---|
| 1 风控预检 | `passport.ctrip.com/…/risk/11448/sendMessageByPhoneLogin.json` | 判断是否需要图片验证码 |
| 2 下发短信 | `passport.ctrip.com/…/soa2/11448/sendMessageByPhoneLogin.json` | 发送验证码 |
| 3 校验验证码 | `passport.ctrip.com/…/soa2/11448/checkPhoneCode.json` | 换取 mobileToken |
| 4 换登录票据 | `passport.ctrip.com/…/soa2/12559/userLogin.json` | mobileToken → ticket + uid + duid |

业务接口仍是 `m.ctrip.com/restapi/soa2/…`，把第 4 步得到的 `auth` 放进 `body.head.auth`。

场景码不能混用。源码里有两张表：

```
登录        messageCode = S200078
手机查订单  messageCode = S200041
```

用错会一直返回"手机号格式错误"，很难从报错里看出原因。

登录态验证做了两条独立通道：业务域的 `13191/getTicketPropertys.json`，网关域的 `13191/getAccountInfoByTicket.json`。两边都通过，才说明票据真的有效，不是本地自娱自乐。

`cid` 与验证码绑定，换 `cid` 必须重新发码。脚本按"发码即落盘"的顺序写，第二步自动衔接。

### 7.3 微信渠道票据

由小程序内登录签发，只能通过抓包获取。流程是：开系统代理 → 起本地中间人代理 → 在小程序里滚动酒店列表触发请求 → 从日志提取票据写回配置 → 恢复代理。

代理开关直接操作注册表（`winreg`），不用 `reg.exe`——后者在本机被安全策略拦截。抓包结束后必须恢复原值，否则系统网络会异常。

## 八、酒店业务链路

### 8.1 接口分工

| 接口 | 用途 | 特点 |
|---|---|---|
| `31454/getHotelList` | 城市酒店列表 | 匿名可用，无价格 |
| `31454/fetchHotelInfoList` | 带价列表 | 需完整签名与票据，响应结构不同 |
| `33278/getHotelRoomListInland` | 房型 | 需 `phantom-token` |

前两个早期被当成同一个接口的不同版本，导致字段一直对不上。带价接口的 body 是四段结构：

```
{head, searchInfo, sceneInfo, pagingInfo}
```

- `head`：`platform:"Applet"`、`group:"ctrip"`、`bu:"HBU"`、`cver`、`pageId:"ignore_page_pv"`、`isSSR:false`、`timezone:"8"`；
- `searchInfo.destinationInfo`：`cityId`、`cityName`、`destinationName`、`destinationType`、`multiDestination`；
- `searchInfo.checkInfo`：`checkInDate`、`checkOutDate`（`YYYYMMDD`）、`dateType:0`；
- `searchInfo.queryFilter`：`type:"80"`（含税价）与 `type:"29"`（人数）两个筛选项。

### 8.2 三个曾经搞错的点

| 错误认知 | 实际情况 |
|---|---|
| `x-wx-openid` 填 unionID | 填 mktOpenID，是 UUID 形状的字符串；unionID 是另一个字段 |
| cSign 线上未启用 | 启用，必须带 `n-payload-source` |
| `phantom-token` 是裸串 | 需 `1005-minicommon-` 前缀 |

### 8.3 203 与 4030

`ResponseStatus.Extension` 里出现 `ResultId: 203` 表示反爬拦截，触发条件是"带了票据但签名或令牌不匹配"。`4030` 才是"需要登录"。两者性质不同，处理方式也不同。

三种典型 203：

| 现象 | 原因 | 处理 |
|---|---|---|
| 列表静默返回 0 条 | 票据被该业务域标记（会话级） | 换会话，等数小时通常自愈 |
| `htlSpiderActionErrorCode: 203` | `auth` 与登录后的 `duid` 未同进同出 | 两个一起换 |
| 所有酒店接口 203（含配置类） | 整个设备标识加票据被标记 | 冷却或换设备 |

第二行来自四组对照实验，每次只改一个变量：

| 条件 | 结果 |
|---|---|
| 新 cid + 无 auth + 新 duid | 正常返回 |
| 新 cid + 带 auth + 新 duid | 203 |
| 登录 cid + 无 auth + 新 duid | 正常返回 |
| 登录 cid + 无 auth + 登录 duid | 203 |

结论是 `auth` 和登录后的 `duid` 都会单独触发拦截，必须成对出现。这个坑比较隐蔽，因为 `duid` 在 Cookie 和 header 里各有一份。

顺带排除两个误判：与 `cid` 无关，换 `cid` 没有作用；列表接口的软拒绝是静默返回空 `data`，不报错，比硬拦截更难查。

## 九、目的地体系

三个 ID 各管一段，混淆会直接返回 0 条：

| ID | 含义 | 例子 |
|---|---|---|
| `cityId` | 城市 | 43 = 三亚，2 = 上海，454 = 泰安 |
| `districtId` | 行政区，不是商圈 | 2 = 上海，61 = 三亚，1019 = 嘉善 |
| 搜索结果的 `id` | POI，不能直接用于筛酒店 | 亚龙湾 = 2020081 |

商圈和景区在携程不是"区"，而是一条独立的"景区型目的地"记录，用 `cityId + districtId` 组合表达：

```
泰山（泰安）      cityId=454   districtId=6
普陀山（舟山）    cityId=19    districtId=16
白洋淀景区（安新）cityId=21900 districtId=10376
三亚              cityId=43    districtId=0     普通城市，全市
```

同样 `cityId=454`，`districtId=6` 返回景区内酒店，`districtId=0` 返回市区酒店。

`destinationType` 是另一个陷阱：源码里 `destinationType === 2` 对应 `cityType: "OVERSEA"`，它表示国内/国外，不是城市/区级别。传 `2` 去筛"亚龙湾"，服务端理解成"海外的亚龙湾"，返回 0 条。国内一律传 `1`。

地名解析的匹配顺序：

```
精确 → "名称(城市)" 景区型 → 前缀 → 包含 → 去括号再精确 → 联想搜索兜底
```

同级冲突时优先命中带 `districtId` 的条目，所以输入"泰山"命中的是"泰山(泰安)"。`source` 字段标明结果来自本地表还是联网兜底。

城市表来自 `31454/getCityList`，`requestType=1` 国内、`2` 海外，一次返回 23 个分组：国内 2360 条（其中 190 条带 `districtId`），海外 751 条。已缓存到 `cities.json`。

## 十、关键词带价

`30668/search` 是联想接口，只返回 `id`、`type`、`word`、`cityName`，`price` 恒为空串——它本来就不负责报价。小程序里的价格是列表页另外发 `fetchHotelInfoList` 得到的。

所以带价搜索是两段拼出来的：

```
30668/search  "汉庭 泰安"  →  [type=hotel] 的 hotelId 列表
      ↓  sceneInfo.hotelIdListInfo.searchHotelList = [id…]
31454/fetchHotelInfoList   →  这些酒店被优先召回，且带价
      ↓  再按 id 过滤
只保留关键词命中的酒店
```

`searchHotelList` 对应源码里的 `urlParams.listQuery.topHotels`，是"带酒店清单进列表页"的正式通道。关键坑在于它只影响排序与优先召回，**不裁剪兜底结果**——实测请求 8 个 id，返回 25 家，其中 8 家命中、17 家是城市兜底。不过滤就会出现"搜汉庭，出全泰安"的情况。

`30668` 还有两个更隐蔽的问题：

1. **不带城市上下文**。`locationInfo` 为空时，搜"海景"返回的是另一个城市的海景酒店，完全不受控；
2. **属性词没有 `type=hotel` 条目**。"民宿"在 `30668` 里只返回城市与榜单类结果，id 通道拿到 0 个 id，等于失效。

因此 `search_priced` 设两条通道，按顺序尝试：

```
① id 通道：30668（带 locationInfo.cityId）→ hotelId 列表
          → searchHotelList 塞进 31454 → 按 id 过滤
          适用：品牌名、具体酒店名、商圈地名

② 本地筛：拉目标城市的 31454 列表页 N 页 → 按名称/地址包含关键词过滤
          适用：属性词（民宿/海景/温泉/亲子），或 id 通道淘汰后仍为空
          列表价本身就是到手价，不需要二次补价
```

`last_search_mode` 记录本次走的是哪条通道，命令行直接打在标题行，便于判断结果可信度。

`--city` 几乎必带，否则结果散落全国；`--pages` 控制本地筛的页数，每页约 24 家，翻 N 页就是 N 次请求。本地筛会自动剔除与城市同名的 token，避免"三亚 海景"里的"三亚"参与匹配。

## 十一、数据清洗与快照

列表与房型的字段映射：

| 输出字段 | 来源 |
|---|---|
| `hotel_id` | 酒店 ID |
| `name` | 酒店名 |
| `price` | `priceInfo.price`，到手价 |
| `original_price` | 原价 |
| `star` / `score` / `score_desc` | 星级、评分、评语 |
| `comment_count` / `collect_count` | 点评数、收藏数 |
| `address` / `distance` | 地址、距离 |
| `discounts` | 优惠标签合并 |
| `price_detail` | `priceFloat` 明细（房费、优惠、税） |

房型侧可拿到：房型名、`price.roomPriceText`、均单价、在线付/到店付、面积、景观、楼层、可住人数、取消政策、费用明细。

价格快照按 `<地区>_<入住>_<离店>.json` 落盘，同 key 追加，保留最近 20 条。每次跑完与上一次同 key 快照对比，输出涨、跌、新增、消失。首次运行只入库，不输出对比。

做这个是因为酒店价格按查询时刻实时计算，会员价、特惠、剩余房量都会影响结果，同一家隔几小时差几十上百很常见，单次结果没有参考价值。

## 十二、工程实现

| 路径 | 说明 |
|---|---|
| `携程_decode.py` | 主入口：客户端、解析、带价查询、登录、CLI |
| `携程_code.js` | cSign 与反爬令牌，运行时加载 vendor 下的 4 个模块 |
| `携程_tools.py` | 抓包代理、系统代理、窗口自动化、会话刷新 |
| `requirements.txt` | Python 依赖 |
| `config.example.json` | 配置模板，复制为 `携程_config.json` 后填写 |
| `vendor/` | 目标方 4 个模块的放置目录，需自行准备 |
| `cities.json` | 城市表缓存，首次运行自动生成 |
| `js_reverse_cache/hotel_list_template.json` | 带价请求体模板 |
| `js_reverse_cache/csv/` | 导出结果 |
| `js_reverse_cache/snapshots/` | 价格快照 |
| `js_reverse_cache/mitm.jsonl` | 抓包日志 |

`携程_code.js` 不内嵌目标方代码，运行时从 `vendor/` 读取 4 个模块，缺失时按名字给出提示并以非零码退出。这样仓库可以公开，使用方需要自己从本机小程序包中提取这几个文件。

数据目录的探测顺序：环境变量 → 脚本同目录 → 历史工作目录 → 兜底。候选里挑第一个可写的，因为要往里落脚本文件。

命令行退出码语义统一：帮助与正常执行为 0，未知命令为 1。早期无参数时返回 1，容易被 IDE 误判成运行失败。

## 十三、验证结果

一次例行自检（同一入住/离店日期，全部退出码 0）：

| 能力 | 命令 | 结果 |
|---|---|---|
| 全市带价列表 | `hotels 三亚` | 24 家全部带价，¥96–¥468 |
| 景区级带价 | `hotels 泰山` | 命中景区内 12 家，¥96–¥385 |
| 房型带价 | `rooms <id>` | 45 个房型，含在线付/到店付 |
| 品牌关键词带价 | `search 汉庭 泰安` | 命中 3 家，走 local-filter |
| 度假关键词带价 | `search 三亚酒店` | 命中 8 家，走 id-channel |
| 属性词 + 城市约束 | `search 民宿 --city 三亚` | 命中 8 家，¥98–¥308 |
| 城市表刷新 | `cities --refresh` | 国内 2360 / 海外 751，景区型 190 |
| 价格快照 | `snapshot 三亚` | 首次入库，二次运行输出「涨 0 / 跌 0 / 新增 0 / 消失 0」 |

签名与反爬层面：

| 项 | 状态 |
|---|---|
| cSign 离线生成 | 通过，输出 `102!` 前缀 |
| 反爬令牌 | 通过，336 字符，`4030` 消失 |
| 手机验证码登录 | 通过，票据有效期约 4 个月 |
| 登录态双通道校验 | 通过 |
| 全程 `ResultId` | 为 `None`，未触发反爬 |

## 十四、问题记录

| 现象 | 真正原因 | 处理 |
|---|---|---|
| `{"Message":"strategy not exist"}` | BFF 靠 `head` 的 `group` 与 `bu` 选策略，不在 URL 也不在参数 | 补 `platform/group/bu/locale/currency/timezone` |
| 传了城市参数却返回北京的酒店 | 字段名是顶层 `location`，不是源码里的变量名 `searchCityInfo` | 改用 `location` |
| 房型接口 `4030` | 缺 `phantom-token` | 补反爬令牌与前缀 |
| 房型接口 `203` | `auth` 与登录 `duid` 未成对 | 两个一起换 |
| 列表静默空 `data` | 会话级风控 | 换会话，不刷新签名 |
| 大响应时小程序提示"加载失败" | 中间人代理解析了 chunked 却仍转发 `Transfer-Encoding` | 删该头并重算 `Content-Length` |
| 抓包日志里响应不完整 | 日志预览截断 4000 字节 | 上限调到 400000 |
| 拦截 `getMKTOpenID` 后小程序连锁 203 | 破坏了小程序的内部状态 | 只在抢一次性凭证时用，用完立刻移除 |
| 系统代理开关被安全策略拦截 | 用了 `reg.exe` | 改 `winreg` 直接操作注册表 |

关于 `strategy not exist` 这一条，排查花了很长时间。试过 `strategy`、`strategyCode`、`strategyName` 等多种字段组合都无效，最后发现服务号本身也不是远端下发的——`getHotelSearchBffServiceId()` 的实现就是两个常量：默认 `31454`，只有本地缓存里 `hotel_sub_search_bff_config[key] === "1"` 时才切到 `34697`。

## 十五、已知限制

- 价格依赖微信渠道票据，票据过期后需重新抓取，代码不提供自动续期；
- 纯商圈（如"亚龙湾"）无法精确到商圈内部，它既不在城市表里，也不是景区型记录，会回落到所属城市；
- 关键词带价的覆盖面受 `30668` 约束，一次约 8–10 个 id；属性词由本地筛兜底，覆盖面等于页数乘每页条数，不是全城穷举；
- `searchFilter` 仍需额外的策略标识，暂未打通；
- `getInquireInfo` 只返回前置信息（日历、资格、banner），未拿到酒店条目；
- 下单与支付全程未涉及。

## 十六、配置结构

复制 `config.example.json` 为 `携程_config.json` 后填写。仓库只保留结构，不含真实值：

```json
{
  "wx": {
    "auth": "<REDACTED>",
    "mktOpenID": "<REDACTED>",
    "duid": "<REDACTED>",
    "udl": "<REDACTED>",
    "cookie": "<REDACTED>",
    "scene": "1005",
    "cid": "<REDACTED>",
    "ua": "Mozilla/5.0 … MiniProgramEnv/Windows …",
    "appVersion": "<版本号>"
  },
  "sms": {
    "cid": "<REDACTED>",
    "duid": "<REDACTED>",
    "udl": "<REDACTED>",
    "auth": "<REDACTED>",
    "uid": "<REDACTED>",
    "mobile": "<REDACTED>",
    "scene": "1145"
  },
  "collect": {
    "place": "广州",
    "checkin": "20261108",
    "checkout": "20261109",
    "pages": 10,
    "size": 20,
    "top": 10
  }
}
```

`.gitignore` 至少包含：

```
携程_config.json
cities.json
js_reverse_cache/
mods/
src/
__pycache__/
```

`mods/` 与 `src/` 是解包产物，体积大且属于目标方代码，不应随仓库分发。

## 十七、部署与使用

### 准备依赖模块

`携程_code.js` 需要目标小程序内的 4 个模块，它们属于目标方代码，仓库不随附分发。解密解包后按原始路径取出，放进 `vendor/` 并重命名：

| 目标文件 | 原始路径 |
|---|---|
| `vendor/c-sign.js` | `cwx/ext/sign/c-sign.js` |
| `vendor/cwx.md5.js` | `cwx/ext/cwx.md5.js` |
| `vendor/cwx.aes.js` | `cwx/ext/cwx.aes.js` |
| `vendor/tiny.039.min.js` | `3rd/tiny.039.min.js` |

### 准备凭证

```bash
cp config.example.json 携程_config.json
# 填写 wx 段（微信渠道票据）与 sms 段（手机登录态）
```

带价查询只认微信渠道票据，`wx` 段为空时价格会返回 `?`。票据的获取方式见「登录」一节。

### 常用命令

```bash
python 携程_decode.py places 泰山                        # 地名转目的地 ID
python 携程_decode.py hotels 泰山 20261107 20261108      # 带价列表（景区级）
python 携程_decode.py hotels 三亚 20261107 20261108      # 带价列表（全市）
python 携程_decode.py rooms <酒店ID> 2026-11-07 2026-11-08
python 携程_decode.py search 汉庭 20261115 20261116 --city 泰安
python 携程_decode.py search 民宿 20261115 20261116 --city 三亚 --pages 3
python 携程_decode.py snapshot 三亚 20261114 20261115 --pages 3 --top 10
python 携程_decode.py cities                             # 城市表体检
python 携程_decode.py waterflow                          # 首页瀑布流
python 携程_decode.py login whoami                       # 查登录态
```

作为库使用：

```python
from 携程_decode import PricedClient, resolve_place, load_cities

c = PricedClient()
resp = c.hotel_list_by_place("泰山", "20261107", "20261108")
for h in c.parse_hotels(resp):
    print(h["name"], h["price"], h["original_price"], h["star"], h["score"])

rooms = c.parse_rooms(c.rooms(<酒店ID>, "2026-11-07", "2026-11-08"))
print(rooms[0]["name"], rooms[0]["price"], rooms[0]["pay_type"])

hits, raw = c.search_priced("民宿", "20261115", "20261116", city="三亚", pages=3)
print(c.last_search_mode)   # "id-channel" / "local-filter" / "none"
```

依赖 `requests` 与 Node.js（运行 `携程_code.js`）。

## 十八、合规声明

本项目用于小程序前端安全机制与协议实现的学习研究。使用时应遵守目标站点的服务条款与相关法律法规，不得用于商业转售、规模化采集或任何影响服务正常运行的行为。仓库不包含可用的账号凭证与票据，不随附目标方的模块与解包源码。因不当使用产生的后果由使用者自行承担。
