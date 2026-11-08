"""携程小程序逆向 —— 酒店价格离线查询

用法:
    from 携程_decode import CtripClient, PricedClient, resolve_place

    PricedClient().hotel_list_by_place("泰山", "20261107", "20261108")
    PricedClient().rooms(14249344, "2026-11-07", "2026-11-08")

命令行:
    python 携程_decode.py places 泰山                     # 地名 -> 目的地 ID
    python 携程_decode.py hotels 泰山 20261107 20261108   # 酒店列表（带价格）
    python 携程_decode.py rooms 14249344 2026-11-07 2026-11-08
    python 携程_decode.py search 三亚酒店 20261114 20261115   # 关键词搜索（带价）
    python 携程_decode.py search 民宿 20261114 20261115 --city 三亚   # 属性词 + 城市约束
    python 携程_decode.py snapshot 三亚 20261114 20261115     # 存价格快照 + 涨跌对比
    python 携程_decode.py cities [--refresh]              # 城市表体检 / 联网刷新
    python 携程_decode.py collect 泰山 20261107 20261108            # 采集+存CSV
    python 携程_decode.py collect 三亚 20261107 20261108 --rooms --top 20  # 连房型一起采
    python 携程_decode.py login send 13800000000
    python 携程_decode.py login whoami

依赖: requests、node（携程_code.js 跑 cSign 签名 + 酒店反爬 VM）
数据: 携程_config.json（凭证）、cities.json（城市表）、
      js_reverse_cache/hotel_list_template.json（带价请求体模板）
运行期产物: js_reverse_cache/{csv,snapshots,mitm.jsonl,certs,flows}/（根目录不放产物）
调试工具（抓包/窗口自动化/系统代理）在同目录的 携程_tools.py。
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import re
import string
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_JS = os.path.join(HERE, "携程_code.js")
CONFIG_FILE = os.path.join(HERE, "携程_config.json")
CITIES_FILE = os.path.join(HERE, "cities.json")
CACHE_DIR = os.path.join(HERE, "js_reverse_cache")
TEMPLATE_FILE = os.path.join(CACHE_DIR, "hotel_list_template.json")
SESSION_FILE = os.path.join(HERE, "ctrip_session.json")


def load_config() -> dict:
    """读取携程_config.json（凭证 + 配置）。"""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _run_code_js(*args: str) -> dict:
    """调用携程_code.js。sign <md5> / token <payload.json>"""
    out = subprocess.run(["node", CODE_JS, *args],
                         capture_output=True, text=True, timeout=90, encoding="utf-8")
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as e:
        raise RuntimeError("携程_code.js 执行失败: " + (out.stderr or out.stdout)[-400:]) from e

# §1 逆向出来的参数总表
#    （全部来自小程序解包源码 + 真实抓包，非猜测）
# ============================================================================

# ---- 小程序身份 ----
APPID = "wx0e6ed4f51db9d078"          # 携程小程序 AppID
CVER = "1.2.370"                       # 小程序 cver（head 里另有 cver=999999 用于 BFF）
SYSTEM_CODE = "30"                     # syscode
ACCESSCODE = "XTHYY69RNSKLWEICHATMINI" # accessCode
HOST = "https://m.ctrip.com"           # 业务网关
GATEWAY = "https://passport.ctrip.com/gateway/api"   # 账号网关（另一个域名！）
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
    "UnifiedPCWindowsWechat(0xf2541f38) XWEB/25819"
)

# ---- 服务号（soa2/{服务号}/{方法}）----
SERVICES = {
    "31454": "酒店 BFF（列表/筛选/询价/城市）",
    "33278": "酒店房型 + 价格",
    "18433": "反爬字节码下发（sdtsource）",
    "13012": "首页瀑布流",
    "30668": "全局搜索",
    "12378": "通用配置",
    "12673": "微信热门活动",
    "12538": "createClientId（换 cid）",
    "13447": "getMKTOpenID（拿 openid + wx.login code）",
    "13916": "广告位",
    "14553": "微信登录",
    "24862": "validateTicket（code 换票据）",
    "24863": "quickLoginPreCheck / checkGetMobilephoneBillingCode",
    "12559": "userLogin",
    "13191": "票据属性 / 账号信息",
    "22559": "合集配置",
}

# ---- 酒店 BFF 带价请求的 head（抓包实测，缺字段就 strategy not exist）----
PRICED_HEAD = {
    "ctok": "", "cver": "999999", "lang": "01", "sid": "", "syscode": "30",
    "sauth": "", "platform": "Applet", "aid": "", "ouid": "",
    "locale": "zh-CN", "pageId": "ignore_page_pv", "currency": "CNY",
    "timezone": "8", "isSSR": False, "group": "ctrip", "bu": "HBU",
}

# ---- 签名 / 反爬 ----
CSIGN_PREFIX = "102!"          # n-payload-source 的格式：cSign(md5(payload))
PHANTOM_PREFIX = "1005-minicommon-"   # phantom-token 的前缀
SD_APPID = "hotel_mini"        # 反爬 VM 的 appid

# ---- 登录相关常量（taroCommon.js 配置表）----
ACCESS_MOBILE_LOGIN = "MINI20210615LOGINV1"
STRATEGY_MOBILE_LOGIN = "VERIFYCODELOGIN2021"
ACCESS_USER_LOGIN = "B6CE8D84FEBBFC0E"
STRATEGY_USER_LOGIN = "85D4BB47E79522CA"
THIRD_CONFIG_CODE = "XTHYY69RNSKLWEICHATMINI"
WX_ACCESS_CODE = "WEIXINAUTEHNTICATE"     # 微信一键登录的 accessCode
MSGCODE_LOGIN = "S200078"     # 登录发码场景
MSGCODE_SEARCH_ORDER = "S200041"  # 手机查订单场景（别搞混！）
SEND_SCENE = "SMS-LOGIN-SITE"

# ---- 错误码 ----
ERR_RESULT_ID_203 = 203   # 反爬拦截：带了票据但签名/令牌不匹配
ERR_NEED_LOGIN_4030 = 4030    # 需要登录
ERR_HOTEL_SPIDER = "htlSpiderActionErrorCode"   # 房型接口的反爬字段名

# ---- queryFilter 类型号 ----
FILTER_TAX_INCLUDED = "80"   # 含税价
FILTER_GUEST_COUNT = "29"    # 人数


# ============================================================================

# §2 通用 HTTP / 匿名 SDK   （源文件：ctrip_api.py）
# ==========================================================================
"""携程小程序 —— 离线接口客户端（不依赖微信/小程序运行）。

由逆向出来的规则重建：
  URL   : https://m.ctrip.com/restapi/soa2/{serviceCode}/{jsonPath}/{method}?_fxpcqlniredt={cid}
  body  : 业务参数 + head（cid/ctok/cver/lang/sid/syscode/auth/sauth/extension[appId,scene]）
  header: x-ctx-locale/group/region/currency + duid/udl/Cookie(GUID) + x-wx-include-credentials
  签名  : 可选 header["n-payload-source"] = cSign(md5(json(body)))，由配置开关控制（当前线上关闭）
"""



APPID = "wx0e6ed4f51db9d078"
CVER = "1.2.370"
SYSTEM_CODE = "30"
ACCESSCODE = "XTHYY69RNSKLWEICHATMINI"
HOST = "https://m.ctrip.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
    "UnifiedPCWindowsWechat(0xf2541f38) XWEB/25819"
)


def load_app_session() -> dict:
    """读取手机验证码登录后落盘的会话（ctrip_login.py 写入）。"""
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def load_cities(scope: str | None = None, refresh: bool = False) -> dict | list:
    """读取城市表 cities.json；文件不存在或 refresh=True 时联网抓取并写回。

    scope=None 返回整个 {"domestic": [...], "oversea": [...]}；
    scope="domestic"/"oversea" 只返回对应列表。
    """
    data: dict = {}
    if not refresh and os.path.exists(CITIES_FILE):
        try:
            with open(CITIES_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    if not data:
        c = CtripClient(use_session=False)
        data = {"domestic": c.city_list("domestic"), "oversea": c.city_list("oversea")}
        try:
            with open(CITIES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except OSError:
            pass
    if scope:
        return data.get(scope) or []
    return data


def resolve_place(name: str, cities: dict | None = None,
                  client: "CtripClient | None" = None) -> dict | None:
    """地名 → 目的地 ID 组合（用户自定义地区用）。

    匹配顺序：精确 → "名称(...)" 景区型 → 前缀 → 包含；
    同级优先命中带 districtId 的条目（景区比全市更精确）。
    本地城市表没有时，回落到 30668 全局联想搜索。

    返回 {"name", "cityId", "districtId", "cityName", "districtName",
          "destinationName", "provinceName", "countryName", "countryId",
          "countryType", "source"}；找不到返回 None。
    """
    name = (name or "").strip()
    if not name:
        return None

    if cities is None:
        cities = load_cities()
    pool: list[dict] = []
    for scope in ("domestic", "oversea"):
        pool.extend(cities.get(scope) or [])

    def _norm(s: str) -> str:
        return (s or "").split("(")[0].strip()

    exact = [c for c in pool if c.get("name") == name]
    cand = exact
    if not cand:
        cand = [c for c in pool if c.get("name", "").startswith(name + "(")]
    if not cand:
        cand = [c for c in pool if c.get("name", "").startswith(name)]
    if not cand:
        cand = [c for c in pool if name in c.get("name", "")]
    if not cand:
        cand = [c for c in pool if _norm(c.get("name", "")) == name]
    if cand:
        cand.sort(key=lambda c: (0 if c.get("districtId") else 1, len(c.get("name", ""))))
        hit = dict(cand[0])
        hit["source"] = "citylist"
        return hit

    # 回落：全局联想搜索
    c = client or CtripClient(use_session=False)
    for x in c.search(name):
        if x.get("type") == "district" and x.get("cityId"):
            return {
                "name": x.get("word") or name,
                "destinationName": (x.get("word") or name).split("·")[0],
                "cityName": (x.get("word") or name).split("·")[0],
                "districtName": "",
                "provinceName": "",
                "countryName": "",
                "cityId": x.get("cityId"),
                "districtId": x.get("districtId") or 0,
                "provinceId": 0,
                "countryId": 1,
                "countryType": 1,
                "source": "search",
            }
    return None


def place_to_destination(place: dict) -> dict:
    """把 resolve_place 的结果转成酒店列表接口的 destinationInfo 字段。"""
    ct = place.get("countryType") or 1
    return {
        "cityId": place.get("cityId") or 0,
        "districtId": place.get("districtId") or 0,
        "provinceId": place.get("provinceId") or 0,
        "countryId": place.get("countryId") or 1,
        "countryType": ct,
        "destinationType": 2 if ct == 2 else 1,   # 1=国内 2=海外（源码 cityType 推断）
        "destinationName": place.get("destinationName") or place.get("name") or "",
        "cityName": place.get("cityName") or "",
        "districtName": place.get("districtName") or "",
        "provinceName": place.get("provinceName") or "",
        "countryName": place.get("countryName") or "",
        "fromMyLocation": False,
        "timeZone": 0,
    }


def gen_cid() -> str:
    """GUID / cid：20 位纯数字。"""
    return "".join(random.choice(string.digits) for _ in range(20))


def gen_duid() -> str:
    return "u=" + "".join(random.choice("0123456789ABCDEF") for _ in range(32)) + "&v=0"


def gen_udl() -> str:
    return "".join(random.choice("0123456789ABCDEF") for _ in range(32))


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


class CtripClient:
    def __init__(self, cid: str | None = None, duid: str | None = None, udl: str | None = None,
                 auth: str = "", scene: str = "1027", openid: str = "",
                 use_session: bool = True) -> None:
        sess = load_app_session() if use_session else {}
        self.cid = cid or sess.get("cid") or gen_cid()
        self.duid = duid or sess.get("duid") or gen_duid()
        self.udl = udl or sess.get("udl") or gen_udl()
        self.auth = auth or sess.get("auth", "")
        self.scene = scene if scene != "1027" else sess.get("scene", scene)
        self.openid = openid
        self.s = requests.Session()

    # ---------- head / header ----------
    def head(self, extra: dict | None = None) -> dict:
        h = {
            "cid": self.cid,
            "ctok": "",
            "cver": CVER,
            "lang": "01",
            "sid": "",
            "syscode": SYSTEM_CODE,
            "auth": self.auth,
            "sauth": "",
            "extension": [
                {"name": "appId", "value": APPID},
                {"name": "scene", "value": self.scene},
            ],
        }
        if extra:
            h.update(extra)
        return h

    def headers(self, sign_body: str | None = None) -> dict:
        cookie = f"DUID={self.duid};_udl={self.udl};GUID={self.cid};"
        h = {
            "Host": "m.ctrip.com",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "User-Agent": UA,
            "udl": self.udl,
            "duid": self.duid,
            "Cookie": cookie,
            "x-ctx-locale": "zh-CN",
            "x-ctx-group": "ctrip",
            "x-ctx-region": "CN",
            "x-ctx-currency": "CNY",
            "x-ctx-personal-recommend": "1",
            "x-ctx-personal-ads-recommend": "1",
            "x-wx-include-credentials": "env",
            "xweb_xhr": "1",
            "Referer": f"https://servicewechat.com/{APPID}/1076/page-frame.html",
        }
        if self.openid:
            h["x-wx-openid"] = self.openid
        if sign_body is not None:
            h["n-payload-source"] = csign(md5_hex(sign_body))
        return h

    # ---------- 调用 ----------
    def call(self, path: str, body: dict | None = None, *, add_head: bool = True,
             sign: bool = False, timeout: int = 20, raw: bool = False):
        """path 例：'13012/getWaterflowInfo' / '12378/json/GetAppConfig'"""
        body = dict(body or {})
        if add_head:
            body["head"] = self.head(body.get("head"))
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        url = f"{HOST}/restapi/soa2/{path.lstrip('/')}?_fxpcqlniredt={self.cid}"
        r = self.s.post(url, data=payload.encode("utf-8"),
                        headers=self.headers(payload if sign else None), timeout=timeout)
        if raw:
            return r
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code, "_raw": r.text[:500]}


    # ---------- 业务便捷方法 ----------
    def waterflow(self, index: int = 1, size: int = 20) -> dict:
        """首页瀑布流。"""
        return self.call("13012/getWaterflowInfo", {
            "sourceid": "wxhome", "appId": "99999999", "source": "wxhome",
            "componentType": "miniapp", "tabType": "", "tabId": "",
            "pageInfo": {"index": index, "size": size},
            "globalInfo": {}, "hotelInfo": {},
            "deviceInfo": {"screenHeight": 782, "screenWidth": 415, "deviceType": "PC",
                           "os": "Windows", "osv": "11", "type": "MINIAPP"},
            "coordinate": {}, "ext": {"cver": "9999.000"},
        })

    def search(self, keyword: str, city_id: int | None = None) -> list:
        """全局联想搜索（酒店/景点/城市/机票等）。"""
        loc = {}
        if city_id:
            loc["cityId"] = city_id
        r = self.call("30668/search", {
            "action": "wechat", "clientId": self.cid,
            "clientInfo": {"system": "windows"},
            "keyword": keyword, "personalRec": 0, "locationInfo": loc,
        })
        return r.get("data") or []

    # ---------- 地区（城市 / 区县 / 景区） ----------
    def city_list(self, scope: str = "domestic") -> list[dict]:
        """城市表（31454/getCityList）。

        scope: "domestic"(requestType=1) / "oversea"(requestType=2)

        返回条目形如：
            {name, destinationName, cityName, provinceName, countryName,
             cityId, districtId, provinceId, countryId, countryType, group}

        其中带 districtId 的 190 条是**景区型目的地**（如 "泰山(泰安)" cityId=454
        districtId=6），它们才是能精确筛到景区酒店的条目；普通城市 districtId=0。
        """
        rt = "2" if scope.startswith("over") else "1"
        r = self.call("31454/getCityList", {"requestType": rt, "head": dict(self.HOTEL_HEAD)})
        data = r.get("data") or {}
        key = "globalCityModel" if rt == "2" else "inlandCityModel"
        groups = (data.get(key) or {}).get("cityModelGroups") or []
        out, seen = [], set()
        for g in groups:
            dc = g.get("displayControlModel") or {}
            for rm in g.get("regionModels") or []:
                dm = rm.get("displayCityModel") or {}
                bm = rm.get("basicCityModel") or {}
                name = dm.get("destinationName") or dm.get("cityName") or ""
                if not name:
                    continue
                key2 = (name, bm.get("cityId"), bm.get("districtId"))
                if key2 in seen:
                    continue
                seen.add(key2)
                out.append({
                    "name": name,
                    "destinationName": dm.get("destinationName") or name,
                    "cityName": dm.get("cityName") or name,
                    "provinceName": dm.get("provinceName") or "",
                    "countryName": dm.get("countryName") or "",
                    "cityId": bm.get("cityId"),
                    "districtId": bm.get("districtId"),
                    "provinceId": bm.get("provinceId"),
                    "countryId": bm.get("countryId"),
                    "countryType": bm.get("countryType"),
                    "group": dc.get("fullName") or "",
                })
        return out

    def destination_info(self, city_id: int = 0, district_id: int = 0,
                         province_id: int = 0, country_id: int = 0) -> dict:
        """反查目的地（31454/getDestinationInfo）。

        返回 {basicCityModel, displayCityModel}；basicCityModel 才是能直接喂给
        酒店列表接口的字段（cityId / districtId / countryType / timeOffset）。
        """
        body = {"head": dict(self.HOTEL_HEAD)}
        if city_id:
            body["cityId"] = city_id
        if district_id:
            body["districtId"] = district_id
        if province_id:
            body["provinceId"] = province_id
        if country_id:
            body["countryId"] = country_id
        r = self.call("31454/getDestinationInfo", body)
        return (r.get("data") or {}).get("city") or {}

    # ---------- 酒店列表（31454 BFF） ----------
    HOTEL_HEAD = {
        "platform": "Applet", "group": "ctrip", "bu": "HBU",
        "locale": "zh-CN", "currency": "CNY", "timezone": "8",
    }

    def hotel_list(self, city_id: int, checkin: str, checkout: str,
                   page: int = 1, size: int = 10, adults: int = 1,
                   rooms: int = 1, keyword: str = "") -> dict:
        """城市酒店列表（31454/getHotelList）。

        checkin/checkout 用 YYYYMMDD。

        两个坑（都已用实验定位）：
        1. 不加 head.group/bu 会报 "strategy not exist" —— BFF 靠 head 的 group+bu
           选策略，不是靠 URL 或参数；
        2. 城市必须放在顶层 `location` 里。放 searchCityInfo / cityInfo / city 都会被
           忽略并回落成北京。
        """
        body = {
            "location": {"cityId": city_id, "districtId": 0, "provinceId": 0,
                         "countryId": 0, "countryType": 1, "timeOffset": 8},
            "checkInfo": {
                "checkInDate": checkin, "checkOutDate": checkout,
                "roomNumber": rooms, "adultNumber": adults,
                "childrenNumber": 0, "childrenAges": [],
            },
            "pagingInfo": {"pageIndex": page, "pageSize": size},
        }
        if keyword:
            body["keyword"] = keyword
        body["head"] = dict(self.HOTEL_HEAD)
        return self.call("31454/getHotelList", body)

    @staticmethod
    def parse_hotels(resp: dict) -> list[dict]:
        """把 hotelList 洗成 [{id, name, star, score, price, city, addr}]。"""
        data = resp.get("data") or {}
        out = []
        for h in data.get("hotelList") or []:
            pi = h.get("priceInfo") or {}
            ci = h.get("commentInfo") or {}
            poi = h.get("poiInfo") or {}
            pos = h.get("positionInfo") or []
            first_pos = pos[0] if isinstance(pos, list) and pos else {}
            out.append({
                "id": h.get("hotelId"),
                "name": h.get("hotelName"),
                "star": (h.get("hotelStar") or {}).get("star"),
                "score": ci.get("commentScore"),
                "commentCount": ci.get("commentNumber"),
                "price": pi.get("displayPrice"),
                "city": poi.get("cityName"),
                "address": poi.get("positionDesc") or first_pos.get("positionName"),
                "zone": poi.get("zoneName"),
                "lat": (poi.get("coordinate") or {}).get("latitude"),
                "lon": (poi.get("coordinate") or {}).get("longitude"),
                "roomHint": (h.get("minPriceRoom") or {}).get("roomName"),
            })
        return out

    def hotel_rooms(self, hotel_id: int, checkin: str, checkout: str,
                    adults: int = 1, rooms: int = 1,
                    extra_head: dict | None = None, duid: str | None = None) -> dict:
        """酒店房型列表（反爬令牌 phantom-token）。

        请求体结构逆向自 hotelsearch 的 M_()：所有条件都塞进 search 对象，
        成人数量必须作为 type="29" 的 filter 出现，否则服务端认为没选人。

        注意两点（都用对照实验确认过）：
        1. 带 head.auth 会触发 htlSpiderActionErrorCode=203；
        2. 登录后拿到的 duid 也必须换掉，否则同样 203 —— duid 和 auth 必须同进同出。
        所以这里强制用"干净身份"：空 auth + 临时新 duid。代价是 priceStr 返回 "?"，
        小程序里那个位置显示为「解锁」，需要小程序内 wx.login 渠道的票据才放价。
        """
        adult_filter = [{"type": "29", "filterId": "29|1", "value": f"1|{adults}"}]
        search = {
            "hotelId": hotel_id,
            "checkIn": checkin,
            "checkOut": checkout,
            "filters": adult_filter,
            "roomFilters": adult_filter,
            "roomQuantity": rooms,
            "scenario": {"scenarioType": "", "sourceFromTag": ""},
            "extras": {"roomPriceTraceInfo": ""},
            "isFirstEnterDetailPage": "T",
            "residenceCode": "CN",
            "abResultEntities": [{"key": "isFromCtripXtaro", "value": "B"}],
            "isUserSelectPersonFilter": False,
        }
        head_extra = {
            "platform": "Applet", "group": "ctrip", "bu": "HBU",
            "locale": "zh-CN", "currency": "CNY", "timezone": "8",
            "cver": "999999",
        }
        head_extra.update(extra_head or {})
        saved_auth = self.auth
        saved_duid = self.duid
        self.auth = ""                      # 酒店通道必须匿名，见上面说明
        self.duid = duid or gen_duid()      # 登录 duid 会连坐触发 203
        try:
            body = {"search": search}
            body["head"] = self.head(head_extra)
            payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            token = self.sd_token(payload)
            url = f"{HOST}/restapi/soa2/33278/getHotelRoomListInland?_fxpcqlniredt={self.cid}"
            h = self.headers()
            h["phantom-token"] = token
            r = self.s.post(url, data=payload.encode("utf-8"), headers=h, timeout=25)
        finally:
            self.auth = saved_auth
            self.duid = saved_duid
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code, "_raw": r.text[:300]}

    @staticmethod
    def parse_rooms(resp: dict) -> list[dict]:
        """把 saleRoomMap 洗成 [{name, code, price, payType, bookText, tags}]。"""
        data = resp.get("data") or {}
        if data.get("htlSpiderActionErrorCode"):
            raise RuntimeError(f"反爬拦截: htlSpiderActionErrorCode={data['htlSpiderActionErrorCode']}")
        out = []
        for room in (data.get("saleRoomMap") or {}).values():
            btn = room.get("bookBtn") or {}
            out.append({
                "name": room.get("name"),
                "code": room.get("roomCode"),
                "price": room.get("priceStr"),
                "payType": (room.get("paymentInfo") or {}).get("paymentTitleNew"),
                "bookText": btn.get("text"),
                "bookTip": btn.get("tip"),
                "tags": [t.get("tagTitle") for t in (room.get("tagInfoList") or [])],
            })
        return out

    def sd_token(self, body_str: str, appid: str = "hotel_mini") -> str:
        """离线跑 tiny VM 生成酒店反爬令牌。"""
        link = json.loads(self.call("18433/sdtsource", {"appid": appid})["link"])
        tmp = os.path.join(CACHE_DIR, "_sd_req.json")
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"d": link["d"], "b": link["b"], "body": body_str,
                       "appid": appid, "cid": self.cid, "auth": self.auth,
                       "duid": self.duid, "udl": self.udl, "scene": self.scene,
                       "openid": self.openid}, f, ensure_ascii=False)
        res = _run_code_js("token", tmp)
        if not res.get("ok"):
            raise RuntimeError("sd_token 失败: " + str(res))
        return res["token"]


_CSIGN_CACHE: dict[str, str] = {}


def csign(md5hex: str) -> str:
    """调用离线跑起来的原版 cSign（Node harness）。"""
    if md5hex in _CSIGN_CACHE:
        return _CSIGN_CACHE[md5hex]
    val = _run_code_js("sign", md5hex).get("sign", "")
    if not val:
        raise RuntimeError("cSign 执行失败")
    _CSIGN_CACHE[md5hex] = val
    return val


# ==========================================================================
# §3 带价格 SDK   （源文件：ctrip_price.py）
# ==========================================================================
"""携程酒店「带价格」离线 SDK

背景：小程序对未登录/异常会话隐藏价格（priceInfo.price = "?"），
     但用微信渠道登录态 + 正确的 cSign/反爬令牌就能拿到真实价格。

三个关键点（都是踩坑换来的）：
1. `x-wx-openid` 要用 **mktOpenID**（UUID），不是 unionID；
2. `n-payload-source` 用 cSign(md5(payload))，线上是开着的；
3. `phantom-token` = "1005-minicommon-" + sd_token(payload)。

用法：
    c = PricedClient()
    c.hotel_list(43, "三亚", "20261107", "20261108")   # 带价格
    c.rooms(1763560, "2026-11-06", "2026-11-07")       # 房型价格
"""




UA_DEFAULT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
              "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
              "UnifiedPCWindowsWechat(0xf2541f38) XWEB/25819")

# 带价格请求的 head（抓包实测）
PRICED_HEAD = {
    "ctok": "", "cver": "999999", "lang": "01", "sid": "", "syscode": "30",
    "sauth": "", "platform": "Applet", "aid": "", "ouid": "",
    "locale": "zh-CN", "pageId": "ignore_page_pv", "currency": "CNY",
    "timezone": "8", "isSSR": False, "group": "ctrip", "bu": "HBU",
}


def load_wx_session() -> dict:
    """读取携程_config.json 的 wx 段（微信渠道凭证，带价必需）。"""
    return load_config().get("wx") or {}


def load_template() -> dict:
    with open(TEMPLATE_FILE, encoding="utf-8") as f:
        return json.load(f)


class PricedClient:
    """携程酒店带价格客户端。凭证来自 wx_session.json（抓包固化）。"""

    def __init__(self, session: dict | None = None, cid: str | None = None) -> None:
        self.sess = session or load_wx_session()
        # 默认沿用小程序会话的 cid：同设备同会话，避免另起会话被判异常
        self.cid = cid or self.sess.get("cid") or gen_cid()
        self.s = requests.Session()
        self.s.trust_env = False          # 不走系统代理，避免自己抓自己
        self._tpl = load_template()
        # 最近一次 search_priced 走的通道：id-channel / local-filter / none
        self.last_search_mode = "none"

    # ---------- 内部 ----------
    def _headers(self, payload: str, token: str) -> dict:
        q = self.sess
        h = {
            "Host": "m.ctrip.com",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "User-Agent": q.get("ua") or UA_DEFAULT,
            "xweb_xhr": "1",
            "x-ctx-locale": "zh-CN",
            "x-ctx-group": "ctrip",
            "x-ctx-region": "CN",
            "x-ctx-currency": "CNY",
            "x-ctx-personal-recommend": "1",
            "x-ctx-personal-ads-recommend": "1",
            "x-wx-include-credentials": "env",
            "x-wx-openid": q["mktOpenID"],
            "duid": q["duid"],
            "udl": q["udl"],
            "Cookie": q["cookie"],
            "Referer": f"https://servicewechat.com/{APPID}/{q.get('appVersion','1077')}/page-frame.html",
            "n-payload-source": csign(md5_hex(payload)),
            "phantom-token": token if token.startswith("1005-") else "1005-minicommon-" + token,
        }
        return h

    def _post(self, path: str, body: dict) -> dict:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        token = self._token(payload)
        h = self._headers(payload, token)
        url = f"{HOST}/restapi/soa2/{path}?_fxpcqlniredt={self.cid}"
        r = self.s.post(url, data=payload.encode("utf-8"), headers=h, timeout=30)
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code, "_raw": r.text[:300]}

    def _token(self, payload: str) -> str:
        """跑酒店反爬 VM 出 phantom-token。"""
        c = CtripClient(cid=self.cid, duid=self.sess["duid"], udl=self.sess["udl"],
                        scene=self.sess.get("scene", "1005"), use_session=False,
                        auth=self.sess["auth"], openid=self.sess["mktOpenID"])
        return c.sd_token(payload)

    # ---------- 酒店列表（带价格） ----------
    def hotel_list(self, city_id: int, city_name: str, checkin: str, checkout: str,
                   page: int = 1, size: int = 10, adults: int = 1, rooms: int = 1) -> dict:
        """城市酒店列表，checkin/checkout 用 YYYYMMDD。返回原始 dict。"""
        di = {"cityId": city_id, "cityName": city_name, "districtId": 0,
              "destinationName": city_name, "countryType": 1,
              "countryId": 1, "destinationType": 1}
        return self._hotel_list_by_dest(di, checkin, checkout,
                                        page=page, size=size, adults=adults, rooms=rooms)

    def hotel_list_by_place(self, place, checkin: str, checkout: str,
                            page: int = 1, size: int = 10,
                            adults: int = 1, rooms: int = 1) -> dict:
        """按「地区名」查酒店（带价格）—— 用户自定义地区的主入口。

        place 可以是：
          - 字符串地名："三亚" / "泰山" / "普陀山" / "浦东新区"
          - 数字：直接当 cityId（等价于 hotel_list）
          - dict：resolve_place() 的返回值

        地名解析规则见 ctrip_api.resolve_place：
        精确 → "名称(...)" 景区型 → 前缀 → 包含；命中带 districtId 的条目
        即可精确筛到景区（例如 "泰山" → cityId=454 + districtId=6）。

        checkin/checkout 用 YYYYMMDD。
        """
        if isinstance(place, dict):
            p = place
        elif isinstance(place, (int, float)):
            p = {"cityId": int(place), "districtId": 0,
                 "cityName": "", "destinationName": "", "countryType": 1, "countryId": 1}
        else:
            p = resolve_place(str(place))
            if not p:
                raise ValueError(f"解析不到地区：{place!r}（可先跑 ctrip.py places {place} 看候选）")
        di = place_to_destination(p)
        return self._hotel_list_by_dest(di, checkin, checkout,
                                        page=page, size=size, adults=adults, rooms=rooms)

    def _hotel_list_by_dest(self, di: dict, checkin: str, checkout: str,
                            page: int = 1, size: int = 10,
                            adults: int = 1, rooms: int = 1,
                            hotel_ids: list | None = None) -> dict:
        """按 destinationInfo 组装并发起 31454/fetchHotelInfoList。

        hotel_ids 非空时塞进 sceneInfo.hotelIdListInfo.searchHotelList ——
        这是小程序「带酒店清单进列表页」的通道（源码里对应 urlParams.listQuery.
        topHotels），服务端会把这些酒店排在前面并给带价卡片。**它只影响排序/优先
        召回，不裁掉兜底结果**，所以调用方要自己按 id 过滤。
        """
        body = json.loads(json.dumps(self._tpl))
        dest = body["searchInfo"]["destinationInfo"]
        dest.update(di)
        body["searchInfo"]["checkInfo"]["checkInDate"] = checkin
        body["searchInfo"]["checkInfo"]["checkOutDate"] = checkout
        body["searchInfo"]["roomQuantity"] = rooms
        body["pagingInfo"] = {"pageIndex": page, "pageSize": size}
        if hotel_ids:
            si = body.setdefault("sceneInfo", {})
            li = si.setdefault("hotelIdListInfo", {})
            li["searchHotelList"] = [int(x) for x in hotel_ids]
            li.setdefault("hotelAlreadyShown", [])
        body["head"] = {**PRICED_HEAD, "cid": self.cid, "auth": self.sess["auth"],
                        "extension": [{"name": "appId", "value": APPID},
                                      {"name": "scene", "value": self.sess.get("scene", "1005")}]}
        # 人数筛选（type 29）
        for f in body["searchInfo"].get("queryFilter", []):
            d = f.get("data") or {}
            if d.get("type") == "29":
                d["title"] = f"{adults}成人,0儿童"
                d["value"] = f"1|{adults}"
                d["filterID"] = "29|1"
        return self._post("31454/fetchHotelInfoList", body)

    # ---------- 关键词搜索（带价格） ----------
    def search_priced(self, keyword: str, checkin: str, checkout: str,
                      size: int = 20, adults: int = 1, city=None,
                      pages: int = 3) -> tuple[list[dict], list[dict]]:
        """关键词搜索 + 带价，返回 (命中的酒店行, 原始搜索结果)。

        两条通道：
          ① id 通道：30668/search 拿到关键词命中的 hotelId（type="hotel"），
             用 searchHotelList 通道送进 31454/fetchHotelInfoList，服务端回
             带价卡片，再按 id 过滤（该通道只影响排序，不裁剪兜底结果）。
          ② 本地筛：id 通道拿不到 id（属性词如 "民宿"/"海景"，30668 只回
             城市/榜单类结果）或按 id 过滤后为空时，拉 city 的列表页若干页，
             按酒店名称/地址包含关键词本地过筛 —— 列表价本来就是到手价，
             不需要二次补价。

        city 可传地名 / cityId / resolve_place() 结果；非空时搜索先在该城市
        （或景区型目的地）内召回，避免 "海景" 命到深圳、"如家" 命到漳州。

        self.last_search_mode 记录本次走的通道："id-channel" / "local-filter" /
        "none"，供 CLI 展示。
        """
        self.last_search_mode = "none"
        p, city_id, city_name = None, 0, ""
        if city not in (None, ""):
            if isinstance(city, dict):
                p = city
            elif isinstance(city, (int, float)):
                p = {"cityId": int(city), "districtId": 0, "cityName": "",
                     "countryType": 1, "countryId": 1}
            else:
                p = resolve_place(str(city))
                if not p:
                    raise ValueError(f"解析不到城市：{city!r}（先跑 places 看候选）")
            city_id = int(p.get("cityId") or 0)
            city_name = (p.get("cityName") or p.get("destinationName")
                         or p.get("name") or "")

        sc = CtripClient(cid=self.cid, duid=self.sess["duid"], udl=self.sess["udl"],
                         scene=self.sess.get("scene", "1005"), use_session=False,
                         auth=self.sess["auth"], openid=self.sess["mktOpenID"])
        raw = sc.search(keyword, city_id=city_id or None)
        ids, order = [], {}
        for x in raw:
            if x.get("type") != "hotel" or not x.get("id"):
                continue
            hid = int(x["id"])
            if hid in order:
                continue
            order[hid] = len(order)
            ids.append(hid)
            city_name = city_name or (x.get("cityName") or "")
        if not city_id:
            for x in raw:
                if x.get("type") == "hotellist" and x.get("id"):
                    city_id = int(x.get("id") or 0)
                    break
        if not ids:
            hits = self._search_local(keyword, p or city_name or city_id,
                                      checkin, checkout, pages=pages, size=size)
            self.last_search_mode = "local-filter" if hits else "none"
            return hits, raw

        if p is None and city_name:
            p = resolve_place(city_name)
        if p is None and not city_id:
            return [], raw
        di = place_to_destination(p) if p else {"cityId": city_id, "districtId": 0,
                                                "cityName": city_name,
                                                "destinationName": city_name,
                                                "countryType": 1, "countryId": 1,
                                                "destinationType": 1}
        di["cityId"] = di.get("cityId") or city_id

        r = self._hotel_list_by_dest(di, checkin, checkout,
                                     page=1, size=max(size, len(ids)),
                                     adults=adults, hotel_ids=ids)
        hits = [h for h in self.parse_hotels(r) if h.get("id") in order]
        hits.sort(key=lambda h: order.get(h.get("id"), 999))
        if not hits:
            # id 通道给了 id 但一个都没回（跨城/下架）→ 退本地筛
            hits = self._search_local(keyword, p, checkin, checkout,
                                      pages=pages, size=size)
            self.last_search_mode = "local-filter" if hits else "none"
            return hits, raw
        self.last_search_mode = "id-channel"
        return hits, raw

    def _search_local(self, keyword: str, place, checkin: str, checkout: str,
                      pages: int = 3, size: int = 20) -> list[dict]:
        """本地筛兜底：拉 place 的列表页，按名称/地址包含关键词过滤。

        适合属性词（"民宿" "海景" "温泉" "亲子"）和 30668 召回不到的品牌名。
        分词后「任一 token 命中即保留」，先剔除与城市同名的 token（"三亚 海景"
        里的 "三亚" 不该参与匹配，否则等于不过滤）。pages 越大覆盖越全，
        但每页一次请求（服务端 size=20 实回 24，按 id 去重）。
        """
        if isinstance(place, (int, float)):
            place = int(place)
        if not place:
            return []
        city_name = ""
        if isinstance(place, dict):
            city_name = (place.get("name") or place.get("cityName")
                         or place.get("destinationName") or "")
        tokens = [t for t in str(keyword).replace("　", " ").split() if t]
        if city_name:
            cut = city_name.split("(")[0]
            tokens = [t for t in tokens if t not in (city_name, cut)]
        tokens = tokens or [str(keyword)]
        seen, out = set(), []
        for pg in range(1, max(1, pages) + 1):
            try:
                r = self.hotel_list_by_place(place, checkin, checkout,
                                             page=pg, size=size)
            except Exception:  # noqa: BLE001  兜底通道失败不掩住主流程
                break
            rows = self.parse_hotels(r)
            if not rows:
                break
            fresh = 0
            for h in rows:
                hid = h.get("id")
                if hid in seen:
                    continue
                seen.add(hid)
                fresh += 1
                hay = f"{h.get('name') or ''} {h.get('address') or ''}"
                if any(t in hay for t in tokens):
                    out.append(h)
            if fresh == 0:
                break
        return out

    @staticmethod
    def parse_hotels(resp: dict) -> list[dict]:
        """洗成 [{id, name, price, original_price, star, score, comment_count, ...}]。"""
        hl = ((resp.get("data") or {}).get("hotelListInfo") or {}).get("hotelInfoList") or []
        out = []
        for x in hl:
            ui = x.get("baseUIInfo") or {}
            bi = x.get("baseInfo") or {}
            pi = x.get("priceInfo") or {}
            ci = ui.get("commentInfo") or {}
            di = ui.get("distanceAndPrice") or {}
            out.append({
                "id": bi.get("hotelId") or bi.get("masterHotelId"),
                "name": (ui.get("name") or {}).get("hotelName"),
                "price": pi.get("price"),
                "currency": pi.get("currency"),
                "original_price": pi.get("originalPrice"),
                "tax_tip": pi.get("tipAfterPrice"),
                "star": (ui.get("hotelStar") or {}).get("star"),
                "score": ci.get("score"),
                "score_desc": ci.get("scoreLevelDesc"),
                "comment_count": ci.get("commentCountDesc"),
                "collect_count": ci.get("collectCountDesc"),
                "address": (di.get("address") or di.get("positionName")) or "",
                "distance": di.get("distanceDesc") or "",
                "discounts": [t.get("title") for t in
                              ((pi.get("priceDiscountTag") or {}).get("subTagList") or [])],
                "price_detail": PricedClient._price_float(pi),
            })
        return out

    @staticmethod
    def _price_float(pi: dict) -> list[dict]:
        """priceFloat -> 每间每晚明细（房费/税费/折扣）。"""
        pf = pi.get("priceFloat") or {}
        rows = []
        for grp in pf.get("priceGroup") or []:
            for sec in grp.get("priceFloatSection") or []:
                p = sec.get("price") or {}
                rows.append({
                    "item": sec.get("title"),
                    "desc": sec.get("extraDesc") or sec.get("subExtraDesc"),
                    "price": p.get("priceText") or p.get("price"),
                    "currency": p.get("currency"),
                    "tax_desc": p.get("fuzzyTaxDesc"),
                })
        return rows

    # ---------- 房型（带价格） ----------
    def rooms(self, hotel_id: int, checkin: str, checkout: str,
              adults: int = 1, rooms: int = 1) -> dict:
        """酒店房型列表（33278，需反爬令牌）。checkin/checkout 用 YYYY-MM-DD。"""
        adult = [{"type": "29", "filterId": "29|1", "value": f"1|{adults}"}]
        body = {"search": {
            "hotelId": hotel_id, "checkIn": checkin, "checkOut": checkout,
            "filters": adult, "roomFilters": adult, "roomQuantity": rooms,
            "scenario": {"scenarioType": "", "sourceFromTag": ""},
            "extras": {"roomPriceTraceInfo": ""},
            "isFirstEnterDetailPage": "T", "residenceCode": "CN",
            "abResultEntities": [{"key": "isFromCtripXtaro", "value": "B"}],
            "isUserSelectPersonFilter": False}}
        body["head"] = {**PRICED_HEAD, "cid": self.cid, "auth": self.sess["auth"],
                        "extension": [{"name": "appId", "value": APPID},
                                      {"name": "scene", "value": self.sess.get("scene", "1005")}]}
        return self._post("33278/getHotelRoomListInland", body)

    @staticmethod
    def parse_rooms(resp: dict) -> list[dict]:
        data = resp.get("data") or {}
        out = []
        for v in (data.get("saleRoomMap") or {}).values():
            pi = v.get("paymentInfo") or {}
            pr = v.get("price") or {}                 # 房型价格在这里，不在 priceInfo
            attr = v.get("roomAttr") or {}
            out.append({
                "id": v.get("id") or v.get("physicalRoomId") or attr.get("roomID"),
                "name": v.get("name"),
                "price": pr.get("roomPriceText"),
                "avg_price": pr.get("roomAvgPriceText"),
                "currency": pr.get("priceCurrencyText"),
                "before_price": (pr.get("beforePriceText") or {}).get("priceText"),
                "book_text": (v.get("bookBtn") or {}).get("text"),
                "book_tip": (v.get("bookBtn") or {}).get("tip"),
                "pay_type": pi.get("paymentTitleNew") or pi.get("paymentTitle"),
                "area": (v.get("areaInfo") or {}).get("areaName"),
                "view": (v.get("viewInfo") or {}).get("viewName"),
                "bed": attr.get("bedTypeDesc") or attr.get("bedType"),
                "window": attr.get("window"),
                "floor": (v.get("floorInfo") or {}).get("floorDesc"),
                "max_people": attr.get("maxOccupancy") or attr.get("adult"),
                "is_package": attr.get("isPackage"),
                "breakfast": v.get("breakfastTypeDesc") or v.get("breakfast"),
                "tags": [t.get("text") if isinstance(t, dict) else t
                         for t in (v.get("featureTags") or v.get("serviceTagList") or [])],
                "fee_detail": PricedClient._fee_float(pr),
            })
        return out

    @staticmethod
    def _fee_float(pr: dict) -> list[dict]:
        """price.priceFloat -> 费用明细（房费/税/优惠）。"""
        pf = pr.get("priceFloat") or {}
        rows = []
        for grp in pf.get("priceGroup") or []:
            for sec in grp.get("priceFloatSection") or []:
                p = sec.get("price") or {}
                rows.append({
                    "item": sec.get("title"),
                    "desc": sec.get("extraDesc") or sec.get("subExtraDesc"),
                    "price": p.get("priceText") or p.get("price"),
                    "currency": p.get("currency"),
                    "tax_desc": p.get("fuzzyTaxDesc"),
                })
        return rows


# ==========================================================================
# §4 手机验证码登录   （源文件：ctrip_login.py）
# ==========================================================================
"""携程小程序 —— 手机验证码登录（纯离线，不依赖微信运行时）。

逆向自 accounts 子包，链路四步：

  1) risk/11448/sendMessageByPhoneLogin.json   风控预检（可能要图片验证码）
  2) soa2/11448/sendMessageByPhoneLogin.json   下发短信
  3) soa2/11448/checkPhoneCode.json            校验验证码 -> mobileToken
  4) soa2/12559/userLogin.json                 mobileToken -> ticket(=auth) + uid + duid

网关域名与业务域名不同：
  - 账号网关 https://passport.ctrip.com/gateway/api/...
  - 业务接口 https://m.ctrip.com/restapi/soa2/...

关键常量（taroCommon.js 里的登录配置表，非猜测）：
  DYNAMIC_LOGIN.MOBILE_QUICK_LOGIN : accessCode=MINI20210615LOGINV1 strategyCode=VERIFYCODELOGIN2021
  THIRD_LOGIN.USER_LOGIN           : accessCode=B6CE8D84FEBBFC0E   strategyCode=85D4BB47E79522CA
  THIRD_LOGIN.*.thirdConfigCode    : XTHYY69RNSKLWEICHATMINI（= 短链 accesscode）
  场景码 messageCode：LOGIN=S200078  SEARCH_ORDER=S200041
"""




GATEWAY = "https://passport.ctrip.com/gateway/api"

# ---- 登录配置常量 ----------------------------------------------------------
ACCESS_MOBILE_LOGIN = "MINI20210615LOGINV1"
STRATEGY_MOBILE_LOGIN = "VERIFYCODELOGIN2021"
ACCESS_USER_LOGIN = "B6CE8D84FEBBFC0E"
STRATEGY_USER_LOGIN = "85D4BB47E79522CA"
THIRD_CONFIG_CODE = "XTHYY69RNSKLWEICHATMINI"
MSGCODE_LOGIN = "S200078"
MSGCODE_SEARCH_ORDER = "S200041"
SEND_SCENE = "SMS-LOGIN-SITE"

PAGE_URL = "pages/accounts/pages/mobiledynamiclogin/index"
PAGE_ID = "10650014926"

DEVICE_NAME = "PC Windows 11"
OS_TYPE = "windows"


def _result_of(resp: dict) -> dict:
    """网关统一返回 {ReturnCode, Result:"<json string>"}，剥一层。"""
    outer = resp.get("ReturnCode")
    if outer != 0:
        return {"_outer_code": outer, "_outer_msg": resp.get("Message"), "_raw": resp}
    result = resp.get("Result")
    if isinstance(result, dict):
        return result
    try:
        return json.loads(result or "{}")
    except (ValueError, TypeError):
        return {"_raw": resp}


class CtripLogin:
    def __init__(self, cid: str | None = None, duid: str | None = None,
                 udl: str | None = None, scene: str = "1145") -> None:
        self.cid = cid or gen_cid()
        self.duid = duid or gen_duid()
        self.udl = udl or gen_udl()
        self.scene = scene
        self.auth = ""
        self.uid = ""
        self.mobile = ""
        self.s = requests.Session()

    # ---------- 公共头 ----------
    def head(self) -> dict:
        return {
            "cid": self.cid,
            "ctok": "",
            "cver": CVER,
            "lang": "01",
            "sid": "",
            "syscode": SYSTEM_CODE,
            "auth": self.auth,
            "sauth": "",
            "extension": [
                {"name": "appId", "value": APPID},
                {"name": "scene", "value": self.scene},
            ],
        }

    def headers(self) -> dict:
        cookie = f"DUID={self.duid};_udl={self.udl};GUID={self.cid};"
        return {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "User-Agent": UA,
            "udl": self.udl,
            "duid": self.duid,
            "Cookie": cookie,
            "x-ctx-locale": "zh-CN",
            "x-ctx-group": "ctrip",
            "x-ctx-region": "CN",
            "x-ctx-currency": "CNY",
            "x-ctx-personal-recommend": "1",
            "x-ctx-personal-ads-recommend": "1",
            "x-wx-include-credentials": "env",
            "xweb_xhr": "1",
            "Referer": f"https://servicewechat.com/{APPID}/1076/page-frame.html",
        }

    def _post(self, path: str, data: dict, timeout: int = 25) -> dict:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        url = f"{GATEWAY}/{path}?_fxpcqlniredt={self.cid}"
        r = self.s.post(url, data=payload.encode("utf-8"),
                        headers=self.headers(), timeout=timeout)
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code, "_raw": r.text[:400]}

    # ---------- 步骤 1：风控预检 ----------
    def risk_check(self, mobile: str) -> dict:
        """返回 {'ok': True} 或 {'ok': False, 'captcha': {...}}（要图片验证码）。"""
        data = {
            "AccountHead": {},
            "Data": {
                "CountryCode": "86",
                "MobilePhone": mobile,
                "sendScene": SEND_SCENE,
                "CheckMobilePhoneNumber": "NoCheck",
                "Context": [
                    {"Key": "clientID", "Value": self.cid},
                    {"Key": "Version", "Value": "1.0"},
                    {"Key": "Url", "Value": PAGE_URL},
                    {"Key": "Platform", "Value": "MINIAPP"},
                    {"Key": "page_id", "Value": PAGE_ID},
                ],
            },
            "head": self.head(),
        }
        res = _result_of(self._post("risk/11448/sendMessageByPhoneLogin.json", data))
        if res.get("ReturnCode") == 1001:
            return {"ok": False, "captcha": {
                "img_base64": "data:image/gif;base64," + res.get("ImgCode", ""),
                "captcha_id": res.get("CaptchaId", ""),
                "signature": res.get("Signature", ""),
            }}
        return {"ok": True, "raw": res}

    # ---------- 步骤 2：下发短信 ----------
    def send_sms(self, mobile: str, message_code: str = MSGCODE_LOGIN,
                 captcha: dict | None = None) -> dict:
        cap = captcha or {}
        data = {
            "AccountHead": {"ImageCaptcha": {
                "Signature": cap.get("signature", ""),
                "ImgCode": cap.get("img_code", ""),
                "CaptchaId": cap.get("captcha_id", ""),
            }},
            "Data": {
                "messageCode": message_code,
                "CountryCode": "86",
                "MobilePhone": mobile,
                "sendScene": SEND_SCENE,
                "CheckMobilePhoneNumber": "NoCheck",
                "extension": [
                    {"Key": "clientID", "Value": self.cid},
                    {"Key": "Version", "Value": "1.0"},
                    {"Key": "Url", "Value": PAGE_URL},
                    {"Key": "Platform", "Value": "MINIAPP"},
                    {"Key": "page_id", "Value": PAGE_ID},
                    {"Key": "SceneType", "Value": SEND_SCENE},
                ],
            },
            "head": self.head(),
        }
        res = _result_of(self._post("soa2/11448/sendMessageByPhoneLogin.json", data))
        self.mobile = mobile
        return res

    # ---------- 步骤 3：校验验证码 -> mobileToken ----------
    def verify_code(self, mobile: str, code: str,
                    message_code: str = MSGCODE_LOGIN) -> dict:
        data = {
            "AccountHead": {},
            "Data": {
                "messageCode": message_code,
                "code": code,
                "countryCode": "86",
                "mobilePhone": mobile,
            },
            "head": self.head(),
        }
        res = _result_of(self._post("soa2/11448/checkPhoneCode.json", data))
        if res.get("returnCode") == 0:
            res["_token"] = res.get("token", "")
        return res

    # ---------- 步骤 4：mobileToken -> ticket(auth) ----------
    def user_login(self, mobile_token: str, mobile: str = "",
                   login_type: str = "messageCode") -> dict:
        data = {
            "AccountHead": {},
            "Data": {
                "accessCode": ACCESS_USER_LOGIN,
                "strategyCode": STRATEGY_USER_LOGIN,
                "loginName": mobile or self.mobile,
                "certificateCode": mobile_token,
                "extendedProperties": [
                    {"key": "clientID", "value": self.cid},
                    {"key": "Version", "value": "1.0"},
                    {"key": "Url", "value": PAGE_URL},
                    {"key": "Platform", "value": "MINIAPP"},
                    {"key": "locale", "value": "zh_CN"},
                    {"key": "page_id", "value": PAGE_ID},
                    {"key": "thirdConfigCode", "value": THIRD_CONFIG_CODE},
                    {"key": "mobileLoginType", "value": login_type},
                    {"key": "deviceName", "value": DEVICE_NAME},
                    {"key": "OsType", "value": OS_TYPE},
                ],
            },
            "head": self.head(),
        }
        res = _result_of(self._post("soa2/12559/userLogin.json", data))
        if res.get("returnCode") == 0:
            self.auth = res.get("ticket", "") or ""
            self.uid = str(res.get("uid", "") or "")
            for kv in res.get("extendedProperties") or []:
                if kv.get("key") == "duid" and kv.get("value") not in ("", "null", None):
                    self.duid = kv["value"]
        return res

    # ---------- 一键：验证码登录 ----------
    def login(self, mobile: str, code: str,
              message_code: str = MSGCODE_LOGIN) -> dict:
        v = self.verify_code(mobile, code, message_code)
        if v.get("returnCode") != 0:
            return {"ok": False, "stage": "checkPhoneCode", "detail": v}
        token = v.get("_token") or v.get("token", "")
        if not token:
            return {"ok": False, "stage": "checkPhoneCode", "detail": v}
        u = self.user_login(token, mobile)
        if u.get("returnCode") != 0:
            return {"ok": False, "stage": "userLogin", "token": token, "detail": u}
        self.mobile = mobile
        self.save()
        check = self.check_status()
        return {"ok": True, "uid": self.uid, "auth": self.auth, "duid": self.duid,
                "expiration": check.get("expiration"), "verify": check}

    # ---------- 登录态校验 ----------
    def check_status(self) -> dict:
        """小程序「我的」页面用的官方登录态校验（13191/getTicketPropertys）。

        业务域(m.ctrip.com) + head.auth 双通道验证，返回 ticket 属性表。
        """
        data = {
            "ticket": self.auth,
            "ticketVersion": 2,
            "accountHead": {"accessCode": "8DF37737425CCFC1"},
        }
        res = CtripClient(cid=self.cid, duid=self.duid, udl=self.udl,
                          auth=self.auth, scene=self.scene).call(
            "13191/getTicketPropertys.json", data)
        prop = res.get("propertys") or {}
        return {
            "ok": res.get("returnCode") == 0,
            "returnCode": res.get("returnCode"),
            "uid": prop.get("UID"),
            "loginName": prop.get("LoginName"),
            "expiration": prop.get("Expiration"),
            "userType": prop.get("UserType"),
            "platform": prop.get("platform"),
            "raw": res,
        }

    def phone_by_ticket(self) -> dict:
        """用 ticket(auth) 反查绑定手机号，验证登录态是否真的有效。"""
        data = {
            "AccountHead": {},
            "Data": {
                "accountHead": {"locale": "zh_CN", "platform": "MINIAPP"},
                "ticket": self.auth,
                "context": [
                    {"key": "ClientID", "value": self.cid},
                    {"key": "thirdConfigCode", "value": THIRD_CONFIG_CODE},
                ],
            },
            "head": self.head(),
        }
        res = _result_of(self._post("soa2/13191/getAccountInfoByTicket.json", data))
        status = (res.get("resultStatus") or {}).get("returnCode")
        return {
            "ok": status == 0,
            "returnCode": status,
            "bindMobilePhone": res.get("bindMobilePhone"),
            "uid": res.get("uid"),
            "raw": res,
        }

    # ---------- 持久化 ----------
    def save(self, path: str = "") -> str:
        """把登录态写进 携程_config.json 的 sms 段。"""
        path = path or CONFIG_FILE
        cfg = load_config()
        cfg["sms"] = {
            "cid": self.cid, "duid": self.duid, "udl": self.udl,
            "auth": self.auth, "uid": self.uid, "mobile": self.mobile,
            "scene": self.scene,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)
        return path

    @classmethod
    def load(cls, path: str = "") -> "CtripLogin | None":
        """从 携程_config.json 的 sms 段恢复登录态。"""
        d = (load_config().get("sms") or {}) if not path else {}
        if path:
            if not os.path.exists(path):
                return None
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        if not d:
            return None
        c = cls(cid=d.get("cid"), duid=d.get("duid"), udl=d.get("udl"),
                scene=d.get("scene", "1145"))
        c.auth = d.get("auth", "")
        c.uid = d.get("uid", "")
        c.mobile = d.get("mobile", "")
        return c

    # ---------- 交给业务 SDK 用 ----------
    def to_client(self) -> CtripClient:
        c = CtripClient(cid=self.cid, duid=self.duid, udl=self.udl,
                        auth=self.auth, scene=self.scene)
        return c


def login_main() -> None:
    if len(sys.argv) < 2:
        print("用法:")
        print("  python ctrip_login.py send <手机号>")
        print("  python ctrip_login.py login <手机号> <验证码>")
        print("  python ctrip_login.py whoami")
        return
    cmd = sys.argv[1]
    if cmd == "send":
        c = CtripLogin.load() or CtripLogin()
        mobile = sys.argv[2]
        rk = c.risk_check(mobile)
        print("risk:", json.dumps(rk, ensure_ascii=False)[:300])
        if not rk["ok"]:
            print("!! 需要图片验证码，先人工过码再用 login 流程")
            return
        r = c.send_sms(mobile)
        print("send:", json.dumps(r, ensure_ascii=False)[:400])
        c.save()
    elif cmd == "login":
        c = CtripLogin.load() or CtripLogin()
        r = c.login(sys.argv[2], sys.argv[3])
        print(json.dumps(r, ensure_ascii=False)[:600])
    elif cmd == "whoami":
        c = CtripLogin.load()
        if not c:
            print("无会话")
            return
        print("uid=", c.uid, "auth=", c.auth[:40], "...", "duid=", c.duid)
        print("verify:", json.dumps(c.check_status(), ensure_ascii=False)[:400])


# ==========================================================================
# §5 微信一次性 code / thirdToken   （源文件：ctrip_wxlogin.py）
# ==========================================================================
"""携程小程序「微信一键登录」离线链路

原理：小程序每次启动都会把 wx.login 的 code 明文发给 getMKTOpenID，
      我们抓包就能拿到。拿 code 直接调 quickLoginPreCheck 换 thirdToken，
      再换 auth —— 全程不需要点按钮。

用法：
    python ctrip_wxlogin.py code            # 从 mitm.jsonl 取最新 code
    python ctrip_wxlogin.py precheck [code] # 预检，返回 thirdToken + 手机号
"""


HOST = "https://m.ctrip.com"
APPID = "wx0e6ed4f51db9d078"
WX_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/144.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
      "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
      "UnifiedPCWindowsWechat(0xf2541f38) XWEB/25819")


def latest_code(path="mitm.jsonl"):
    code = None
    with open(path, encoding="utf-8") as f:
        for ln in f:
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            if d.get("kind") not in ("request", "drop"):
                continue
            if "getMKTOpenID" in d.get("path", ""):
                m = re.search(r'"code":"([^"]+)"', d.get("req_body") or "")
                if m:
                    code = m.group(1)
    return code


def wx_session():
    s = requests.Session()
    s.trust_env = False                       # 绕开系统代理，避免自己抓自己
    s.headers.update({
        "User-Agent": WX_UA,
        "Content-Type": "application/json",
        "Accept": "*/*",
        "xweb_xhr": "1",
        "x-ctx-locale": "zh-CN",
        "x-ctx-group": "ctrip",
        "x-ctx-region": "CN",
        "x-ctx-currency": "CNY",
        "x-wx-include-credentials": "env",
        "Referer": f"https://servicewechat.com/{APPID}/1076/page-frame.html",
    })
    return s


def wx_head():
    return {
        "ctok": "", "cver": "1.2.370", "lang": "01", "sid": "",
        "syscode": "30", "auth": "", "sauth": "",
        "extension": [{"name": "appId", "value": APPID}, {"name": "scene", "value": "1027"}],
    }


def precheck(code):
    body = {
        "accessCode": "WEIXINAUTEHNTICATE",
        "clientInfo": {
            "clientId": "", "deviceName": "", "deviceType": "microsoft", "osType": "windows",
            "pageId": "10320613574", "allianceId": "262684", "sid": "711465",
            "longitude": "", "latitude": "",
        },
        "code": code,
        "head": wx_head(),
    }
    s = wx_session()
    r = s.post(f"{HOST}/restapi/soa2/24863/quickLoginPreCheck", json=body, timeout=20)
    return r.json()


def wxlogin_main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "code"
    if cmd == "code":
        c = latest_code()
        print(c or "NO_CODE")
    elif cmd == "precheck":
        code = sys.argv[2] if len(sys.argv) > 2 else latest_code()
        if not code:
            print("没有 code，先启动一次小程序")
            return 2
        print("code:", code)
        print(json.dumps(precheck(code), ensure_ascii=False)[:800])


# ==========================================================================


def _cmd_waterflow() -> None:
    c = CtripClient(scene="1145")
    r = c.waterflow()
    print("Ack:", (r.get("ResponseStatus") or {}).get("Ack"))
    d = r.get("data")
    if isinstance(d, dict):
        d = d.get("items")
    print("条目:", len(d) if isinstance(d, list) else "?")


def _cmd_search(kw: str, ci: str = "", co: str = "",
                city: str = "", pages: int = 3) -> None:
    """关键词搜索。带日期走带价通道，不带日期只看 30668 联想结果（无价格）。

    city 非空时把召回限制在该城市/景区内（属性词必须配套 city，否则会命到异地）。
    pages 是本地筛兜底时翻的列表页数（每页约 24 家）。
    """
    if ci and co:
        c = PricedClient()
        try:
            hits, raw = c.search_priced(kw, ci, co, size=20,
                                        city=city or None, pages=pages)
        except Exception as e:  # noqa: BLE001
            print("!! 带价搜索失败：", e)
            return
        mode = getattr(c, "last_search_mode", "none")
        scope = f" @{city}" if city else ""
        print(f"搜索 {kw!r}{scope}（带价 {ci}~{co}）-> 命中 {len(hits)} 条 [{mode}]")
        for h in hits:
            print(f"  {(h['name'] or '')[:24]:<26} ¥{h['price']:<6} 原价{h['original_price']:<6} "
                  f"{h['star']}星 评{h['score']} {h['comment_count']}")
        if not hits:
            if mode == "none" and city:
                print(f"  （{city} 内无命中：30668 无 type=hotel 条目，"
                      f"本地筛 {pages} 页也没匹配；可加 --pages 加大覆盖）")
            elif mode == "none":
                print("  （无命中：属性词建议加 --city 指定城市，否则 30668 只有异地块状结果）")
        return
    c = CtripClient(scene="1145")
    res = c.search(kw)
    print(f"搜索 {kw!r} -> {len(res)} 条")
    for x in res[:10]:
        print("  ", {k: x.get(k) for k in ("id", "type", "word", "cityName", "price", "scoreDesc")})


def _cmd_cities(refresh: bool = False) -> None:
    """城市表体检：条数 / 景区型目的地条数。refresh=True 时联网重抓并写回 cities.json。"""
    old = {}
    if refresh and os.path.exists(CITIES_FILE):
        try:
            with open(CITIES_FILE, encoding="utf-8") as f:
                old = json.load(f)
        except (OSError, ValueError):
            old = {}
    data = load_cities(refresh=True) if refresh else load_cities()
    for scope in ("domestic", "oversea"):
        rows = data.get(scope) or []
        scenic = sum(1 for c in rows if c.get("districtId"))
        print(f"  {scope:<9} {len(rows):>5} 条（景区型 {scenic}）")
        if refresh and old.get(scope) is not None:
            d = len(rows) - len(old[scope])
            flag = "" if d >= 0 else "  ⚠ 条数缩水，检查接口是否改版"
            print(f"            较刷新前 {d:+d}{flag}")
    if refresh:
        print(f"✓ 已写回：{CITIES_FILE}")
    else:
        print("  （加 --refresh 联网重抓并覆盖 cities.json）")


def _cmd_places(name: str) -> None:
    """地名解析：看看这个名字能解析成什么目的地 ID 组合。"""
    cities = load_cities()
    hit = resolve_place(name, cities=cities)
    if not hit:
        print(f"没解析到：{name!r}")
        pool = []
        for scope in ("domestic", "oversea"):
            pool.extend(cities.get(scope) or [])
        cand = [c for c in pool if name in c.get("name", "")][:10]
        print("相似候选：")
        for c in cand:
            print(f"   {c['name']:<24} cityId={c['cityId']} districtId={c['districtId']}")
        return
    print(f"{name!r} ->")
    for k in ("name", "destinationName", "cityName", "districtName", "provinceName",
              "countryName", "cityId", "districtId", "countryId", "countryType", "source"):
        print(f"   {k:<18} {hit.get(k)}")
    d = place_to_destination(hit)
    print("  → destinationInfo:", json.dumps(d, ensure_ascii=False))


def _cmd_hotels(place, ci: str, co: str, page: int = 1,
                size: int = 10, priced: bool = True) -> None:
    """place 可以是地名、cityId 数字，或 (city_id, city_name) 二元组。"""
    if priced:
        c = PricedClient()
        if isinstance(place, tuple):
            r = c.hotel_list(place[0], place[1], ci, co, page=page, size=size)
        else:
            r = c.hotel_list_by_place(place, ci, co, page=page, size=size)
        ext = {e.get("id"): e.get("value") for e in
               (r.get("ResponseStatus") or {}).get("Extension") or []}
        print("ResultId:", ext.get("ResultId"), "| Ack:", (r.get("ResponseStatus") or {}).get("Ack"))
        for h in c.parse_hotels(r):
            print(f"  {(h['name'] or '')[:24]:<26} ¥{h['price']:<6} 原价{h['original_price']:<6} "
                  f"{h['star']}星 评{h['score']} {h['comment_count']} {','.join(h['discounts'][:2])}")
    else:
        c = CtripClient(scene="1145", use_session=False)
        cid = place[0] if isinstance(place, tuple) else place
        if isinstance(cid, str):
            hit = resolve_place(cid)
            if not hit:
                print(f"解析不到地区：{cid!r}")
                return
            cid = hit["cityId"]
        r = c.hotel_list(cid, ci, co, page=page, size=size)
        for h in c.parse_hotels(r):
            print(f"  {(h['name'] or '')[:24]:<26} {h['price']} {h['star']}星 评{h['score']}")


def _cmd_rooms(hotel_id: int, ci: str, co: str) -> None:
    c = PricedClient()
    r = c.rooms(hotel_id, ci, co)
    data = r.get("data") or {}
    print("反爬码:", data.get(ERR_HOTEL_SPIDER), "| 房型数:", len(data.get("saleRoomMap") or {}))
    for x in c.parse_rooms(r):
        print(f"  {(x['name'] or '')[:26]:<28} ¥{x['price']:<7} 均{x['avg_price']:<7} "
              f"{x['pay_type'] or '':<5} {x['area'] or '':<6} {x['bed'] or ''}")


def _cmd_login(args: list[str]) -> None:
    cmd = args[0] if args else ""
    if cmd == "send":
        c = CtripLogin.load() or CtripLogin()
        mobile = args[1]
        rk = c.risk_check(mobile)
        print("风控预检:", json.dumps(rk, ensure_ascii=False)[:200])
        if not rk.get("ok"):
            print("!! 需要图片验证码，先人工过码")
            return
        print("发码:", json.dumps(c.send_sms(mobile), ensure_ascii=False)[:300])
        c.save()
    elif cmd == "login":
        c = CtripLogin.load() or CtripLogin()
        print(json.dumps(c.login(args[1], args[2]), ensure_ascii=False)[:600])
    elif cmd == "whoami":
        c = CtripLogin.load()
        if not c:
            print("无会话")
            return
        print("uid=", c.uid, "| auth=", c.auth[:40], "... | duid=", c.duid)
        print("校验:", json.dumps(c.check_status(), ensure_ascii=False)[:300])
    else:
        print("用法: login send|login|whoami")


# ==========================================================================
# §6 一键采集 + CSV 落盘   （用户想要：跑一下就把完整数据存成 CSV）
# ==========================================================================
"""采集流程：
   1) 解析地区名 -> 目的地 ID（resolve_place / place_to_destination）
   2) 翻页拉 31454/fetchHotelInfoList（带价），直到拉完或到 pages 上限
   3) 洗成扁平行，写 CSV（utf-8-sig，Excel 直接能开中文）
   4) 可选 --rooms：对前 N 家酒店再拉 33278 房型（带价），单独存一个 CSV

CSV 列：
   酒店: hotel_id,name,price,original_price,currency,star,score,score_desc,
        comment_count,collect_count,address,distance,discounts,price_detail
   房型: hotel_id,hotel_name,room_code,name,price,avg_price,currency,
        before_price,pay_type,area,view,bed,window,floor,max_people,
        is_package,breakfast,tags,fee_detail
   （price_detail / fee_detail 是 JSON 文本，存完整明细不丢信息）
"""


def _safe_name(s: str) -> str:
    """Windows 文件名非法字符清理。"""
    return re.sub(r'[\\/:*?"<>|]', "_", (s or "").strip())


def _write_csv(path: str, cols: list[str], rows: list[dict]) -> str:
    """写 CSV；若目标被占用（Excel/编辑器打开），自动改存带时间戳的文件名。返回实际路径。"""
    try:
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        return path
    except PermissionError:
        stamp = time.strftime("%H%M%S")
        alt = re.sub(r"\.csv$", f"_{stamp}.csv", path)
        print(f"  ⚠ 原文件被占用（可能正被 Excel/编辑器打开），改存：{alt}")
        with open(alt, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        return alt


def save_hotels_csv(hotels: list[dict], path: str) -> str:
    """酒店列表 -> CSV。返回实际写出的文件路径。"""
    cols = ["hotel_id", "name", "price", "original_price", "currency", "star",
            "score", "score_desc", "comment_count", "collect_count", "address",
            "distance", "discounts", "price_detail"]
    rows = []
    for h in hotels:
        rows.append({
            "hotel_id": h.get("id"),
            "name": h.get("name"),
            "price": h.get("price"),
            "original_price": h.get("original_price"),
            "currency": h.get("currency"),
            "star": h.get("star"),
            "score": h.get("score"),
            "score_desc": h.get("score_desc"),
            "comment_count": h.get("comment_count"),
            "collect_count": h.get("collect_count"),
            "address": h.get("address"),
            "distance": h.get("distance"),
            "discounts": " | ".join(h.get("discounts") or []),
            "price_detail": json.dumps(h.get("price_detail") or [],
                                       ensure_ascii=False),
        })
    return _write_csv(path, cols, rows)


def save_rooms_csv(rooms: list[dict], path: str) -> str:
    """房型列表 -> CSV。返回实际写出的文件路径。"""
    cols = ["hotel_id", "hotel_name", "room_code", "name", "price", "avg_price",
            "currency", "before_price", "pay_type", "area", "view", "bed",
            "window", "floor", "max_people", "is_package", "breakfast", "tags",
            "fee_detail"]
    rows = []
    for r in rooms:
        rows.append({
            "hotel_id": r.get("hotel_id"),
            "hotel_name": r.get("hotel_name"),
            "room_code": r.get("id"),
            "name": r.get("name"),
            "price": r.get("price"),
            "avg_price": r.get("avg_price"),
            "currency": r.get("currency"),
            "before_price": r.get("before_price"),
            "pay_type": r.get("pay_type"),
            "area": r.get("area"),
            "view": r.get("view"),
            "bed": r.get("bed"),
            "window": r.get("window"),
            "floor": r.get("floor"),
            "max_people": r.get("max_people"),
            "is_package": r.get("is_package"),
            "breakfast": r.get("breakfast"),
            "tags": " | ".join(str(t) for t in (r.get("tags") or []) if t not in (None, "")),
            "fee_detail": json.dumps(r.get("fee_detail") or [],
                                     ensure_ascii=False),
        })
    return _write_csv(path, cols, rows)


def _place_to_di(place) -> tuple[dict, dict]:
    """把 place（字符串/数字/dict）解析成 (原始命中, destinationInfo)。"""
    if isinstance(place, dict):
        p = place
    elif isinstance(place, (int, float)):
        p = {"cityId": int(place), "districtId": 0, "cityName": "",
             "destinationName": "", "countryType": 1, "countryId": 1}
    else:
        p = resolve_place(str(place))
        if not p:
            raise ValueError(f"解析不到地区：{place!r}（先跑 places {place} 看候选）")
    return p, place_to_destination(p)


def collect_hotels(place, checkin: str, checkout: str,
                   pages: int = 10, size: int = 20,
                   adults: int = 1, rooms_count: int = 1) -> tuple[dict, list[dict]]:
    """翻页采集某地区的酒店列表（带价）。返回 (地区信息, 酒店行列表)。

    翻页停止条件：某页返回数量 < size、整页都是重复酒店（服务端翻页有重叠，
    size=20 实际会回 24 家），或达到 pages 上限。全程按 hotelId 去重。
    """
    c = PricedClient()
    p, di = _place_to_di(place)
    all_hotels: list[dict] = []
    seen: set = set()
    for page in range(1, pages + 1):
        r = c._hotel_list_by_dest(di, checkin, checkout, page=page, size=size,
                                  adults=adults, rooms=rooms_count)
        ext = {e.get("id"): e.get("value") for e in
               (r.get("ResponseStatus") or {}).get("Extension") or []}
        rid = ext.get("ResultId")
        if rid == "203":
            print(f"  ⚠ 第{page}页被反爬拦截(ResultId=203)，停止翻页")
            break
        if rid == "4030":
            print(f"  ⚠ 第{page}页需要登录(ResultId=4030)，检查 携程_config.json 的 wx 凭证")
            break
        hs = PricedClient.parse_hotels(r)
        fresh = [h for h in hs if h.get("id") not in seen]
        print(f"  第{page}页：{len(hs)} 家，新增 {len(fresh)} (ResultId={rid})")
        if not fresh:
            print("  （整页都是前面出现过的酒店，视为到底）")
            break
        for h in fresh:
            seen.add(h.get("id"))
        all_hotels.extend(fresh)
        if len(hs) < size:
            break
        time.sleep(random.uniform(0.4, 1.0))   # 翻页间隔，温柔一点
    return p, all_hotels


def collect_rooms(hotel_pairs: list[tuple], checkin: str, checkout: str,
                  top: int = 10, adults: int = 1, rooms_count: int = 1) -> list[dict]:
    """对前 top 家酒店拉房型（带价）。hotel_pairs = [(hotel_id, name), ...]。"""
    c = PricedClient()
    out: list[dict] = []
    for i, (hid, hname) in enumerate(hotel_pairs):
        if i >= top:
            break
        try:
            r = c.rooms(hid, checkin, checkout, adults=adults, rooms=rooms_count)
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠ 酒店 {hid} 房型请求异常：{e}")
            continue
        data = r.get("data") or {}
        if data.get(ERR_HOTEL_SPIDER):
            print(f"  ⚠ 酒店 {hid} 房型被反爬拦截({data[ERR_HOTEL_SPIDER]})")
            break
        for x in PricedClient.parse_rooms(r):
            x["hotel_id"] = hid
            x["hotel_name"] = hname
            out.append(x)
        print(f"  {hname or hid}：{len(PricedClient.parse_rooms(r))} 个房型")
        time.sleep(random.uniform(0.6, 1.4))   # 房型间隔，避免连发被封
    return out


def run_collect(args: list[str]) -> int:
    """命令行 collect 的入口。参数支持默认值从 携程_config.json 的 collect 段读取。"""
    cfg = load_config().get("collect") or {}
    place = ci = co = None
    flags = {"rooms": False, "pages": int(cfg.get("pages", 10)),
             "size": int(cfg.get("size", 20)), "top": int(cfg.get("top", 10))}
    i = 0
    pos: list[str] = []
    while i < len(args):
        a = args[i]
        if a == "--rooms":
            flags["rooms"] = True
        elif a == "--pages" and i + 1 < len(args):
            flags["pages"] = int(args[i + 1]); i += 1
        elif a == "--size" and i + 1 < len(args):
            flags["size"] = int(args[i + 1]); i += 1
        elif a == "--top" and i + 1 < len(args):
            flags["top"] = int(args[i + 1]); i += 1
        else:
            pos.append(a)
        i += 1
    if pos:
        place, ci, co = (pos + [None, None, None])[:3]
    # 缺省回落到配置文件
    place = place or cfg.get("place")
    ci = ci or cfg.get("checkin")
    co = co or cfg.get("checkout")
    if not (place and ci and co):
        print("用法: collect <地区名> <入住YYYYMMDD> <离店YYYYMMDD> "
              "[--rooms] [--pages N] [--size N] [--top N]")
        print("示例: collect 泰山 20261107 20261108")
        print("      collect 三亚 20261107 20261108 --rooms --top 20")
        print("（地区/日期可只写在 携程_config.json 的 collect 段，这样直接 collect 即可）")
        return 1

    print(f"== 采集：{place} {ci}~{co} ==")
    try:
        p, hotels = collect_hotels(place, ci, co, pages=flags["pages"],
                                   size=flags["size"])
    except Exception as e:  # noqa: BLE001
        print("!! 采集失败：", e)
        return 1

    if not hotels:
        print("没有拿到任何酒店数据（可能反爬或凭证过期）。")
        return 1

    base = f"{_safe_name(str(p.get('name') or place))}_{ci}_{co}"
    out_dir = os.path.join(CACHE_DIR, "csv")
    os.makedirs(out_dir, exist_ok=True)      # 运行期产物统一落 js_reverse_cache/，根目录保持干净
    hotels_csv = os.path.join(out_dir, base + "_hotels.csv")
    hotels_csv = save_hotels_csv(hotels, hotels_csv)
    n = len(hotels)
    print(f"✓ 酒店列表已存：{hotels_csv}  ({n} 行)")

    priced = sum(1 for h in hotels if h.get("price") not in (None, "", "?"))
    print(f"  其中带价 {priced}/{n} 家"
          + ("" if priced == n else "  （部分价格为 ? 说明会话被风控，需刷新 wx 凭证）"))

    if flags["rooms"]:
        pairs = [(h.get("id"), h.get("name")) for h in hotels[:flags["top"]]]
        rooms = collect_rooms(pairs, ci, co, top=flags["top"])
        if rooms:
            rooms_csv = os.path.join(out_dir, base + "_rooms.csv")
            rooms_csv = save_rooms_csv(rooms, rooms_csv)
            m = len(rooms)
            print(f"✓ 房型已存：{rooms_csv}  ({m} 行)")
        else:
            print("  房型未采集到（可能反爬，先拿酒店列表即可）。")
    return 0


# ==========================================================================
# §7 价格快照   （同城同日期的多次采集 -> 升/降价对比）
# ==========================================================================
"""快照落在 js_reverse_cache/snapshots/<地区>_<入住>_<离店>.json，
同一个 (地区, 日期) 反复跑会追加一条 run，保留最近 SNAP_KEEP 条。

结构：
    {place, cityId, districtId, checkin, checkout,
     runs: [{taken_at, hotel_count, priced_count, note,
             hotels: {"<hotelId>": {name, price, original_price, star, score}}}]}

为什么要快照：酒店价格是按查询时刻实时算的（会员价 / 特惠 / 剩余房量），
同一家酒店隔几小时差几十上百很常见。想判断「这个价该不该订」，得看同城同日期
的历史曲线，而不是单次结果。
"""

SNAP_DIR = os.path.join(CACHE_DIR, "snapshots")
SNAP_KEEP = 20


def _num(v) -> float | None:
    """价格字段可能是 "358" / 358 / "?" / None，统一转成 float 或 None。"""
    try:
        return float(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def _snap_path(place_name: str, checkin: str, checkout: str) -> str:
    return os.path.join(SNAP_DIR, f"{_safe_name(place_name)}_{checkin}_{checkout}.json")


def snapshot_prices(place, checkin: str, checkout: str, pages: int = 1,
                    size: int = 20, note: str = "") -> dict:
    """采一次带价列表并存快照，返回 {path, run, hotels, diff, first}。

    与上一次同 key 快照比对：升/降价（按到手价）、新增、消失。
    """
    p, hotels = collect_hotels(place, checkin, checkout, pages=pages, size=size)
    name = str(p.get("name") or place)
    os.makedirs(SNAP_DIR, exist_ok=True)
    path = _snap_path(name, checkin, checkout)

    old: dict = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                old = json.load(f)
        except (OSError, ValueError):
            old = {}
    runs = old.get("runs") or []
    prev = (runs[-1].get("hotels") or {}) if runs else {}

    cur = {}
    for h in hotels:
        hid = h.get("id")
        if hid is None:
            continue
        cur[str(hid)] = {
            "name": h.get("name"),
            "price": _num(h.get("price")),
            "original_price": _num(h.get("original_price")),
            "star": h.get("star"),
            "score": h.get("score"),
        }

    up, down, new, gone = [], [], [], []
    for hid, row in cur.items():
        before = _num((prev.get(hid) or {}).get("price"))
        now = row["price"]
        if hid not in prev:
            new.append((row["name"], now))
        elif before is not None and now is not None and now != before:
            rec = (row["name"], before, now, now - before)
            (up if now > before else down).append(rec)
    for hid, row in prev.items():
        if hid not in cur:
            gone.append((row.get("name"), _num(row.get("price"))))

    runs.append({
        "taken_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hotel_count": len(cur),
        "priced_count": sum(1 for r in cur.values() if r["price"] is not None),
        "note": note,
        "hotels": cur,
    })
    data = {
        "place": name,
        "cityId": p.get("cityId"),
        "districtId": p.get("districtId") or 0,
        "checkin": checkin,
        "checkout": checkout,
        "runs": runs[-SNAP_KEEP:],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    return {"path": path, "run": len(runs), "hotels": hotels, "first": not prev,
            "up": up, "down": down, "new": new, "gone": gone}


def _cmd_snapshot(place, ci: str, co: str, pages: int = 1, size: int = 20,
                  top: int = 10, note: str = "") -> int:
    print(f"== 快照：{place} {ci}~{co} ==")
    try:
        s = snapshot_prices(place, ci, co, pages=pages, size=size, note=note)
    except Exception as e:  # noqa: BLE001
        print("!! 快照失败：", e)
        return 1
    hs = s["hotels"]
    if not hs:
        print("没有拿到酒店数据（可能反爬或凭证过期）。")
        return 1
    priced = sum(1 for h in hs if _num(h.get("price")) is not None)
    for h in hs[:top]:
        print(f"  {(h['name'] or '')[:24]:<26} ¥{h['price']:<6} 原价{h['original_price']}")
    print(f"✓ 快照已存：{s['path']}  第{s['run']}次  共{len(hs)}家（带价{priced}）")

    if s["first"]:
        print("  （该地区+日期首次快照，下次再跑就能出涨跌）")
        return 0
    print(f"  — 对比上一次：涨{len(s['up'])} / 跌{len(s['down'])} / "
          f"新增{len(s['new'])} / 消失{len(s['gone'])}")
    for name, before, now, d in sorted(s["down"], key=lambda r: r[3])[:8]:
        print(f"    ↓ {(name or '')[:22]:<24} {before:.0f} → {now:.0f}  ({d:+.0f})")
    for name, before, now, d in sorted(s["up"], key=lambda r: -r[3])[:8]:
        print(f"    ↑ {(name or '')[:22]:<24} {before:.0f} → {now:.0f}  ({d:+.0f})")
    for name, price in s["new"][:5]:
        print(f"    + {(name or '')[:22]:<24} ¥{price}")
    for name, price in s["gone"][:5]:
        print(f"    - {(name or '')[:22]:<24} ¥{price}")
    return 0


# ==========================================================================
# 统一命令行
# ==========================================================================

def main(argv: list[str]) -> int:
    if argv and argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if not argv:
        # 裸跑（不传任何参数）= 直接按 携程_config.json 的 collect 默认配置采集
        print("（未传参数，按 携程_config.json 的 collect 默认配置采集）")
        return run_collect([])
    cmd, args = argv[0], argv[1:]
    if cmd == "waterflow":
        _cmd_waterflow()
    elif cmd == "search" and args:
        # search <词>                          -> 30668 联想结果（无价）
        # search <词> <入住> <离店> [--city 三亚] [--pages 3]  -> 带价
        # 关键词可以带空格（如 "汉庭 泰安"）：末两个 8 位数字才被认成日期
        city, pages, rest, i = "", 3, [], 0
        while i < len(args):
            a = args[i]
            if a in ("--city", "--pages") and i + 1 < len(args):
                if a == "--city":
                    city = args[i + 1]
                else:
                    pages = int(args[i + 1])
                i += 2
                continue
            rest.append(a)
            i += 1
        if (len(rest) >= 3 and rest[-1].isdigit() and rest[-2].isdigit()
                and len(rest[-1]) == 8 and len(rest[-2]) == 8):
            _cmd_search(" ".join(rest[:-2]), rest[-2], rest[-1],
                        city=city, pages=pages)
        else:
            _cmd_search(" ".join(rest))
    elif cmd == "cities":
        _cmd_cities(refresh=("--refresh" in args))
    elif cmd == "snapshot" and len(args) >= 3:
        pages = size = top = None
        note = ""
        i = 0
        pos: list[str] = []
        while i < len(args):
            a = args[i]
            if a in ("--pages", "--size", "--top", "--note") and i + 1 < len(args):
                v = args[i + 1]
                if a == "--pages":
                    pages = int(v)
                elif a == "--size":
                    size = int(v)
                elif a == "--top":
                    top = int(v)
                else:
                    note = v
                i += 1
            else:
                pos.append(a)
            i += 1
        if len(pos) < 3:
            print("用法: snapshot <地区名> <入住YYYYMMDD> <离店YYYYMMDD> "
                  "[--pages N] [--size N] [--top N] [--note 备注]")
            print("示例: snapshot 三亚 20261114 20261115 --pages 2")
            return 1
        return _cmd_snapshot(pos[0], pos[1], pos[2],
                             pages=pages or 1, size=size or 20,
                             top=top or 10, note=note)
    elif cmd == "places" and args:
        _cmd_places(args[0])
    elif cmd == "hotels" and len(args) >= 3:
        page = int(args[4]) if len(args) > 4 and args[4].isdigit() else 1
        if len(args) >= 4 and args[0].isdigit():
            _cmd_hotels((int(args[0]), args[1]), args[2], args[3], page=page)
        elif len(args) == 3 and args[0].isdigit():
            _cmd_hotels(int(args[0]), args[1], args[2], page=page)
        else:
            _cmd_hotels(args[0], args[1], args[2], page=page)
    elif cmd == "rooms" and len(args) >= 3:
        _cmd_rooms(int(args[0]), args[1], args[2])
    elif cmd == "login":
        _cmd_login(args)
    elif cmd == "collect":
        return run_collect(args)
    elif cmd == "wxcode":
        print(latest_code())
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
