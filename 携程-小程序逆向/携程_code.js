// 携程_code.js —— cSign 签名 + 酒店反爬令牌
//
// 运行目标小程序内的 4 个原始模块（版权归目标方，本仓库不分发，需自行提取到 vendor/）：
//   vendor/c-sign.js          cSign 签名
//   vendor/cwx.md5.js         md5
//   vendor/cwx.aes.js         aes
//   vendor/tiny.039.min.js    酒店反爬虚拟机
//
// 提取方法见 README「准备依赖模块」。
//
// 用法:
//   node 携程_code.js sign <md5hex>            -> {"sign":"102!..."}
//   node 携程_code.js token <payload.json>      -> {"ok":true,"token":"U2FsdGVkX1..."}
//
// payload.json 字段（token 子命令）:
//   {d, b, body, appid, cid, openid, auth, duid, udl, uid, uuid, scene, pageId}

const fs = require("fs");
const path = require("path");

// 目标方模块按需从 vendor/ 读取，路径固定，缺失时给出明确提示。
const VENDOR_DIR = path.join(__dirname, "vendor");
const VENDOR_FILES = {
  CSIGN: "c-sign.js",
  MD5: "cwx.md5.js",
  AES: "cwx.aes.js",
  TINY: "tiny.039.min.js",
};

function readVendor(key) {
  const name = VENDOR_FILES[key];
  const p = path.join(VENDOR_DIR, name);
  if (!fs.existsSync(p)) {
    console.error(JSON.stringify({
      ok: false,
      err: `缺少 vendor/${name}，请参考 README「准备依赖模块」`,
    }));
    process.exit(1);
  }
  return fs.readFileSync(p, "utf8");
}

// 通用模块加载器：模拟小程序的 define()/require()
function loadDefine(code, env) {
  env = env || {};
  let captured = null;
  const define = (name, factory) => {
    const module = { exports: {} };
    const req = (id) =>
      id.includes("helpers/typeof")
        ? (v) => (v === null ? "object" : typeof v)
        : {};
    factory.apply(null, [
      req, module, module.exports, globalThis,
      env.document || { cookie: "" },
      env.frames || [],
      globalThis,
      env.location || { href: "https://servicewechat.com/wx0e6ed4f51db9d078/1076/page-frame.html", protocol: "https:" },
      env.navigator || { userAgent: "MiniProgramEnv/Windows XWEB/25819", platform: "Win32" },
      env.localStorage || { getItem: () => null, setItem() {} },
      env.history || {},
      env.caches || {},
      env.screen || { width: 1280, height: 800 },
      env.alert || (() => {}),
      env.confirm || (() => true),
      env.prompt || (() => ""),
      env.xhr || function () {},
      env.ws || function () {},
      env.reporter || {},
      env.webkit || {},
      env.wxcore || {},
    ]);
    captured = module.exports;
  };
  new Function("define", "module", code)(define, { exports: {} });
  return captured;
}

// ---------------- cSign ----------------
function cSign(md5hex) {
  const code = readVendor("CSIGN");
  let captured = null;
  const define = (name, factory) => {
    const module = { exports: {} };
    const req = (id) =>
      id.includes("helpers/typeof")
        ? (v) => (v === null ? "object" : typeof v)
        : {};
    factory(
      req,
      module,
      module.exports,
      /* window */ globalThis,
      /* document */ { cookie: "", createElement: () => ({}), addEventListener() {} },
      /* frames */ [],
      /* self */ globalThis,
      /* location */ { href: "https://servicewechat.com/wx0e6ed4f51db9d078/1076/page-frame.html", protocol: "https:" },
      /* navigator */ { userAgent: "MiniProgramEnv/Windows XWEB/25819", platform: "Win32" },
      /* localStorage */ { getItem: () => null, setItem() {} },
      /* history */ {},
      /* Caches */ {},
      /* screen */ { width: 1280, height: 800 },
      /* alert */ () => {},
      /* confirm */ () => true,
      /* prompt */ () => "",
      /* XMLHttpRequest */ function () {},
      /* WebSocket */ function () {},
      /* Reporter */ {},
      /* webkit */ {},
      /* WeixinJSCore */ {}
    );
    captured = module.exports;
  };
  new Function("define", "module", code)(define, { exports: {} });
  return captured.cSign(md5hex);
}

// ---------------- 反爬令牌 phantom-token ----------------
function makeToken(req) {
  const md5 = loadDefine(readVendor("MD5")).default;
  const aes = loadDefine(readVendor("AES")).default;
  const tiny = loadDefine(readVendor("TINY"))();

  const cwx = {
    md5,
    aes,
    clientID: req.cid || "",
    appId: "wx0e6ed4f51db9d078",
    miniType: "mini",
    cwx_mkt: { openid: req.openid || "" },
    // 登录态相关：VM 可能读取 cwx.user.auth 参与签名，缺失会导致服务端判定令牌无效
    user: {
      auth: req.auth || "",
      duid: req.duid || "",
      udl: req.udl || "",
      uid: req.uid || "",
      uuid: req.uuid || "",
      isLogin: () => !!req.auth,
    },
    scene: req.scene || "",
    systemCode: "30",
    getCurrentPage: () => ({ pageId: req.pageId || "", ubtDevTrace: () => {} }),
    request: () => {},
    wxSystemInfo: {
      screenWidth: 415, screenHeight: 782,
      bluetoothEnabled: false, locationEnabled: true, wifiEnabled: true,
      SDKVersion: "3.10.0", enableDebug: false, language: "zh_CN",
      version: "8.0.5", fontSizeScaleFactor: 1, fontSizeSetting: 16,
      brand: "microsoft", model: "PC", system: "Windows 11 x64", platform: "windows",
      memorySize: 8192, batteryLevel: 100,
      albumAuthorized: true, bluetoothAuthorized: true, cameraAuthorized: true,
      locationAuthorized: true, microphoneAuthorized: true, notificationAuthorized: true,
    },
  };

  const ctx = {
    Infinity: 1 / 0, NaN, undefined: undefined, null: null,
    isFinite, isNaN, parseFloat, parseInt,
    decodeURI, decodeURIComponent, encodeURI, encodeURIComponent,
    Object, Function, Boolean, Error, Number, Math, Date, String, RegExp, Array, Map, Set, JSON, Promise,
    console, escape,
    navigator: { userAgent: "MiniProgramEnv/Windows XWEB/25819", platform: "Win32" },
    location: { href: "https://servicewechat.com/wx0e6ed4f51db9d078/1076/page-frame.html" },
    document: { cookie: "" },
    cwx,
    globals: {},
  };
  ctx.self = ctx;

  tiny(ctx, { d: req.d, b: req.b }, 0);
  try {
    return ctx.globals.signature(req.body, req.appid || "hotel_mini");
  } catch (e) {
    return "ERR:" + (e && e.message);
  }
}

// ---------------- CLI ----------------
function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "sign") {
    const md5hex = rest[0];
    if (!md5hex) {
      console.error("usage: node 携程_code.js sign <md5hex>");
      process.exit(1);
    }
    console.log(JSON.stringify({ sign: cSign(md5hex) }));
    return;
  }
  if (cmd === "token") {
    const file = rest[0];
    if (!file) {
      console.error("usage: node 携程_code.js token <payload.json>");
      process.exit(1);
    }
    const req = JSON.parse(fs.readFileSync(file, "utf8"));
    const token = makeToken(req);
    console.log(JSON.stringify({ ok: !String(token).startsWith("ERR:"), token }));
    return;
  }
  console.error("usage: node 携程_code.js sign|token ...");
  process.exit(1);
}

main();
