#!/usr/bin/env node
/**
 * 界面冒烟桩（F4）：**运行时**从 src/bmcdhcp/ui/index.html 里抽取真函数来跑，
 * 不复制粘贴任何应用代码 —— 页面里的 api()/loadIfaces()/renderIfaceError() 改坏了，
 * 这里必须跟着红。
 *
 * 用法：
 *   node tools/ui_smoke.mjs                 # 跑仓库里的 index.html
 *   node tools/ui_smoke.mjs --html /tmp/x.html   # 跑变异过的副本（变异测试用）
 *   node tools/ui_smoke.mjs --quiet         # 只打一行汇总
 *
 * 覆盖：
 *   1. 500 连击 → 恰好 1 次自动重试，且重试带 ?refresh=1
 *   2. AbortError → 文案含超时秒数（GET 8s / POST 30s），且请求真的带 AbortSignal
 *   3. 超时/重试链被改坏（API_TIMEOUT_GET=0、删掉 AbortController）→ 必红
 *   4. 0 网卡 → 下拉有占位项 + 手填入口可见
 *   5. 全是 Wi-Fi/虚拟网卡 → 下拉不为空且**不替用户选 Wi-Fi**
 *   6. ok=false → 逐级枚举原因渲染出来
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_HTML = path.join(HERE, "..", "src", "bmcdhcp", "ui", "index.html");

function parseArgs(argv) {
  const out = { html: DEFAULT_HTML, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--html" && argv[i + 1]) {
      out.html = path.resolve(argv[i + 1]);
      i += 1;
    } else if (argv[i] === "--quiet") {
      out.quiet = true;
    }
  }
  return out;
}

/** 从源码里抠出 `function NAME(...) {...}` 的完整源码（花括号配平）。 */
function extractFunction(source, name) {
  let start = source.indexOf("function " + name + "(");
  if (start < 0) throw new Error("index.html 里找不到函数 " + name + "()");
  // `async function` 的 async 也要一起抠出来，否则 await 在非 async 函数里直接语法错
  if (source.slice(start - 6, start) === "async ") start -= 6;
  let depth = 0;
  let opened = false;
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "{") {
      depth += 1;
      opened = true;
    } else if (ch === "}") {
      depth -= 1;
      if (opened && depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error("函数 " + name + "() 的花括号没配平");
}

/** 从源码里抠出 `const NAME = ...;`（去掉行尾注释）。 */
function extractConst(source, name) {
  const re = new RegExp("const\\s+" + name + "\\s*=\\s*([^;\\n]+);");
  const m = re.exec(source);
  if (!m) throw new Error("index.html 里找不到常量 " + name);
  return "const " + name + " = " + m[1].trim() + ";";
}

// ---------------- 极简 DOM ----------------

class El {
  constructor(tag) {
    this.tag = tag || "div";
    this._text = "";
    this.value = "";
    this.checked = false;
    this.style = {};
    this.dataset = {};
    this.children = [];
    this.selectedOptions = [];
    this.className = "";
    this.classList = { toggle() {}, add() {}, remove() {} };
  }

  get textContent() {
    return this._text;
  }

  set textContent(v) {
    this._text = String(v);
    if (this.tag === "select" && this._text === "") {
      this.children = [];
      this.selectedOptions = [];
    }
  }

  get firstChild() {
    return this.children.length ? this.children[0] : null;
  }

  appendChild(child) {
    this.children.push(child);
    if (this.tag === "select") {
      this.selectedOptions = [{ value: child.value, dataset: child.dataset || {} }];
    }
    return child;
  }

  insertBefore(child) {
    this.children.unshift(child);
    if (this.tag === "select") {
      this.selectedOptions = [{ value: child.value, dataset: child.dataset || {} }];
    }
    return child;
  }

  addEventListener() {}
  remove() {}
}

function makeDocument() {
  const els = new Map();
  return {
    getElementById(id) {
      if (!els.has(id)) {
        // iface 是 <select>（textContent="" 要清空 children），showAllIfaces 是复选框
        const tag = id === "iface" ? "select" : (id === "showAllIfaces" ? "input" : "div");
        els.set(id, new El(tag));
        els.get(id).id = id;
      }
      return els.get(id);
    },
    createElement(tag) {
      return new El(tag);
    },
    _els: els,
  };
}

function makeResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

// ---------------- 装配被测函数 ----------------

function buildApp(htmlSource, opts) {
  const doc = makeDocument();
  const env = {
    document: doc,
    fetch: opts.fetch,
    AbortController,
    // 真定时器会把 node 拖 8 秒（而且重试里的 sleep(1200) 会真的等）：
    // 这里只做「异步化」，不真的走时钟 —— 超时逻辑靠 fetch 抛 AbortError 验证。
    setTimeout: (fn) => {
      Promise.resolve().then(() => {
        try {
          fn();
        } catch (e) {
          /* ignore */
        }
      });
      return 1;
    },
    clearTimeout: () => {},
    TOKEN: "test-token",
    SHOW_ALL: false,
    S: {
      ifaces: [], candidates: [], platform: "", enum: null,
      ifacesError: "", ifacesSource: "", autoCidrs: "", tab: "leases",
    },
    wantedIface: "",
    wantedService: "",
  };

  const parts = [
    extractConst(htmlSource, "API_TIMEOUT_GET"),
    extractConst(htmlSource, "API_TIMEOUT_POST"),
    extractFunction(htmlSource, "api"),
    extractFunction(htmlSource, "sleep"),
    extractFunction(htmlSource, "ifaceOption"),
    extractFunction(htmlSource, "renderIfaceError"),
    extractFunction(htmlSource, "applyDefaultCidrs"),
    extractFunction(htmlSource, "loadIfaces"),
  ];

  const body = `
    "use strict";
    const document = env.document, fetch = env.fetch, AbortController = env.AbortController,
          setTimeout = env.setTimeout, clearTimeout = env.clearTimeout,
          TOKEN = env.TOKEN, SHOW_ALL = env.SHOW_ALL, S = env.S,
          wantedIface = env.wantedIface, wantedService = env.wantedService;
    const $ = (id) => document.getElementById(id);
    ${parts.join("\n")}
    return { api, loadIfaces, renderIfaceError, ifaceOption, applyDefaultCidrs, S,
             document, API_TIMEOUT_GET, API_TIMEOUT_POST };
  `;

  // eslint-disable-next-line no-new-func
  const factory = new Function("env", body);
  return factory(env);
}

// ---------------- 断言 ----------------

const results = { total: 0, failures: [] };

function check(cond, message) {
  results.total += 1;
  if (!cond) results.failures.push(message);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const html = fs.readFileSync(args.html, "utf8");
  const log = (line) => {
    if (!args.quiet) console.log(line);
  };

  // ---- 场景 1：500 连击 → 恰好 1 次重试，且重试带 ?refresh=1 ----
  {
    const calls = [];
    const app = buildApp(html, {
      fetch: async (url) => {
        calls.push(url);
        return makeResponse(500, { error: "枚举失败了" });
      },
    });
    await app.loadIfaces(false, {});
    check(calls.length === 2, "500 只应重试一次（实际 " + calls.length + " 次请求）");
    check(calls[0] === "/api/ifaces", "首次请求不该带 refresh（实际 " + calls[0] + "）");
    check(calls[1] === "/api/ifaces?refresh=1", "重试必须带 ?refresh=1（实际 " + calls[1] + "）");
    check(String(app.S.ifacesError).includes("枚举失败了"), "失败原因要写进 S.ifacesError");
    const sel = app.document.getElementById("iface");
    check(sel.children.length === 1, "失败后下拉框只应有 1 条占位项");
    check(sel.children[0] && sel.children[0].textContent === "— 读不到网卡列表 —",
      "占位项文案必须是「— 读不到网卡列表 —」");
    check(app.document.getElementById("ifaceManualRow").style.display === "",
      "失败时必须露出「手填网卡名」入口");
    check(sel.value === "" || sel.value === undefined, "失败时不许自动选一个不存在的网卡");
    log("  [1] 500 连击：请求 " + calls.length + " 次，重试 URL = " + calls[1]);
  }

  // ---- 场景 2：AbortError → 文案含超时秒数；请求必须带 AbortSignal ----
  {
    const opts = [];
    const app = buildApp(html, {
      fetch: async (url, o) => {
        opts.push(o || {});
        const err = new Error("aborted");
        err.name = "AbortError";
        throw err;
      },
    });
    let getMsg = "";
    try {
      await app.api("/api/ifaces");
    } catch (e) {
      getMsg = e.message;
    }
    let postMsg = "";
    try {
      await app.api("/api/start", { iface: "en9" });
    } catch (e) {
      postMsg = e.message;
    }
    check(/请求超时（8 秒）/.test(getMsg), "GET 超时文案要含「8 秒」（实际：" + getMsg + "）");
    check(getMsg.includes("/api/ifaces"), "GET 超时文案要带请求路径（实际：" + getMsg + "）");
    check(/请求超时（30 秒）/.test(postMsg), "POST 超时文案要含「30 秒」（实际：" + postMsg + "）");
    check(opts[0] && opts[0].signal != null, "GET 请求必须带 AbortSignal（AbortController 生效）");
    check(opts[1] && opts[1].signal != null, "POST 请求必须带 AbortSignal");
    check(app.API_TIMEOUT_GET === 8000, "API_TIMEOUT_GET 必须还是 8000（实际 " + app.API_TIMEOUT_GET + "）");
    check(app.API_TIMEOUT_POST === 30000, "API_TIMEOUT_POST 必须还是 30000（实际 " + app.API_TIMEOUT_POST + "）");
    log("  [2] 超时文案：" + getMsg + " / " + postMsg);
  }

  // ---- 场景 3：0 网卡 → 占位项 + 手填入口 ----
  {
    const app = buildApp(html, {
      fetch: async () => makeResponse(200, {
        ok: true, platform: "windows", ifaces: [], candidates: [], error: "",
      }),
    });
    await app.loadIfaces(false, {});
    const sel = app.document.getElementById("iface");
    check(sel.children.length === 1, "0 网卡时下拉框要有且只有一条占位项");
    check(sel.children[0].textContent === "— 没有读到网卡（可在下面手填网卡名）—",
      "0 网卡占位文案不对：" + (sel.children[0] && sel.children[0].textContent));
    check(app.document.getElementById("ifaceCount").textContent === "读不到网卡",
      "0 网卡时计数文案要是「读不到网卡」");
    check(app.document.getElementById("ifaceManualRow").style.display === "",
      "0 网卡时必须露出手填入口");
    check(String(app.document.getElementById("ifaceHint").textContent).includes("手填"),
      "0 网卡时提示要告诉用户可以手填");
    log("  [3] 0 网卡：占位 = " + sel.children[0].textContent);
  }

  // ---- 场景 4：全是 Wi-Fi / 虚拟 → 不隐藏、不替用户选 Wi-Fi ----
  {
    const app = buildApp(html, {
      fetch: async () => makeResponse(200, {
        ok: true, platform: "windows", candidates: [], error: "",
        ifaces: [
          { name: "WLAN", service: "WLAN", mac: "aa:bb:cc:dd:ee:01", wifi: true,
            virtual: false, tunnel: false, loopback: false, has_link: true },
          { name: "vEthernet (Default Switch)", service: "vEthernet (Default Switch)",
            mac: "00:15:5d:00:00:01", wifi: false, virtual: true, tunnel: false,
            loopback: false, has_link: true },
        ],
      }),
    });
    await app.loadIfaces(false, {});
    const sel = app.document.getElementById("iface");
    const values = sel.children.map((c) => c.value);
    check(values.includes("WLAN"), "Wi-Fi 网卡不能被藏起来（只是不自动选）");
    check(values.length >= 3, "下拉框里应有「占位项 + 2 张网卡」（实际 " + values.length + " 项）");
    check(sel.value === "" || sel.value === undefined, "不许替用户自动选中 Wi-Fi：" + sel.value);
    check(app.document.getElementById("showAllIfaces").checked === true,
      "没有正经有线口时应自动勾上「显示虚拟/Wi-Fi」");
    check(String(app.document.getElementById("ifaceHint").textContent || "").length > 0,
      "全部不可自动挑选时也要有提示文案");
    log("  [4] 全 Wi-Fi/虚拟：下拉 " + JSON.stringify(values) + "，选中 = " + JSON.stringify(sel.value));
  }

  // ---- 场景 5：ok=false → 逐级原因要渲染出来 ----
  {
    const reason = "ctypes：GAA 炸了；powershell：被策略拦；ipconfig：空";
    const app = buildApp(html, {
      fetch: async () => makeResponse(200, {
        ok: false, platform: "windows", ifaces: [], candidates: [], error: reason,
      }),
    });
    await app.loadIfaces(false, {});
    check(app.S.ifacesError === reason, "S.ifacesError 要原样保留后端给的逐级原因");
    const hint = String(app.document.getElementById("ifaceHint").textContent);
    check(hint.includes("ctypes：GAA 炸了"), "提示里要能看到 ctypes 那一级的原因：" + hint);
    check(hint.includes("powershell：被策略拦"), "提示里要能看到 powershell 那一级的原因");
    check(hint.includes("ipconfig：空"), "提示里要能看到 ipconfig 那一级的原因");
    check(hint.includes("手填"), "枚举失败时也要告诉用户可以手填");
    log("  [5] ok=false 提示：" + hint);
  }

  // ---- 场景 6：正常枚举 → 选中链路最好的那张，且不误报错误 ----
  {
    const app = buildApp(html, {
      fetch: async () => makeResponse(200, {
        ok: true, platform: "windows", candidates: ["以太网 2"], error: "",
        ifaces: [
          { name: "WLAN", service: "WLAN", wifi: true, virtual: false, has_link: false,
            loopback: false },
          { name: "以太网 2", service: "以太网 2", mac: "b0:83:fe:11:22:33", wifi: false,
            virtual: false, has_link: true, ipv4: "192.168.0.10", default_route: true,
            scan_cidrs: ["192.168.0.0/24"] },
        ],
      }),
    });
    await app.loadIfaces(false, {});
    const sel = app.document.getElementById("iface");
    check(sel.value === "以太网 2", "有链路的有线口要被选中（实际 " + sel.value + "）");
    check(app.S.ifacesError === "", "枚举成功时不该带错误文案");
    check(String(app.document.getElementById("ifaceCount").textContent).includes("个网口"),
      "成功时计数文案应是「N 个网口」");
    check(app.document.getElementById("scanCidrs").value === "192.168.0.0/24",
      "选中网卡后要带出默认扫描网段");
    check(app.document.getElementById("ifaceManualRow").style.display === "none",
      "正常枚举 + 有选中时不该一直摊着手填入");
    log("  [6] 正常枚举：选中 " + sel.value + "，hint = " + app.document.getElementById("ifaceHint").textContent);
  }

  const passed = results.total - results.failures.length;
  if (results.failures.length) {
    console.error("UI smoke: " + passed + "/" + results.total + " passed");
    for (const f of results.failures) console.error("  ✗ " + f);
    process.exit(1);
  }
  console.log("UI smoke: " + passed + "/" + results.total + " passed（源：" + args.html + "）");
}

main().catch((err) => {
  console.error("UI smoke 崩了：" + (err && err.stack ? err.stack : err));
  process.exit(1);
});
