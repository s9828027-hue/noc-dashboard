/* GitHub Pages 靜態展示頁用:攔截大螢幕對 /api/* 的請求,改回傳預先算好的模擬資料(demo-data.js)。
   這裡沒有任何後端;所有數字都是 demo/demo_data.py 產生的假資料。
   作法:資料是在「建置當下」算好的,這裡把裡面所有時間平移到現在,並依目前時間挑選對應的那一格畫面,
        所以頁面看起來會持續變化(每分鐘換一組數字,每 8 分鐘有一次線路超標)。 */
(function () {
  "use strict";
  const D = window.NOC_DEMO;
  if (!D) return;
  const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

  // 把物件裡所有時間(ISO 字串、接近建置時間的 epoch 秒數)平移 delta 秒
  function shift(o, delta) {
    if (Array.isArray(o)) return o.map(v => shift(v, delta));
    if (o && typeof o === "object") { const r = {}; for (const k in o) r[k] = shift(o[k], delta); return r; }
    if (typeof o === "string" && ISO.test(o)) {
      const ms = Date.parse(o);
      return isNaN(ms) ? o : new Date(ms + delta * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
    }
    if (typeof o === "number" && Math.abs(o - D.t0) < 4 * 86400) return o + delta;
    return o;
  }
  const src = (data, period, now) => ({ available: true, age_sec: Math.floor(now % period), stale: false, data });

  function summary() {
    const now = Date.now() / 1000;
    const k = Math.floor((now % D.cycle) / 60) % D.frames.length;      // 目前該用第幾格
    const f = D.frames[k];
    const dFrame = (now - now % 60) - (D.t0 + k * 60);                  // 這一格的時間 → 這一分鐘的開頭
    const dNow = now - D.t0;
    return {
      server_time: now, topn_enabled: true, demo: true,
      netflow: src(shift(f.netflow, dFrame), 60, now),
      firewall: src(shift(f.firewall, dFrame), 60, now),
      availability: src(shift(f.availability, dFrame), 60, now),
      threat_map: src(shift(D.fixed.threat_map, dNow), 3600, now),
      risk_hits: src(shift(D.fixed.risk_hits, dNow), 300, now),
      meraki: src(shift(D.fixed.meraki, dNow), 60, now),
    };
  }

  function find(q) {
    q = (q || "").trim().toLowerCase();
    if (q.length < 3 || q.length > 40) return [400, { error: { message: "搜尋字串不正確(3~40 個字,只能用文字、數字、空白與 . : @ -)" } }];
    const now = Date.now() / 1000;
    const hits = D.find.results.filter(r => [r.mac, r.name, r.user, r.ip].map(x => String(x || "")).join(" ").toLowerCase().includes(q)
                                         || [r.mac].join("").includes(q.replace(/-/g, ":")))
      .map(r => Object.assign({}, r, { last_seen: now - (r.online ? 45 : 5400) }));
    return [200, { total: hits.length, results: hits, window_hours: D.find.window_hours || 24 }];
  }

  function diag(mac, hours) {
    mac = (mac || "").toLowerCase();
    const profile = D.diagProfile[mac] || D.diagDefault;
    const base = D.diag[profile + "|" + hours];
    if (!base) return [400, { error: { message: "參數不正確(需要完整 MAC,時間範圍只能 1、2、4、24 小時)" } }];
    const out = shift(base, Date.now() / 1000 - D.t0);
    const me = D.find.results.find(r => r.mac === mac);
    if (me && profile !== mac) {
      Object.assign(out.client, { mac: me.mac, name: me.name, user: me.user, ip: me.ip, ssid: me.ssid, ap_serial: me.ap_serial,
                                  ap_name: String(me.ap_name || "").replace("HQ-AP-", "") });
    }
    return [200, out];
  }

  function topn(line, dir) {
    const r = D.topn[line + "|" + dir];
    return r ? [200, shift(r, Date.now() / 1000 - D.t0)] : [200, { error: { message: "不認得這個線路 ID" } }];
  }

  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = function (input, init) {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    if (!url.pathname.includes("/api/")) return realFetch ? realFetch(input, init) : Promise.reject(new Error("no fetch"));
    const name = url.pathname.split("/api/")[1], qs = url.searchParams;
    let res;
    if (name === "summary") res = [200, summary()];
    else if (name === "topn") res = topn(qs.get("line"), (qs.get("dir") || "").toLowerCase());
    else if (name === "meraki_find") res = find(qs.get("q"));
    else if (name === "meraki_diag") res = diag(qs.get("mac"), qs.get("h") || "2");
    else res = [404, { error: { message: "not found" } }];
    // 加一點延遲,讓「查詢中」的畫面看得到
    return new Promise(resolve => setTimeout(() => resolve(new Response(JSON.stringify(res[1]), {
      status: res[0], headers: { "Content-Type": "application/json; charset=utf-8" } })), name === "summary" ? 60 : 350));
  };
})();
