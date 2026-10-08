(() => {
  const HOSTING_RE = /amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|vultr|choopa|oracle|alibaba|tencent|cloudflare|m247|datacamp|leaseweb|contabo|hostinger|scaleway|fastly|zscaler|nord|express ?vpn|proton|mullvad|surfshark|private internet/i;

  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const report = { generated_at: new Date().toISOString() };

  /* ---------------- UI helpers ---------------- */

  const logEl = $("whLog");
  const log = (msg, cls = "") => {
    const line = document.createElement("div");
    line.className = "wh-log-line";
    const ts = document.createElement("span");
    ts.className = "wh-log-ts";
    ts.textContent = new Date().toISOString().slice(11, 23);
    const body = document.createElement("span");
    body.className = `wh-log-msg ${cls}`;
    body.textContent = msg;
    line.append(ts, body);
    logEl.append(line);
    logEl.scrollTop = logEl.scrollHeight;
  };

  const setKV = (listId, key, value, cls = "") => {
    const list = $(listId);
    let v = [...list.querySelectorAll(".wh-row-v")].find((el) => el.dataset.k === key);
    if (!v) {
      const row = document.createElement("div");
      row.className = "wh-row";
      const k = document.createElement("span");
      k.className = "wh-row-k";
      k.textContent = key;
      v = document.createElement("span");
      v.dataset.k = key;
      row.append(k, v);
      list.append(row);
    }
    v.textContent = value == null || value === "" ? "—" : String(value);
    v.className = `wh-row-v ${cls}`;
  };

  const setText = (id, value) => {
    $(id).textContent = value == null || value === "" ? "—" : String(value);
  };

  const setStatus = (text, state = "busy") => {
    const el = $("whStatus");
    el.dataset.state = state;
    el.querySelector(".wh-pill-text").textContent = text;
  };

  const decode = async (el, finalText, duration = 700) => {
    const glyphs = "0123456789abcdef";
    const steps = 16;
    for (let i = 0; i <= steps; i++) {
      const reveal = Math.floor((i / steps) * finalText.length);
      let out = finalText.slice(0, reveal);
      for (let j = reveal; j < finalText.length; j++) {
        out += finalText[j] === "." || finalText[j] === ":" ? finalText[j] : glyphs[(Math.random() * glyphs.length) | 0];
      }
      el.textContent = out;
      await sleep(duration / steps);
    }
    el.textContent = finalText;
  };

  /* ---------------- network helpers ---------------- */

  const fetchWithTimeout = (url, opts = {}, ms = 6000) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    return fetch(url, { ...opts, signal: ctrl.signal, cache: "no-store" }).finally(() => clearTimeout(timer));
  };

  const fetchJSON = async (url, opts, ms) => {
    const res = await fetchWithTimeout(url, opts, ms);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const getGeo = async () => {
    try {
      const d = await fetchJSON("https://ipwho.is/");
      if (!d.success) throw new Error(d.message || "ipwho.is failed");
      return {
        source: "ipwho.is",
        ip: d.ip,
        type: d.type,
        continent: d.continent,
        country: d.country,
        country_code: d.country_code,
        flag: d.flag && d.flag.emoji,
        region: d.region,
        city: d.city,
        postal: d.postal,
        lat: d.latitude,
        lon: d.longitude,
        calling_code: d.calling_code,
        asn: d.connection && d.connection.asn,
        org: d.connection && d.connection.org,
        isp: d.connection && d.connection.isp,
        domain: d.connection && d.connection.domain,
        tz: d.timezone && d.timezone.id,
        tz_offset: d.timezone && d.timezone.offset,
      };
    } catch (e) {
      log(`ipwho.is unavailable (${e.message}), falling back to ipapi.is`, "warn");
      const d = await fetchJSON("https://api.ipapi.is/");
      const asn = /^AS(\d+)\s*(.*)$/.exec(d.asn || "");
      return {
        source: "ipapi.is",
        ip: d.ip,
        type: d.ip && d.ip.includes(":") ? "IPv6" : "IPv4",
        country: d.country,
        region: d.region,
        city: d.city,
        lat: d.lat,
        lon: d.lon,
        asn: asn ? asn[1] : null,
        isp: asn ? asn[2] : null,
        org: d.company,
        tz: d.timezone,
      };
    }
  };

  const getTrace = async () => {
    const res = await fetchWithTimeout("https://www.cloudflare.com/cdn-cgi/trace");
    const text = await res.text();
    return Object.fromEntries(
      text.trim().split("\n").map((l) => {
        const i = l.indexOf("=");
        return [l.slice(0, i), l.slice(i + 1)];
      })
    );
  };

  const getStackIP = (host) =>
    fetchJSON(`https://${host}.ipify.org?format=json`, {}, 4000).then((d) => d.ip).catch(() => null);

  const expandV6 = (ip) => {
    const [head, tail = ""] = ip.split("::");
    const h = head ? head.split(":") : [];
    const t = ip.includes("::") && tail ? tail.split(":") : [];
    const fill = Array(8 - h.length - t.length).fill("0");
    return [...h, ...fill, ...t].map((g) => g.padStart(4, "0")).join("");
  };

  const getPTR = async (ip) => {
    const name = ip.includes(":")
      ? expandV6(ip).split("").reverse().join(".") + ".ip6.arpa"
      : ip.split(".").reverse().join(".") + ".in-addr.arpa";
    const d = await fetchJSON(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=PTR`,
      { headers: { accept: "application/dns-json" } },
      5000
    );
    const ans = (d.Answer || []).find((a) => a.type === 12);
    return ans ? ans.data.replace(/\.$/, "") : null;
  };

  const measureRTT = async () => {
    const samples = [];
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      try {
        await fetchWithTimeout(`https://1.1.1.1/cdn-cgi/trace?${Date.now()}`, {}, 3000);
        samples.push(performance.now() - t0);
      } catch (_) {}
    }
    return samples.length ? Math.round(Math.min(...samples)) : null;
  };

  const getWebRTC = () =>
    new Promise((resolve) => {
      if (!window.RTCPeerConnection) return resolve({ supported: false, ips: [] });
      const ips = new Set();
      let pc;
      const done = () => {
        try { pc.close(); } catch (_) {}
        resolve({ supported: true, ips: [...ips] });
      };
      try {
        pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
        pc.createDataChannel("whoami");
        pc.onicecandidate = (e) => {
          if (!e.candidate) return done();
          const parts = e.candidate.candidate.split(" ");
          const addr = parts[4];
          const typ = parts[parts.indexOf("typ") + 1];
          if (addr && typ === "srflx") ips.add(addr);
        };
        pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(done);
        setTimeout(done, 3500);
      } catch (_) {
        resolve({ supported: false, ips: [] });
      }
    });

  /* ---------------- client fingerprint ---------------- */

  const sha256 = async (str) => {
    if (!crypto.subtle) return null;
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const canvasHash = async () => {
    try {
      const c = document.createElement("canvas");
      c.width = 240;
      c.height = 60;
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(100, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("chw㉿world:~$ whoami 🛰", 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText("chw㉿world:~$ whoami 🛰", 4, 17);
      const h = await sha256(c.toDataURL());
      return h && h.slice(0, 16);
    } catch (_) {
      return null;
    }
  };

  const gpuInfo = () => {
    try {
      const gl = document.createElement("canvas").getContext("webgl");
      if (!gl) return null;
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      return ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
    } catch (_) {
      return null;
    }
  };

  const parseUA = () => {
    const ua = navigator.userAgent;
    let browser = "Unknown";
    const m =
      /(Edg|OPR|SamsungBrowser|Firefox|FxiOS|CriOS|Chrome)\/([\d.]+)/.exec(ua) ||
      (/Version\/([\d.]+).*Safari/.test(ua) && ["", "Safari", /Version\/([\d.]+)/.exec(ua)[1]]);
    if (m) {
      const names = { Edg: "Edge", OPR: "Opera", FxiOS: "Firefox", CriOS: "Chrome" };
      browser = `${names[m[1]] || m[1]} ${m[2].split(".")[0]}`;
    }
    let os = "Unknown";
    if (/Windows NT 10/.test(ua)) os = "Windows 10/11";
    else if (/Windows/.test(ua)) os = "Windows";
    else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS " + ((/OS (\d+)_/.exec(ua) || [])[1] || "");
    else if (/Mac OS X/.test(ua)) os = "macOS";
    else if (/Android/.test(ua)) os = "Android " + ((/Android ([\d.]+)/.exec(ua) || [])[1] || "");
    else if (/CrOS/.test(ua)) os = "ChromeOS";
    else if (/Linux/.test(ua)) os = "Linux";
    return { browser, os: os.trim() };
  };

  const collectClient = async () => {
    const { browser, os } = parseUA();
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const conn = navigator.connection || {};
    const c = {
      os,
      browser,
      language: (navigator.languages || [navigator.language]).join(", "),
      timezone: `${tz} (UTC${formatOffset(-new Date().getTimezoneOffset() * 60)})`,
      screen: `${screen.width}×${screen.height} @${window.devicePixelRatio}x, ${screen.colorDepth}-bit`,
      viewport: `${window.innerWidth}×${window.innerHeight}`,
      cpu_cores: navigator.hardwareConcurrency || null,
      memory: navigator.deviceMemory ? `≥ ${navigator.deviceMemory} GB` : null,
      gpu: gpuInfo(),
      touch: navigator.maxTouchPoints > 0 ? `yes (${navigator.maxTouchPoints} points)` : "no",
      network: conn.effectiveType ? `${conn.effectiveType}, ~${conn.downlink} Mbps, ${conn.rtt} ms` : null,
      do_not_track: navigator.doNotTrack === "1" ? "on" : "off",
      gpc: navigator.globalPrivacyControl ? "on" : "off",
      cookies: navigator.cookieEnabled ? "enabled" : "disabled",
      referrer: document.referrer || "direct",
      webdriver: !!navigator.webdriver,
      canvas_hash: await canvasHash(),
    };
    c.fingerprint = (await sha256(JSON.stringify([navigator.userAgent, c.language, c.timezone, c.screen, c.cpu_cores, c.memory, c.gpu, c.canvas_hash]))) || "";
    c.fingerprint = c.fingerprint.slice(0, 24);
    return c;
  };

  /* ---------------- misc ---------------- */

  function formatOffset(sec) {
    const sign = sec >= 0 ? "+" : "-";
    const a = Math.abs(sec);
    return `${sign}${String(Math.floor(a / 3600)).padStart(2, "0")}:${String(Math.floor((a % 3600) / 60)).padStart(2, "0")}`;
  }

  const haversine = (a, b) => {
    const R = 6371;
    const rad = (d) => (d * Math.PI) / 180;
    const dLat = rad(b.lat - a.lat);
    const dLon = rad(b.lon - a.lon);
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(h));
  };

  const fmtCoord = (lat, lon) => {
    const ns = lat >= 0 ? "N" : "S";
    const ew = lon >= 0 ? "E" : "W";
    return `${Math.abs(lat).toFixed(6)}° ${ns} · ${Math.abs(lon).toFixed(6)}° ${ew}`;
  };

  const getDeviceLocation = () =>
    new Promise((resolve) => {
      if (!window.isSecureContext) {
        log("device location requires HTTPS (or localhost)", "warn");
        return resolve(null);
      }
      if (!navigator.geolocation) {
        log("device location not supported by this browser", "warn");
        return resolve(null);
      }
      navigator.geolocation.getCurrentPosition(
        (p) => resolve({ lat: p.coords.latitude, lon: p.coords.longitude, accuracy_m: Math.round(p.coords.accuracy) }),
        (e) => {
          const reason = { 1: "permission denied", 2: "position unavailable", 3: "timed out" }[e.code] || "error";
          log(`device location ${reason}${e.message ? `: ${e.message}` : ""}`, "warn");
          resolve(null);
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 60000 }
      );
    });

  /* ---------------- map ---------------- */

  let map = null;

  const initMap = () => {
    if (!window.L) {
      log("map engine failed to load (leaflet)", "err");
      return;
    }
    map = L.map("whMap", {
      center: [22, 30],
      zoom: 2,
      minZoom: 2,
      worldCopyJump: true,
      scrollWheelZoom: false,
      zoomControl: false,
      attributionControl: true,
    });
    map.attributionControl.setPrefix(false);

    const esri = (service, opts = {}) =>
      L.tileLayer(`https://server.arcgisonline.com/ArcGIS/rest/services/${service}/MapServer/tile/{z}/{y}/{x}`, {
        maxZoom: 18,
        ...opts,
      });
    const layers = {
      map: L.layerGroup([
        esri("Canvas/World_Dark_Gray_Base", { className: "wh-tiles-map", attribution: "Esri" }),
        esri("Canvas/World_Dark_Gray_Reference", { className: "wh-tiles-label" }),
      ]),
      sat: L.layerGroup([
        esri("World_Imagery", { className: "wh-tiles-sat", attribution: "Esri" }),
        esri("Reference/World_Boundaries_and_Places", { className: "wh-tiles-label" }),
      ]),
    };
    let current = layers.map.addTo(map);

    document.querySelectorAll(".wh-seg button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const next = layers[btn.dataset.layer];
        if (next === current) return;
        map.removeLayer(current);
        current = next.addTo(map);
        document.querySelectorAll(".wh-seg button").forEach((b) => b.classList.toggle("is-active", b === btn));
      });
    });

    map.on("move", () => {
      const c = map.getCenter();
      $("whCoord").textContent = fmtCoord(c.lat, c.lng);
    });
  };

  let originLine = null;

  const plotOrigin = (origin, geo) => {
    if (!map || !origin || geo.lat == null || originLine) return;
    L.marker([origin.lat, origin.lon], {
      icon: L.divIcon({ className: "", html: '<div class="wh-origin-dot"></div>', iconSize: [0, 0] }),
      interactive: false,
    }).addTo(map);
    originLine = L.polyline([[origin.lat, origin.lon], [geo.lat, geo.lon]], {
      color: "#30d158",
      weight: 1,
      opacity: 0.7,
      dashArray: "2 6",
      interactive: false,
    }).addTo(map);
  };

  const lockOn = async (geo, pOrigin) => {
    if (!map || geo.lat == null) return;
    const target = [geo.lat, geo.lon];

    const origin = await Promise.race([pOrigin, sleep(1500).then(() => null)]);
    plotOrigin(origin, geo);

    if (origin && haversine(origin, geo) > 300) {
      map.flyToBounds(originLine.getBounds(), { padding: [90, 90], duration: 1.8 });
      await new Promise((r) => map.once("moveend", r));
      await sleep(300);
    }

    $("whLockText").textContent = "Tracing";
    map.flyTo(target, 12, { duration: 3.6, easeLinearity: 0.2 });
    await new Promise((r) => map.once("moveend", r));

    L.marker(target, {
      icon: L.divIcon({
        className: "",
        html: '<div class="wh-target"><div class="wh-target-h"></div><div class="wh-target-v"></div><div class="wh-target-ring"></div><div class="wh-target-ring wh-target-ring--2"></div><div class="wh-target-dot"></div></div>',
        iconSize: [0, 0],
      }),
      interactive: false,
    }).addTo(map);

    $("whLock").classList.add("is-locked");
    $("whLockText").textContent = geo.city ? `Located · ${geo.city}` : "Located";
    $("whCoord").textContent = fmtCoord(geo.lat, geo.lon);
  };

  /* ---------------- main ---------------- */

  const run = async () => {
    initMap();

    log("whoami — passive client-side trace", "step");
    log("spawning probes: geo, edge, dual-stack, webrtc, fingerprint", "step");

    const pGeo = getGeo();
    const pTrace = getTrace().catch(() => null);
    const pV4 = getStackIP("api4");
    const pV6 = getStackIP("api6");
    const pRTC = getWebRTC();
    const pRTT = measureRTT();
    const pClient = collectClient();
    const pOrigin = getDeviceLocation();

    ["IPv4", "IPv6", "Reverse DNS", "ASN", "ISP", "Organization", "Type"].forEach((k) => setKV("whNet", k, "…", "is-pending"));
    ["Country", "Region", "City", "Postal code", "Coordinates", "Time zone", "Local time"].forEach((k) => setKV("whGeo", k, "…", "is-pending"));
    ["Edge", "Protocol", "TLS", "Key exchange", "WARP", "Latency"].forEach((k) => setKV("whConn", k, "…", "is-pending"));

    /* --- geo --- */
    let geo;
    try {
      geo = await pGeo;
    } catch (e) {
      log(`geolocation failed: ${e.message}`, "err");
      setStatus("Trace failed", "error");
      $("whIp").textContent = "unknown";
      $("whLockText").textContent = "Signal lost";
      return;
    }
    report.geo = geo;
    log(`public address ${geo.ip} (${geo.type}) via ${geo.source}`, "ok");
    setStatus("Resolving");
    (geo.ip.includes(":") ? pV4 : Promise.resolve(geo.ip)).then((ip) => decode($("whIp"), ip || geo.ip));

    const locText = [geo.city, geo.region, geo.country].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(", ");
    $("whLoc").textContent = `${geo.flag ? geo.flag + "  " : ""}${locText}`;

    setKV("whNet", "ASN", geo.asn ? `AS${geo.asn}` : null);
    setKV("whNet", "ISP", geo.isp);
    setKV("whNet", "Organization", geo.org);
    const hosting = HOSTING_RE.test(`${geo.isp} ${geo.org} ${geo.domain || ""}`);
    setKV("whNet", "Type", hosting ? "Datacenter / VPN" : "Residential ISP", hosting ? "is-warn" : "");
    setText("tagNet", geo.domain || (geo.asn ? `AS${geo.asn}` : ""));
    setText("stIsp", (geo.isp || geo.org || "").replace(/[,\s]+(co\.?,?\s*ltd\.?|inc\.?|llc|corp(oration)?\.?|limited|gmbh|s\.?a\.?)$/i, ""));
    setText("stAsn", geo.asn ? `AS${geo.asn}` : "");

    setKV("whGeo", "Country", `${geo.flag || ""} ${geo.country || "—"}`.trim());
    setKV("whGeo", "Region", geo.region);
    setKV("whGeo", "City", geo.city);
    setKV("whGeo", "Postal code", geo.postal);
    setKV("whGeo", "Coordinates", geo.lat != null ? `${geo.lat.toFixed(4)}, ${geo.lon.toFixed(4)}` : null);
    setKV("whGeo", "Time zone", geo.tz ? `${geo.tz}${geo.tz_offset != null ? ` · UTC${formatOffset(geo.tz_offset)}` : ""}` : null);
    setText("tagGeo", geo.country_code || "");
    if (geo.tz) {
      const tick = () => {
        try {
          setKV("whGeo", "Local time", new Date().toLocaleTimeString("en-GB", { timeZone: geo.tz }));
        } catch (_) {}
      };
      tick();
      setInterval(tick, 1000);
    } else {
      setKV("whGeo", "Local time", null);
    }
    log(`geolocated ${locText} [${geo.lat}, ${geo.lon}]`, "ok");

    const pLock = lockOn(geo, pOrigin);
    pOrigin.then((origin) => {
      report.device_location = origin;
      if (!origin) {
        setText("stDistSub", "location not shared");
        return;
      }
      plotOrigin(origin, geo);
      if (geo.lat != null) {
        const km = Math.round(haversine(origin, geo));
        setText("stDist", `${km.toLocaleString("en-US")} km`);
      }
      log(`device location [${origin.lat.toFixed(4)}, ${origin.lon.toFixed(4)}] ±${origin.accuracy_m} m`, "ok");
    });

    /* --- PTR --- */
    log("PTR lookup over DNS-over-HTTPS", "step");
    getPTR(geo.ip)
      .then((ptr) => {
        report.ptr = ptr;
        $("whPtr").textContent = ptr || "no PTR record";
        setKV("whNet", "Reverse DNS", ptr || "no record", ptr ? "" : "is-pending");
        log(ptr ? `PTR ${ptr}` : "no PTR record", ptr ? "ok" : "warn");
      })
      .catch(() => {
        $("whPtr").textContent = "PTR lookup failed";
        setKV("whNet", "Reverse DNS", "lookup failed", "is-warn");
      });

    /* --- dual stack --- */
    const [v4, v6] = await Promise.all([pV4, pV6]);
    report.ipv4 = v4;
    report.ipv6 = v6;
    setKV("whNet", "IPv4", v4 || "not detected", v4 ? "" : "is-pending");
    setKV("whNet", "IPv6", v6 || "not detected", v6 ? "" : "is-pending");
    log(`dual-stack IPv4=${v4 || "none"} IPv6=${v6 || "none"}`, "step");

    /* --- cloudflare trace --- */
    const trace = await pTrace;
    report.cf_trace = trace;
    if (trace) {
      const pq = /mlkem|kyber/i.test(trace.kex || "");
      setKV("whConn", "Edge", trace.colo);
      setKV("whConn", "Protocol", trace.http);
      setKV("whConn", "TLS", trace.tls);
      setKV("whConn", "Key exchange", `${trace.kex || "—"}${pq ? " · PQ" : ""}`, pq ? "is-good" : "");
      setKV("whConn", "WARP", trace.warp, trace.warp === "on" || trace.warp === "plus" ? "is-warn" : "");
      setText("stEdge", trace.colo);
      setText("stEdgeSub", `${trace.http} · ${trace.tls}`);
      log(`edge ${trace.colo} · ${trace.http} · ${trace.tls} · ${trace.kex}`, "ok");
    } else {
      ["Edge", "Protocol", "TLS", "Key exchange", "WARP"].forEach((k) => setKV("whConn", k, "unavailable", "is-pending"));
      log("cloudflare trace unavailable", "warn");
    }
    const rtt = await pRTT;
    report.rtt_ms = rtt;
    setKV("whConn", "Latency", rtt != null ? `${rtt} ms` : "unavailable", rtt == null ? "is-pending" : "");
    setText("stRtt", rtt != null ? `${rtt} ms` : "—");

    /* --- client --- */
    const client = await pClient;
    report.client = client;
    [
      ["OS", client.os],
      ["Browser", client.browser],
      ["Language", client.language],
      ["Time zone", client.timezone],
      ["Display", client.screen],
      ["Viewport", client.viewport],
      ["CPU cores", client.cpu_cores],
      ["Memory", client.memory],
      ["GPU", client.gpu],
      ["Touch", client.touch],
      ["Network", client.network],
      ["DNT / GPC", `${client.do_not_track} / ${client.gpc}`],
      ["Cookies", client.cookies],
      ["Referrer", client.referrer],
      ["Canvas hash", client.canvas_hash],
    ].forEach(([k, v]) => setKV("whClient", k, v));
    setText("tagFp", client.fingerprint ? `fp ${client.fingerprint.slice(0, 12)}` : "");
    log(`client fingerprint ${client.fingerprint}`, "ok");

    /* --- webrtc --- */
    const rtc = await pRTC;
    report.webrtc = rtc;

    /* --- privacy assessment --- */
    const findings = [];
    const sameFamily = (a, b) => a.includes(":") === b.includes(":");
    const leaked = rtc.ips.filter((ip) => ip !== geo.ip && ip !== v4 && ip !== v6 && sameFamily(ip, geo.ip));
    if (!rtc.supported) {
      setKV("whRisk", "WebRTC", "disabled", "is-good");
    } else if (leaked.length) {
      setKV("whRisk", "WebRTC", `leaks ${leaked.join(", ")}`, "is-bad");
      findings.push("webrtc");
      log(`WebRTC STUN reveals a different public IP: ${leaked.join(", ")}`, "err");
    } else {
      setKV("whRisk", "WebRTC", rtc.ips.length ? "consistent" : "no candidate", "is-good");
    }

    const browserOffset = -new Date().getTimezoneOffset() * 60;
    if (geo.tz_offset != null) {
      const match = browserOffset === geo.tz_offset;
      setKV("whRisk", "Time zone", match ? "matches IP" : `UTC${formatOffset(browserOffset)} ≠ UTC${formatOffset(geo.tz_offset)}`, match ? "is-good" : "is-warn");
      if (!match) findings.push("tz");
    }

    setKV("whRisk", "IP class", hosting ? "datacenter" : "residential", hosting ? "is-warn" : "is-good");
    if (hosting) findings.push("hosting");

    const warpOn = trace && trace.warp !== "off";
    setKV("whRisk", "Cloudflare WARP", trace ? trace.warp : "unknown", warpOn ? "is-warn" : "is-good");
    if (warpOn) findings.push("warp");

    setKV("whRisk", "Automation", client.webdriver ? "webdriver" : "none", client.webdriver ? "is-bad" : "is-good");
    if (client.webdriver) findings.push("webdriver");

    const masked = findings.some((f) => ["tz", "hosting", "warp"].includes(f));
    const [label, level, note] = findings.includes("webrtc")
      ? ["Leaking", "bad", "Your proxy or VPN is bypassed — WebRTC exposes another public address."]
      : masked
      ? ["Masked", "warn", "Signals suggest a VPN, proxy or datacenter exit. Your real address is likely hidden."]
      : ["Exposed", "bad", "This is your real ISP-assigned address. Every site you visit sees it."];
    const v = $("whVerdict");
    v.textContent = label;
    v.dataset.level = level;
    $("whVerdictNote").textContent = note;
    report.assessment = { findings, verdict: label };
    log(`assessment: ${label.toLowerCase()}`, level === "bad" ? "err" : "warn");

    await pLock;
    setStatus("Located", "done");
    log("trace complete", "ok");
  };

  $("whCopy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      log("report copied to clipboard", "ok");
    } catch (_) {
      log("clipboard write blocked", "err");
    }
  });

  $("whRetrace").addEventListener("click", () => location.reload());

  run().catch((e) => {
    log(`fatal: ${e.message}`, "err");
    setStatus("Trace failed", "error");
  });
})();
