(() => {
  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const pad = (n) => String(n).padStart(2, "0");
  const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  const FALLBACK_OFFSET = 8 * 60;

  const userTz = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    } catch (_) {
      return null;
    }
  })();

  /* user's time zone when the browser reports one, otherwise fixed UTC+8 */
  const toZone = (d) => {
    if (userTz) {
      return { y: d.getFullYear(), mo: d.getMonth(), d: d.getDate(), wd: d.getDay(), h: d.getHours(), mi: d.getMinutes(), s: d.getSeconds() };
    }
    const u = new Date(d.getTime() + FALLBACK_OFFSET * 60000);
    return { y: u.getUTCFullYear(), mo: u.getUTCMonth(), d: u.getUTCDate(), wd: u.getUTCDay(), h: u.getUTCHours(), mi: u.getUTCMinutes(), s: u.getUTCSeconds() };
  };

  const formatDate = (now) => {
    const t = toZone(now);
    return `${t.y}/${pad(t.mo + 1)}/${pad(t.d)} ${DAYS[t.wd]}`;
  };
  const formatClock = (now) => {
    const t = toZone(now);
    return `${pad(t.h)}:${pad(t.mi)}:${pad(t.s)}`;
  };

  const formatOffset = (min) => {
    const sign = min >= 0 ? "+" : "-";
    const a = Math.abs(min);
    return `UTC${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
  };

  const decode = async (el, finalText, duration = 700) => {
    const glyphs = "0123456789abcdef";
    const steps = 16;
    for (let i = 0; i <= steps; i++) {
      const reveal = Math.floor((i / steps) * finalText.length);
      let out = finalText.slice(0, reveal);
      for (let j = reveal; j < finalText.length; j++) {
        out += /[\s/:]/.test(finalText[j]) ? finalText[j] : glyphs[(Math.random() * glyphs.length) | 0];
      }
      el.textContent = out;
      await sleep(duration / steps);
    }
    el.textContent = finalText;
  };

  const tick = $("tmTick");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const setTick = (d) => {
    const progress = (d.getSeconds() + d.getMilliseconds() / 1000) / 60;
    tick.style.transform = `scaleX(${progress})`;
  };

  const animateTick = () => {
    setTick(new Date());
    if (!reduceMotion) requestAnimationFrame(animateTick);
  };

  const render = () => {
    const now = new Date();
    $("tmDate").textContent = formatDate(now);
    $("tmClock").textContent = formatClock(now);
    if (reduceMotion) setTick(now);
    setTimeout(render, 1000 - now.getMilliseconds() + 5);
  };

  const run = async () => {
    $("tmZone").textContent = userTz ? `${userTz} · ${formatOffset(-new Date().getTimezoneOffset())}` : formatOffset(FALLBACK_OFFSET);

    const now = new Date();
    await Promise.all([decode($("tmDate"), formatDate(now)), decode($("tmClock"), formatClock(now))]);
    render();
    animateTick();
  };

  run();
})();
