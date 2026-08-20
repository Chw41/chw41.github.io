(function () {
  var badges = document.querySelectorAll(".cert-badge");
  if (!badges.length) return;

  var GLOW_ALPHA = 0.26;
  var FALLBACK = "rgba(0, 255, 156, " + GLOW_ALPHA + ")";
  var SAMPLE_SIZE = 48;
  var BUCKET_STEP = 24;

  function isVividPixel(r, g, b, a) {
    if (a < 200) return false;
    var mx = Math.max(r, g, b);
    var mn = Math.min(r, g, b);
    var sat = mx === 0 ? 0 : (mx - mn) / mx;
    var val = mx / 255;
    if (val < 0.12) return false;
    if (val > 0.95 && sat < 0.25) return false;
    if (sat < 0.35) return false;
    return true;
  }

  function extractGlowColor(img) {
    try {
      var canvas = document.createElement("canvas");
      canvas.width = SAMPLE_SIZE;
      canvas.height = SAMPLE_SIZE;
      var ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, SAMPLE_SIZE, SAMPLE_SIZE);

      var data = ctx.getImageData(0, 0, SAMPLE_SIZE, SAMPLE_SIZE).data;
      var buckets = Object.create(null);

      for (var i = 0; i < data.length; i += 4) {
        var r = data[i], g = data[i + 1], b = data[i + 2], a = data[i + 3];
        if (!isVividPixel(r, g, b, a)) continue;

        var key =
          Math.round(r / BUCKET_STEP) + "," +
          Math.round(g / BUCKET_STEP) + "," +
          Math.round(b / BUCKET_STEP);

        var bucket = buckets[key] || (buckets[key] = { r: 0, g: 0, b: 0, count: 0 });
        bucket.r += r;
        bucket.g += g;
        bucket.b += b;
        bucket.count += 1;
      }

      var best = null;
      for (var k in buckets) {
        if (!best || buckets[k].count > best.count) best = buckets[k];
      }
      if (!best) return null;

      var rr = Math.round(best.r / best.count);
      var gg = Math.round(best.g / best.count);
      var bb = Math.round(best.b / best.count);
      return "rgba(" + rr + ", " + gg + ", " + bb + ", " + GLOW_ALPHA + ")";
    } catch (err) {
      return null;
    }
  }

  function applyGlow(badge, img) {
    badge.style.setProperty("--cert-glow", extractGlowColor(img) || FALLBACK);
  }

  badges.forEach(function (badge) {
    var img = badge.querySelector("img");
    if (!img) return;

    if (img.complete && img.naturalWidth > 0) {
      applyGlow(badge, img);
    } else {
      img.addEventListener("load", function () { applyGlow(badge, img); }, { once: true });
    }
  });
})();
