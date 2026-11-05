(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const nextFrame = () => new Promise((r) => requestAnimationFrame(() => r()));

  /* ---------------- limits ---------------- */

  const READ_CAP = 350 * 1024 * 1024; // bytes read into memory
  const MD5_CAP = 100 * 1024 * 1024;  // MD5 is pure-JS → cap it
  const SCAN_MAX = 2000000;           // samples used for entropy / histogram / byte map
  const STRINGS_SCAN = 16 * 1024 * 1024;
  const STRINGS_MAX = 400;
  const HEX_START = 512;
  const HEX_STEP = 2048;
  const HEX_CAP = 64 * 1024;

  /* ---------------- UI helpers ---------------- */

  const logEl = $("upLog");
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

  const setStatus = (text, state = "busy") => {
    const el = $("upStatus");
    el.dataset.state = state;
    el.querySelector(".wh-pill-text").textContent = text;
  };

  const addRow = (listId, key, value, cls = "") => {
    const list = $(listId);
    const row = document.createElement("div");
    row.className = "wh-row";
    const k = document.createElement("span");
    k.className = "wh-row-k";
    k.textContent = key;
    const v = document.createElement("span");
    v.className = `wh-row-v ${cls}`;
    v.textContent = value == null || value === "" ? "·" : String(value);
    row.append(k, v);
    list.append(row);
  };

  const fmtBytes = (n) => {
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB", "TB"];
    let i = -1, x = n;
    do { x /= 1024; i++; } while (x >= 1024 && i < u.length - 1);
    return `${x.toFixed(x < 10 ? 2 : 1)} ${u[i]} (${n.toLocaleString("en-US")} B)`;
  };

  const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");

  /* ---------------- MD5 (operates on a Uint8Array) ---------------- */

  const md5 = (() => {
    const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = new Int32Array(64);
    for (let i = 0; i < 64; i++) K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0;
    const rol = (x, c) => (x << c) | (x >>> (32 - c));

    return (bytes) => {
      const origLen = bytes.length;
      const bitLen = origLen * 8;
      const padLen = ((origLen + 8) >> 6 << 6) + 64; // multiple of 64, room for 1 + length
      const buf = new Uint8Array(padLen);
      buf.set(bytes);
      buf[origLen] = 0x80;
      // 64-bit little-endian length (low 32 bits enough for our sizes, but write both)
      const lenLo = bitLen >>> 0;
      const lenHi = Math.floor(bitLen / 4294967296) >>> 0;
      buf[padLen - 8] = lenLo & 0xff;
      buf[padLen - 7] = (lenLo >>> 8) & 0xff;
      buf[padLen - 6] = (lenLo >>> 16) & 0xff;
      buf[padLen - 5] = (lenLo >>> 24) & 0xff;
      buf[padLen - 4] = lenHi & 0xff;
      buf[padLen - 3] = (lenHi >>> 8) & 0xff;
      buf[padLen - 2] = (lenHi >>> 16) & 0xff;
      buf[padLen - 1] = (lenHi >>> 24) & 0xff;

      let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
      const M = new Int32Array(16);

      for (let off = 0; off < padLen; off += 64) {
        for (let i = 0; i < 16; i++) {
          const j = off + i * 4;
          M[i] = buf[j] | (buf[j + 1] << 8) | (buf[j + 2] << 16) | (buf[j + 3] << 24);
        }
        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
          let F, g;
          if (i < 16) { F = (B & C) | (~B & D); g = i; }
          else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
          else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
          else { F = C ^ (B | ~D); g = (7 * i) & 15; }
          F = (F + A + K[i] + M[g]) | 0;
          A = D; D = C; C = B;
          B = (B + rol(F, s[i])) | 0;
        }
        a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
      }

      const out = (x) => {
        let h = "";
        for (let i = 0; i < 4; i++) h += ((x >>> (i * 8)) & 0xff).toString(16).padStart(2, "0");
        return h;
      };
      return out(a0) + out(b0) + out(c0) + out(d0);
    };
  })();

  const digestHex = async (algo, bytes) => {
    const h = await crypto.subtle.digest(algo, bytes);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  /* ---------------- magic-byte signatures ---------------- */
  // bytes: array of numbers; null = wildcard
  const SIGNATURES = [
    { o: 0, b: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], label: "PNG image", ext: "png", mime: "image/png" },
    { o: 0, b: [0xff, 0xd8, 0xff], label: "JPEG image", ext: "jpg", mime: "image/jpeg" },
    { o: 0, b: [0x47, 0x49, 0x46, 0x38], label: "GIF image", ext: "gif", mime: "image/gif" },
    { o: 0, b: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50], label: "WebP image", ext: "webp", mime: "image/webp" },
    { o: 0, b: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45], label: "WAV audio", ext: "wav", mime: "audio/wav" },
    { o: 0, b: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x41, 0x56, 0x49, 0x20], label: "AVI video", ext: "avi", mime: "video/x-msvideo" },
    { o: 0, b: [0x42, 0x4d], label: "BMP image", ext: "bmp", mime: "image/bmp" },
    { o: 0, b: [0x00, 0x00, 0x01, 0x00], label: "ICO icon", ext: "ico", mime: "image/x-icon" },
    { o: 0, b: [0x25, 0x50, 0x44, 0x46], label: "PDF document", ext: "pdf", mime: "application/pdf" },
    { o: 0, b: [0x50, 0x4b, 0x03, 0x04], label: "ZIP archive (or docx/xlsx/jar/apk)", ext: "zip", mime: "application/zip" },
    { o: 0, b: [0x50, 0x4b, 0x05, 0x06], label: "ZIP archive (empty)", ext: "zip", mime: "application/zip" },
    { o: 0, b: [0x1f, 0x8b], label: "GZIP archive", ext: "gz", mime: "application/gzip" },
    { o: 0, b: [0x42, 0x5a, 0x68], label: "BZIP2 archive", ext: "bz2", mime: "application/x-bzip2" },
    { o: 0, b: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], label: "XZ archive", ext: "xz", mime: "application/x-xz" },
    { o: 0, b: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], label: "RAR archive", ext: "rar", mime: "application/vnd.rar" },
    { o: 0, b: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], label: "7-Zip archive", ext: "7z", mime: "application/x-7z-compressed" },
    { o: 257, b: [0x75, 0x73, 0x74, 0x61, 0x72], label: "TAR archive", ext: "tar", mime: "application/x-tar" },
    { o: 0, b: [0x7f, 0x45, 0x4c, 0x46], label: "ELF executable", ext: "elf", mime: "application/x-elf" },
    { o: 0, b: [0x4d, 0x5a], label: "Windows PE executable", ext: "exe", mime: "application/x-msdownload" },
    { o: 0, b: [0xca, 0xfe, 0xba, 0xbe], label: "Java class / Mach-O fat binary", ext: "class", mime: "application/java-vm" },
    { o: 0, b: [0xfe, 0xed, 0xfa, 0xce], label: "Mach-O (32-bit)", ext: "macho", mime: "application/x-mach-binary" },
    { o: 0, b: [0xfe, 0xed, 0xfa, 0xcf], label: "Mach-O (64-bit)", ext: "macho", mime: "application/x-mach-binary" },
    { o: 0, b: [0xcf, 0xfa, 0xed, 0xfe], label: "Mach-O (64-bit, LE)", ext: "macho", mime: "application/x-mach-binary" },
    { o: 0, b: [0x00, 0x61, 0x73, 0x6d], label: "WebAssembly module", ext: "wasm", mime: "application/wasm" },
    { o: 0, b: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], label: "SQLite database", ext: "sqlite", mime: "application/vnd.sqlite3" },
    { o: 0, b: [0x49, 0x44, 0x33], label: "MP3 audio (ID3)", ext: "mp3", mime: "audio/mpeg" },
    { o: 0, b: [0x4f, 0x67, 0x67, 0x53], label: "OGG media", ext: "ogg", mime: "audio/ogg" },
    { o: 0, b: [0x66, 0x4c, 0x61, 0x43], label: "FLAC audio", ext: "flac", mime: "audio/flac" },
    { o: 0, b: [0x1a, 0x45, 0xdf, 0xa3], label: "Matroska / WebM", ext: "mkv", mime: "video/x-matroska" },
    { o: 0, b: [0x25, 0x21, 0x50, 0x53], label: "PostScript", ext: "ps", mime: "application/postscript" },
    { o: 0, b: [0x49, 0x49, 0x2a, 0x00], label: "TIFF image (LE)", ext: "tiff", mime: "image/tiff" },
    { o: 0, b: [0x4d, 0x4d, 0x00, 0x2a], label: "TIFF image (BE)", ext: "tiff", mime: "image/tiff" },
    { o: 0, b: [0x69, 0x63, 0x6e, 0x73], label: "Apple icon image", ext: "icns", mime: "image/icns" },
    { o: 0, b: [0x7b, 0x5c, 0x72, 0x74, 0x66], label: "RTF document", ext: "rtf", mime: "application/rtf" },
    { o: 0, b: [0x28, 0xb5, 0x2f, 0xfd], label: "Zstandard archive", ext: "zst", mime: "application/zstd" },
    { o: 0, b: [0x04, 0x22, 0x4d, 0x18], label: "LZ4 archive", ext: "lz4", mime: "application/x-lz4" },
    { o: 0, b: [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e], label: "ar archive / Debian package", ext: "deb", mime: "application/x-debian-package" },
    { o: 0, b: [0xed, 0xab, 0xee, 0xdb], label: "RPM package", ext: "rpm", mime: "application/x-rpm" },
    { o: 0, b: [0x77, 0x4f, 0x46, 0x46], label: "WOFF font", ext: "woff", mime: "font/woff" },
    { o: 0, b: [0x77, 0x4f, 0x46, 0x32], label: "WOFF2 font", ext: "woff2", mime: "font/woff2" },
    { o: 0, b: [0x4f, 0x54, 0x54, 0x4f], label: "OpenType font", ext: "otf", mime: "font/otf" },
    { o: 0, b: [0x00, 0x01, 0x00, 0x00, 0x00], label: "TrueType font", ext: "ttf", mime: "font/ttf" },
    { o: 0, b: [0xd4, 0xc3, 0xb2, 0xa1], label: "PCAP capture", ext: "pcap", mime: "application/vnd.tcpdump.pcap" },
    { o: 0, b: [0xa1, 0xb2, 0xc3, 0xd4], label: "PCAP capture", ext: "pcap", mime: "application/vnd.tcpdump.pcap" },
    { o: 0, b: [0x0a, 0x0d, 0x0d, 0x0a], label: "PCAPNG capture", ext: "pcapng", mime: "application/x-pcapng" },
    { o: 0, b: [0x3c, 0x73, 0x76, 0x67], label: "SVG image", ext: "svg", mime: "image/svg+xml" },
    { o: 0x8001, b: [0x43, 0x44, 0x30, 0x30, 0x31], label: "ISO 9660 disk image", ext: "iso", mime: "application/x-iso9660-image" },
    { o: 0, b: [0x3c, 0x3f, 0x78, 0x6d, 0x6c], label: "XML document", ext: "xml", mime: "application/xml" },
    { o: 0, b: [0x23, 0x21], label: "Script with shebang (#!)", ext: "sh", mime: "text/x-shellscript" },
    { o: 0, b: [0xef, 0xbb, 0xbf], label: "UTF-8 text (BOM)", ext: "txt", mime: "text/plain" },
    { o: 0, b: [0xff, 0xfe], label: "UTF-16 LE text (BOM)", ext: "txt", mime: "text/plain" },
  ];

  const matchSig = (bytes, sig) => {
    if (bytes.length < sig.o + sig.b.length) return false;
    for (let i = 0; i < sig.b.length; i++) {
      if (sig.b[i] !== null && bytes[sig.o + i] !== sig.b[i]) return false;
    }
    return true;
  };

  // ISO base-media (MP4/MOV/HEIC/AVIF/3GP) all share "ftyp" at offset 4; resolve by brand
  const detectFtyp = (b) => {
    if (b.length < 12 || b[4] !== 0x66 || b[5] !== 0x74 || b[6] !== 0x79 || b[7] !== 0x70) return null;
    let brand = "";
    for (let i = 8; i < 12; i++) brand += String.fromCharCode(b[i]);
    const bl = brand.toLowerCase();
    if (/^(heic|heix|heim|heis|hevc|hevx|mif1|msf1)$/.test(bl)) return { ext: "heic", label: "HEIC / HEIF image" };
    if (/^avi[fs]$/.test(bl)) return { ext: "avif", label: "AVIF image" };
    if (bl === "qt  ") return { ext: "mov", label: "QuickTime video" };
    if (bl.startsWith("m4a")) return { ext: "m4a", label: "M4A audio" };
    if (bl.startsWith("3gp") || bl.startsWith("3g2")) return { ext: "3gp", label: "3GP video" };
    return { ext: "mp4", label: "MP4 / ISO media" };
  };

  // DMG has no header magic; it carries a "koly" trailer in the last 512 bytes
  const detectDmg = (b) => {
    if (b.length < 512) return null;
    const o = b.length - 512;
    if (b[o] === 0x6b && b[o + 1] === 0x6f && b[o + 2] === 0x6c && b[o + 3] === 0x79) return { ext: "dmg", label: "Apple Disk Image (DMG)" };
    return null;
  };

  const detectType = (bytes) => {
    const ft = detectFtyp(bytes); if (ft) return ft;
    for (const sig of SIGNATURES) if (matchSig(bytes, sig)) return sig;
    const dmg = detectDmg(bytes); if (dmg) return dmg;
    return null;
  };

  // signatures that merely indicate "this is text" (never an extension forgery)
  const SOFT_TEXT = new Set(["txt", "xml", "sh"]);
  const IMG_EXT = new Set(["png", "jpg", "gif", "webp", "bmp", "ico", "heic", "heif", "avif", "svg", "tiff", "icns"]);
  const ARCHIVE_EXT = new Set(["zip", "gz", "bz2", "xz", "rar", "7z", "tar", "zst", "lz4", "deb", "rpm"]);
  const MEDIA_EXT = new Set(["mp4", "mkv", "ogg", "mp3", "flac", "wav", "avi", "mov", "m4a", "3gp"]);
  const EXEC_EXT = new Set(["elf", "exe", "macho", "class", "wasm"]);
  // which declared extensions legitimately map to a detected type
  const EXT_FAMILY = {
    png: ["png"], jpg: ["jpg", "jpeg", "jpe"], gif: ["gif"], webp: ["webp"], bmp: ["bmp", "dib"], ico: ["ico", "cur"],
    heic: ["heic", "heif"], avif: ["avif"], tiff: ["tiff", "tif"], icns: ["icns"], svg: ["svg"],
    pdf: ["pdf"], rtf: ["rtf"], ps: ["ps", "eps"],
    zip: ["zip", "docx", "xlsx", "pptx", "jar", "apk", "epub", "odt", "ods", "odp", "kmz", "vsdx", "whl", "war", "ipa", "crx", "nupkg", "docm", "xlsm", "pptm"],
    gz: ["gz", "tgz"], bz2: ["bz2", "tbz2"], xz: ["xz"], rar: ["rar"], "7z": ["7z"], tar: ["tar"],
    zst: ["zst", "zstd", "tzst"], lz4: ["lz4"], deb: ["deb", "ar", "udeb"], rpm: ["rpm"],
    elf: ["elf", "so", "o", "out", "bin", "axf", ""], exe: ["exe", "dll", "sys", "scr", "msi", "cpl", "ocx"],
    macho: ["macho", "dylib", "bundle", "o", ""], class: ["class"], wasm: ["wasm"],
    sqlite: ["sqlite", "sqlite3", "db", "db3"], iso: ["iso", "img", "udf"], dmg: ["dmg"],
    woff: ["woff"], woff2: ["woff2"], otf: ["otf", "otc"], ttf: ["ttf", "ttc"],
    pcap: ["pcap", "cap", "dmp"], pcapng: ["pcapng", "ntar"],
    mp3: ["mp3"], ogg: ["ogg", "oga", "ogv", "opus"], flac: ["flac"], wav: ["wav"], avi: ["avi"],
    mp4: ["mp4", "m4v", "m4b"], mov: ["mov", "qt"], m4a: ["m4a"], "3gp": ["3gp", "3g2"], mkv: ["mkv", "webm"],
  };

  // forensic: byte-sequence search
  const idxSeq = (b, needle, from = 0) => {
    const n0 = needle[0], last = b.length - needle.length;
    outer: for (let i = from; i <= last; i++) {
      if (b[i] !== n0) continue;
      for (let j = 1; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  };
  const lastIdxSeq = (b, needle) => {
    const n0 = needle[0];
    outer: for (let i = b.length - needle.length; i >= 0; i--) {
      if (b[i] !== n0) continue;
      for (let j = 1; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  };

  // forensic: bytes appended after a format's logical end-of-file
  const detectOverlay = (b, sig) => {
    if (!sig) return 0;
    if (sig.ext === "png") { const i = lastIdxSeq(b, [0x49, 0x45, 0x4e, 0x44]); return i < 0 ? 0 : Math.max(0, b.length - (i + 8)); }
    if (sig.ext === "jpg") { const i = lastIdxSeq(b, [0xff, 0xd9]); return i < 0 ? 0 : Math.max(0, b.length - (i + 2)); }
    if (sig.ext === "pdf") {
      const i = lastIdxSeq(b, [0x25, 0x25, 0x45, 0x4f, 0x46]); if (i < 0) return 0;
      let e = i + 5; while (e < b.length && (b[e] === 10 || b[e] === 13 || b[e] === 32)) e++;
      return Math.max(0, b.length - e);
    }
    return 0;
  };

  // forensic: foreign file signatures embedded inside an image/pdf host (polyglot / stego)
  const CARVE_SIGS = [
    { n: "ZIP", b: [0x50, 0x4b, 0x03, 0x04] }, { n: "RAR", b: [0x52, 0x61, 0x72, 0x21] },
    { n: "7-Zip", b: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] }, { n: "GZIP", b: [0x1f, 0x8b, 0x08] },
    { n: "ELF", b: [0x7f, 0x45, 0x4c, 0x46] }, { n: "PDF", b: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  ];
  const carvePolyglot = (b, sig) => {
    if (!sig || !(IMG_EXT.has(sig.ext) || sig.ext === "pdf")) return [];
    const cap = Math.min(b.length, 16 * 1024 * 1024);
    const sub = cap < b.length ? b.subarray(0, cap) : b;
    const out = [];
    for (const s of CARVE_SIGS) {
      if (s.n === "PDF" && sig.ext === "pdf") continue;
      const i = idxSeq(sub, s.b, 1);
      if (i > 0) out.push({ n: s.n, off: i });
      if (out.length >= 6) break;
    }
    return out;
  };

  // crude "looks like text" test over a sample
  const looksTextual = (bytes) => {
    const n = Math.min(bytes.length, 4096);
    if (!n) return false;
    let printable = 0;
    for (let i = 0; i < n; i++) {
      const c = bytes[i];
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
    }
    return printable / n > 0.9;
  };

  /* ---------------- entropy ---------------- */

  const entropyFromCounts = (counts, total) => {
    if (!total) return 0;
    let e = 0;
    for (let i = 0; i < 256; i++) {
      const c = counts[i];
      if (c) { const p = c / total; e -= p * Math.log2(p); }
    }
    return e;
  };

  /* ---------------- byte-class colour ---------------- */

  const byteColor = (v) => {
    if (v === 0) return [12, 20, 15];
    if (v >= 32 && v <= 126) { const t = (v - 32) / 94; return [34 + t * 46, 150 + t * 85, 78 + t * 48]; }  // green
    if (v < 32) { const t = v / 31; return [210 + t * 40, 130 + t * 45, 20 + t * 20]; }                      // amber
    const t = (v - 127) / 128; return [205 + t * 45, 58 + t * 24, 50 + t * 18];                              // red
  };

  /* ---------------- byte map ---------------- */

  const drawByteMap = async (scan) => {
    const canvas = $("upByteCanvas");
    const W = 600, H = 200;
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    const img = ctx.createImageData(W, H);
    const data = img.data;
    const total = W * H;
    const n = scan.length;
    for (let k = 0; k < total; k++) {
      const v = n ? scan[Math.min(n - 1, Math.floor((k * n) / total))] : 0;
      const [r, g, b] = byteColor(v);
      const o = k * 4;
      data[o] = r; data[o + 1] = g; data[o + 2] = b; data[o + 3] = 255;
    }
    ctx.putImageData(img, 0, 0);
  };

  /* ---------------- histogram ---------------- */

  const drawHistogram = (gHist, maxCount) => {
    const canvas = $("upHistCanvas");
    const W = 256, H = 140;
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, W, H);
    const denom = Math.log(1 + maxCount) || 1;
    for (let v = 0; v < 256; v++) {
      const h = Math.round((Math.log(1 + gHist[v]) / denom) * (H - 2));
      if (!h) continue;
      const [r, g, b] = byteColor(v);
      ctx.fillStyle = `rgb(${r | 0},${g | 0},${b | 0})`;
      ctx.fillRect(v, H - h, 1, h);
    }
  };

  /* ---------------- entropy curve ---------------- */

  const drawEntropy = (scan) => {
    const W = 300, H = 100;
    const n = scan.length;
    const BUCKETS = Math.max(1, Math.min(256, n));
    const ent = new Float32Array(BUCKETS);
    const local = new Uint32Array(256);
    const segLen = n / BUCKETS;
    let bucket = 0, localTotal = 0, bound = segLen;
    for (let i = 0; i < n; i++) {
      local[scan[i]]++; localTotal++;
      if (i + 1 >= bound && bucket < BUCKETS - 1) {
        ent[bucket] = entropyFromCounts(local, localTotal);
        local.fill(0); localTotal = 0; bucket++; bound = segLen * (bucket + 1);
      }
    }
    ent[bucket] = entropyFromCounts(local, localTotal);

    const xAt = (i) => (BUCKETS === 1 ? W : (i / (BUCKETS - 1)) * W);
    const yAt = (e) => H - (Math.min(8, e) / 8) * H;
    let d = "";
    for (let i = 0; i < BUCKETS; i++) d += `${d ? "L" : "M"}${xAt(i).toFixed(1)} ${yAt(ent[i]).toFixed(1)}`;
    $("upEntLine").setAttribute("d", d);
    $("upEntArea").setAttribute("d", `${d}L${W} ${H}L0 ${H}Z`);
  };

  /* ---------------- 3D byte cloud (trigram point cloud) ---------------- */

  let cloud = null;

  const disposeCloud = () => {
    if (!cloud) return;
    try {
      cancelAnimationFrame(cloud.raf);
      window.removeEventListener("pointermove", cloud.move);
      window.removeEventListener("pointerup", cloud.up);
      window.removeEventListener("resize", cloud.resize);
      cloud.geo.dispose(); cloud.mat.dispose();
      if (cloud.sprite) cloud.sprite.dispose();
      cloud.renderer.dispose();
      if (cloud.renderer.domElement.parentNode) cloud.renderer.domElement.parentNode.removeChild(cloud.renderer.domElement);
    } catch (_) {}
    cloud = null;
  };

  const makeSprite = (THREE) => {
    const c = document.createElement("canvas"); c.width = c.height = 64;
    const g = c.getContext("2d");
    const grd = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    grd.addColorStop(0, "rgba(255,255,255,1)");
    grd.addColorStop(0.3, "rgba(170,255,200,0.85)");
    grd.addColorStop(1, "rgba(255,255,255,0)");
    g.fillStyle = grd; g.beginPath(); g.arc(32, 32, 32, 0, Math.PI * 2); g.fill();
    return new THREE.CanvasTexture(c);
  };

  const build3DCloud = (buf) => {
    const host = $("upCloud");
    disposeCloud();
    host.innerHTML = "";
    const THREE = window.THREE;
    if (!THREE) { host.innerHTML = '<div class="ins-cloud-fallback">3D renderer unavailable</div>'; return; }
    try {
      const W = host.clientWidth || 600, H = host.clientHeight || 400;
      const scene = new THREE.Scene();
      scene.fog = new THREE.FogExp2(0x000000, 0.0062);
      const camera = new THREE.PerspectiveCamera(52, W / H, 0.1, 2000);
      let camZ = 158; camera.position.z = camZ;
      const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(W, H);
      host.append(renderer.domElement);

      const group = new THREE.Group();
      scene.add(group);

      const n = buf.length;
      const MAXP = 60000;
      const step = Math.max(1, Math.floor((n - 2) / MAXP));
      const pos = [], col = [];
      for (let i = 0; i + 2 < n; i += step) {
        pos.push((buf[i] / 255 - 0.5) * 90, (buf[i + 1] / 255 - 0.5) * 90, (buf[i + 2] / 255 - 0.5) * 90);
        const t = buf[i + 1] / 255;
        col.push(0.12 + 0.3 * t, 0.6 + 0.4 * t, 0.3 + 0.3 * t); // green glow
      }
      const geo = new THREE.BufferGeometry();
      geo.setAttribute("position", new THREE.Float32BufferAttribute(pos, 3));
      geo.setAttribute("color", new THREE.Float32BufferAttribute(col, 3));
      const sprite = makeSprite(THREE);
      const mat = new THREE.PointsMaterial({
        size: 2.6, map: sprite, vertexColors: true, transparent: true,
        opacity: 0.92, depthWrite: false, blending: THREE.AdditiveBlending, sizeAttenuation: true,
      });
      group.add(new THREE.Points(geo, mat));

      const cube = new THREE.LineSegments(
        new THREE.EdgesGeometry(new THREE.BoxGeometry(90, 90, 90)),
        new THREE.LineBasicMaterial({ color: 0x30d158, transparent: true, opacity: 0.16 })
      );
      group.add(cube);

      let rotX = 0.5, rotY = 0.5, velX = 0, velY = 0, dragging = false, lx = 0, ly = 0, px = 0, py = 0, camZt = camZ;
      const el = renderer.domElement;
      el.style.cursor = "grab"; el.style.touchAction = "none";
      const down = (e) => { dragging = true; el.style.cursor = "grabbing"; lx = e.clientX; ly = e.clientY; velX = velY = 0; };
      const move = (e) => {
        const r = el.getBoundingClientRect();
        px = ((e.clientX - r.left) / r.width - 0.5) * 2;
        py = ((e.clientY - r.top) / r.height - 0.5) * 2;
        if (!dragging) return;
        velY = (e.clientX - lx) * 0.005; velX = (e.clientY - ly) * 0.005;
        rotY += velY; rotX += velX; rotX = Math.max(-1.49, Math.min(1.49, rotX));
        lx = e.clientX; ly = e.clientY;
      };
      const up = () => { dragging = false; el.style.cursor = "grab"; };
      const wheel = (e) => { e.preventDefault(); camZt = Math.max(78, Math.min(330, camZt + e.deltaY * 0.09)); };
      const resize = () => {
        const w = host.clientWidth || W, h = host.clientHeight || H;
        camera.aspect = w / h; camera.updateProjectionMatrix(); renderer.setSize(w, h);
      };
      el.addEventListener("pointerdown", down);
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      el.addEventListener("wheel", wheel, { passive: false });
      window.addEventListener("resize", resize);

      cloud = { raf: 0, renderer, geo, mat, sprite, move, up, resize };
      const loop = () => {
        if (!dragging) {
          rotY += velY; rotX += velX;
          velX *= 0.95; velY *= 0.95;
          if (Math.abs(velX) < 0.00015) velX = 0;
          if (Math.abs(velY) < 0.00015) velY = 0;
          rotY += 0.0015; // gentle idle spin
          rotX = Math.max(-1.49, Math.min(1.49, rotX));
        }
        group.rotation.x = rotX + (dragging ? 0 : py * 0.12);
        group.rotation.y = rotY + (dragging ? 0 : px * 0.12);
        camera.position.z += (camZt - camera.position.z) * 0.08;
        renderer.render(scene, camera);
        cloud.raf = requestAnimationFrame(loop);
      };
      loop();
    } catch (e) {
      host.innerHTML = '<div class="ins-cloud-fallback">3D view failed to initialise</div>';
    }
  };

  /* ---------------- findings (forensic summary) ---------------- */

  const renderFindings = (list) => {
    const box = $("upFindings");
    const badge = $("upFindingsVerdict");
    box.textContent = "";
    const order = { bad: 0, warn: 1, info: 2 };
    list.sort((a, b) => order[a[0]] - order[b[0]]);
    const worst = list.some((f) => f[0] === "bad") ? "bad" : list.some((f) => f[0] === "warn") ? "warn" : "info";
    const flags = list.filter((f) => f[0] !== "info").length;
    badge.dataset.level = worst === "info" ? "pending" : worst;
    badge.textContent = flags ? `${flags} ${worst === "bad" ? "flag" : "caution"}${flags > 1 ? "s" : ""}` : "observations";
    if (!list.length) {
      list = [["info", "No structural indicators recorded."]];
    }
    for (const [lvl, txt] of list) {
      const d = document.createElement("div");
      d.className = "ins-finding";
      const dot = document.createElement("span"); dot.className = `ins-finding-dot is-${lvl}`;
      d.append(dot, document.createTextNode(txt));
      box.append(d);
    }
  };

  /* ---------------- strings ---------------- */

  const extractStrings = (bytes, minLen) => {
    const limit = Math.min(bytes.length, STRINGS_SCAN);
    const out = [];
    let start = -1, total = 0;
    const flush = (end) => {
      if (start >= 0 && end - start >= minLen) {
        total++;
        if (out.length < STRINGS_MAX) {
          let str = "";
          for (let j = start; j < end && str.length < 180; j++) str += String.fromCharCode(bytes[j]);
          out.push({ off: start, str });
        }
      }
      start = -1;
    };
    for (let i = 0; i < limit; i++) {
      const c = bytes[i];
      const printable = c === 9 || (c >= 32 && c <= 126);
      if (printable) { if (start < 0) start = i; }
      else flush(i);
    }
    flush(limit);
    return { items: out, total, capped: bytes.length > STRINGS_SCAN };
  };

  const INTERESTING = /(https?:\/\/|www\.|\/[a-z0-9_.-]+\/|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|[A-Za-z]:\\|flag\{|[0-9a-f]{32,})/i;

  const renderStrings = (res) => {
    $("upStringsTag").textContent = res.total
      ? `${res.total.toLocaleString("en-US")} found · showing ${res.items.length}${res.capped ? " · first 16 MB" : ""}`
      : "none found";
    const box = $("upStrings");
    box.textContent = "";
    if (!res.items.length) { box.textContent = "no printable strings of 4+ characters"; return; }
    const frag = document.createDocumentFragment();
    for (const it of res.items) {
      const line = document.createElement("span");
      line.className = "up-str" + (INTERESTING.test(it.str) ? " up-hl" : "");
      const off = document.createElement("span");
      off.className = "up-off";
      off.textContent = "0x" + it.off.toString(16).padStart(8, "0");
      line.append(off, document.createTextNode(it.str));
      frag.append(line);
    }
    box.append(frag);
  };

  /* ---------------- hex dump ---------------- */

  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const hexDump = (bytes, end) => {
    let html = "";
    for (let off = 0; off < end; off += 16) {
      let hex = "", asc = "";
      for (let i = 0; i < 16; i++) {
        if (off + i < end) {
          const b = bytes[off + i];
          hex += b.toString(16).padStart(2, "0") + " ";
          asc += b >= 32 && b <= 126
            ? `<span class="up-hx-asc">${esc(String.fromCharCode(b))}</span>`
            : `<span class="up-hx-dim">.</span>`;
        } else { hex += "   "; }
        if (i === 7) hex += " ";
      }
      html += `<span class="up-hx-off">${off.toString(16).padStart(8, "0")}</span>  ` +
        `<span class="up-hx-hex">${hex}</span> ${asc}\n`;
    }
    return html;
  };

  /* ---------------- EXIF (JPEG) ---------------- */

  const parseJpegExif = (bytes) => {
    try {
      if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
      let p = 2, app1 = -1, app1end = -1;
      while (p + 4 < bytes.length) {
        if (bytes[p] !== 0xff) break;
        const marker = bytes[p + 1];
        if (marker === 0xda || marker === 0xd9) break; // SOS / EOI
        const len = (bytes[p + 2] << 8) | bytes[p + 3];
        if (len < 2) break;
        if (marker === 0xe1 &&
          bytes[p + 4] === 0x45 && bytes[p + 5] === 0x78 && bytes[p + 6] === 0x69 && bytes[p + 7] === 0x66) {
          app1 = p + 10; app1end = p + 2 + len; break;
        }
        p += 2 + len;
      }
      if (app1 < 0) return null;

      const tiff = app1;
      const le = bytes[tiff] === 0x49;
      const u16 = (o) => le ? bytes[o] | (bytes[o + 1] << 8) : (bytes[o] << 8) | bytes[o + 1];
      const u32 = (o) => le
        ? (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0
        : ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;

      const TSIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

      const readVal = (type, count, valOff) => {
        const size = (TSIZE[type] || 1) * count;
        const base = size <= 4 ? valOff : tiff + u32(valOff);
        if (type === 2) { // ASCII
          let s = "";
          for (let i = 0; i < count && base + i < bytes.length; i++) {
            const c = bytes[base + i];
            if (c === 0) break;
            s += String.fromCharCode(c);
          }
          return s.trim();
        }
        if (type === 3) return u16(base);
        if (type === 4 || type === 9) return u32(base);
        if (type === 5 || type === 10) { // RATIONAL(s)
          const arr = [];
          for (let i = 0; i < count; i++) {
            const num = u32(base + i * 8), den = u32(base + i * 8 + 4) || 1;
            arr.push(num / den);
          }
          return count === 1 ? arr[0] : arr;
        }
        return bytes[base];
      };

      const readIFD = (ifdOff, want) => {
        const res = {};
        if (ifdOff + 2 > bytes.length) return res;
        const count = u16(ifdOff);
        for (let i = 0; i < count; i++) {
          const e = ifdOff + 2 + i * 12;
          if (e + 12 > bytes.length) break;
          const tag = u16(e), type = u16(e + 2), cnt = u32(e + 4);
          if (want[tag] !== undefined) {
            try { res[tag] = readVal(type, cnt, e + 8); } catch (_) {}
          }
        }
        return res;
      };

      const ifd0 = readIFD(tiff + u32(tiff + 4), { 0x010f: 1, 0x0110: 1, 0x0132: 1, 0x0112: 1, 0x0131: 1, 0x8769: 1, 0x8825: 1 });
      const out = {
        make: ifd0[0x010f], model: ifd0[0x0110], datetime: ifd0[0x0132],
        orientation: ifd0[0x0112], software: ifd0[0x0131],
      };
      if (ifd0[0x8769]) {
        const ex = readIFD(tiff + ifd0[0x8769], { 0x829a: 1, 0x829d: 1, 0x8827: 1, 0x920a: 1, 0xa002: 1, 0xa003: 1, 0x9003: 1, 0xa434: 1 });
        out.exposure = ex[0x829a]; out.fnumber = ex[0x829d]; out.iso = ex[0x8827];
        out.focal = ex[0x920a]; out.px = ex[0xa002]; out.py = ex[0xa003];
        out.dateOriginal = ex[0x9003]; out.lens = ex[0xa434];
      }
      if (ifd0[0x8825]) {
        const g = readIFD(tiff + ifd0[0x8825], { 0x0001: 1, 0x0002: 1, 0x0003: 1, 0x0004: 1, 0x0005: 1, 0x0006: 1 });
        const dms = (a, ref) => {
          if (!Array.isArray(a) || a.length < 3) return null;
          let dec = a[0] + a[1] / 60 + a[2] / 3600;
          if (ref === "S" || ref === "W") dec = -dec;
          return dec;
        };
        const lat = dms(g[0x0002], g[0x0001]);
        const lon = dms(g[0x0004], g[0x0003]);
        if (lat != null && lon != null) {
          out.gps = { lat, lon, alt: g[0x0006] };
        }
      }
      return out;
    } catch (_) {
      return null;
    }
  };

  /* ---------------- ZIP central directory ---------------- */

  const parseZip = (bytes) => {
    try {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      // find EOCD (PK\x05\x06) scanning backwards
      let eocd = -1;
      const minPos = Math.max(0, bytes.length - 65557);
      for (let i = bytes.length - 22; i >= minPos; i--) {
        if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
      }
      if (eocd < 0) return null;
      const entries = dv.getUint16(eocd + 10, true);
      let off = dv.getUint32(eocd + 16, true);
      const list = [];
      for (let i = 0; i < entries && off + 46 <= bytes.length; i++) {
        if (dv.getUint32(off, true) !== 0x02014b50) break;
        const method = dv.getUint16(off + 10, true);
        const csize = dv.getUint32(off + 20, true);
        const usize = dv.getUint32(off + 24, true);
        const nameLen = dv.getUint16(off + 28, true);
        const extraLen = dv.getUint16(off + 30, true);
        const commLen = dv.getUint16(off + 32, true);
        let name = "";
        for (let j = 0; j < nameLen && off + 46 + j < bytes.length; j++) name += String.fromCharCode(bytes[off + 46 + j]);
        try { name = decodeURIComponent(escape(name)); } catch (_) {}
        list.push({ name, csize, usize, method });
        off += 46 + nameLen + extraLen + commLen;
        if (list.length >= 800) break;
      }
      return { entries, list };
    } catch (_) {
      return null;
    }
  };

  const ZIP_METHOD = { 0: "Stored", 8: "Deflate", 9: "Deflate64", 12: "BZIP2", 14: "LZMA", 93: "Zstd", 95: "XZ" };

  /* ---------------- rendering: identity / type ---------------- */

  const setVerdict = (id, text, level) => {
    const el = $(id);
    el.textContent = text;
    el.dataset.level = level;
  };

  /* ---------------- reset ---------------- */

  const clearResults = () => {
    ["upIdentity", "upHashes", "upExif"].forEach((id) => { $(id).textContent = ""; });
    $("upTypeNote").textContent = "";
    $("upExifNote").textContent = "";
    $("upStrings").textContent = "";
    $("upHex").textContent = "";
    $("upArchive").textContent = "";
    $("upPreview").textContent = "";
    $("upImageCards").hidden = true;
    $("upArchiveCard").hidden = true;
    $("upEntLine").setAttribute("d", "");
    $("upEntArea").setAttribute("d", "");
    $("upFindings").textContent = "";
    disposeCloud();
    document.querySelectorAll(".up-canvas-wrap, .up-entropy").forEach((e) => e.classList.remove("is-reveal"));
  };

  let hexState = { bytes: null, shown: 0 };

  /* ---------------- byte-map legend ---------------- */

  const buildLegend = () => {
    const el = $("upByteLegend");
    if (el.childElementCount) return;
    const items = [["null", [16, 26, 20]], ["printable", [48, 209, 88]], ["control", [255, 159, 10]], ["high-bit", [255, 69, 58]]];
    for (const [name, [r, g, b]] of items) {
      const s = document.createElement("span");
      const i = document.createElement("i");
      i.style.background = `rgb(${r},${g},${b})`;
      s.append(i, document.createTextNode(name));
      el.append(s);
    }
  };

  /* ---------------- main ---------------- */

  let analyzing = false;

  const analyze = async (file) => {
    if (analyzing) return;
    analyzing = true;
    try {
      openScan(file.name || "(unnamed)");
      const results = $("upResults");
      results.hidden = false;
      clearResults();
      buildLegend();

      setStatus("Reading", "busy"); scanPhase("READING");
      log(`loaded ${file.name || "(unnamed)"} · ${fmtBytes(file.size)}`, "step");

      const truncated = file.size > READ_CAP;
      const blob = truncated ? file.slice(0, READ_CAP) : file;
      const buf = new Uint8Array(await blob.arrayBuffer());
      if (truncated) log(`file exceeds ${fmtBytes(READ_CAP)}; analysing first ${fmtBytes(READ_CAP)}`, "warn");

      /* identity */
      const ext = (file.name.match(/\.([^.\/\\]+)$/) || [, ""])[1].toLowerCase();
      const sig = buf.length ? detectType(buf) : null;
      $("upFileName").textContent = file.name || "(unnamed)";
      $("upFileMeta").textContent = `${fmtBytes(file.size).replace(/ \(.*\)/, "")} · ${file.type || "unknown type"}`;
      addRow("upIdentity", "Modified", file.lastModified ? new Date(file.lastModified).toLocaleString() : "·");
      addRow("upIdentity", "Extension", ext ? "." + ext : "none");
      addRow("upIdentity", "Browser MIME", file.type || "unknown");
      addRow("upIdentity", "Magic bytes", buf.length ? toHex(buf.subarray(0, 8)) : "·");

      let trueType, trueExt;
      if (sig) {
        trueType = sig.label; trueExt = sig.ext;
        addRow("upIdentity", "Detected type", sig.label, "is-good");
      } else if (buf.length === 0) {
        trueType = "empty file";
        addRow("upIdentity", "Detected type", "empty file", "is-warn");
      } else if (looksTextual(buf)) {
        trueType = "Plain text / source"; trueExt = "txt";
        addRow("upIdentity", "Detected type", "Plain text / source");
      } else {
        trueType = "Unknown / raw binary";
        addRow("upIdentity", "Detected type", "unknown (no known signature)", "is-pending");
      }
      $("upTypeBadge").textContent = trueType;

      // extension vs content verdict. Only a real binary signature can be a forgery.
      // Text/unknown content never counts (source files legitimately use any extension).
      let mismatch = false, gpsFound = false;
      if (buf.length === 0) {
        setVerdict("upTypeVerdict", "Empty", "warn");
      } else if (!sig) {
        setVerdict("upTypeVerdict", looksTextual(buf) ? "Text" : "Unknown", looksTextual(buf) ? "good" : "pending");
      } else if (SOFT_TEXT.has(sig.ext)) {
        setVerdict("upTypeVerdict", "Text", "good");
      } else if (!ext) {
        setVerdict("upTypeVerdict", "No extension", "warn");
        $("upTypeNote").textContent = `Content is ${trueType}; the file has no extension.`;
      } else if ((EXT_FAMILY[sig.ext] || [sig.ext]).includes(ext)) {
        setVerdict("upTypeVerdict", "Verified", "good");
      } else {
        mismatch = true;
        setVerdict("upTypeVerdict", "Mismatch", "bad");
        $("upTypeNote").textContent = `Declared .${ext} but the content is ${trueType}. Extension and real type disagree.`;
        log(`extension mismatch: .${ext} vs ${trueType}`, "warn");
      }

      /* hashes */
      setStatus("Hashing", "busy"); scanPhase("HASHING");
      await nextFrame();
      addRow("upHashes", "SHA-256", "computing…", "is-pending");
      addRow("upHashes", "SHA-1", "computing…", "is-pending");
      addRow("upHashes", "MD5", "computing…", "is-pending");
      const hashTarget = buf; // whole read region
      let sha256, sha1, md5hex;
      try { sha256 = await digestHex("SHA-256", hashTarget); } catch (_) { sha256 = "unavailable"; }
      try { sha1 = await digestHex("SHA-1", hashTarget); } catch (_) { sha1 = "unavailable"; }
      md5hex = buf.length <= MD5_CAP ? md5(buf) : `skipped (> ${fmtBytes(MD5_CAP)})`;
      $("upHashes").textContent = "";
      addRow("upHashes", "SHA-256", sha256);
      addRow("upHashes", "SHA-1", sha1);
      addRow("upHashes", "MD5", md5hex);
      if (truncated) addRow("upHashes", "Note", "digests cover analysed region only", "is-warn");
      log(`sha256 ${sha256.slice(0, 32)}…`, "ok");

      /* sampled scan for visuals */
      setStatus("Scanning", "busy"); scanPhase("MAPPING");
      await nextFrame();
      let scan, stride = 1;
      if (buf.length <= SCAN_MAX) scan = buf;
      else {
        stride = Math.ceil(buf.length / SCAN_MAX);
        scan = new Uint8Array(Math.floor(buf.length / stride));
        for (let k = 0; k < scan.length; k++) scan[k] = buf[k * stride];
        log(`sampled every ${stride} bytes for visualisation`, "step");
      }

      // global histogram + overall entropy
      const gHist = new Uint32Array(256);
      for (let i = 0; i < scan.length; i++) gHist[scan[i]]++;
      let maxCount = 0;
      for (let i = 0; i < 256; i++) if (gHist[i] > maxCount) maxCount = gHist[i];
      const overall = entropyFromCounts(gHist, scan.length);
      const entHint = overall >= 7.9 ? "encrypted / compressed" : overall >= 6.5 ? "likely packed" : overall >= 4.5 ? "mixed" : "structured / text";
      $("upEntropyAvg").textContent = `${overall.toFixed(2)} bits · ${entHint}`;

      /* draw visuals */
      await drawByteMap(scan);
      $("upByteCanvas").closest(".up-canvas-wrap").classList.add("is-reveal");
      drawHistogram(gHist, maxCount);
      $("upHistCanvas").closest(".up-canvas-wrap").classList.add("is-reveal");
      drawEntropy(scan);
      document.querySelector(".up-entropy").classList.add("is-reveal");
      log(`entropy ${overall.toFixed(2)} bits/byte (${entHint})`, overall >= 7.9 ? "warn" : "ok");

      /* 3D interactive byte cloud */
      scanPhase("ENTROPY");
      build3DCloud(buf);

      /* strings */
      scanPhase("CONTENT");
      renderStrings(extractStrings(buf, 4));

      /* hex */
      hexState = { bytes: buf, shown: Math.min(HEX_START, buf.length) };
      $("upHex").innerHTML = hexDump(buf, hexState.shown);
      $("upHexMore").disabled = hexState.shown >= Math.min(buf.length, HEX_CAP);

      /* image preview + exif */
      const imgExt = { png: 1, jpg: 1, gif: 1, webp: 1, bmp: 1, ico: 1, svg: 1, avif: 1 };
      if (sig && imgExt[sig.ext]) {
        $("upImageCards").hidden = false;
        reveal($("upImageCards"));
        const url = URL.createObjectURL(sig.ext === "svg" ? new Blob([buf], { type: "image/svg+xml" }) : file);
        const im = new Image();
        im.onload = () => { $("upImgDims").textContent = `${im.naturalWidth} × ${im.naturalHeight}px`; };
        im.onerror = () => { $("upImgDims").textContent = "preview unavailable"; };
        im.alt = "preview";
        im.src = url;
        $("upPreview").append(im);

        const exif = sig.ext === "jpg" ? parseJpegExif(buf) : null;
        renderExif(exif);
        if (exif && exif.gps) gpsFound = true;
      }

      /* archive listing */
      if (sig && sig.ext === "zip") {
        const zip = parseZip(buf);
        if (zip && zip.list.length) renderArchive(zip);
      }

      /* indicators: structural observations, NOT a malware verdict */
      const overlayBytes = detectOverlay(buf, sig);
      const polyglot = carvePolyglot(buf, sig);
      const isExec = !!(sig && EXEC_EXT.has(sig.ext));
      const isArchive = !!(sig && (ARCHIVE_EXT.has(sig.ext) || sig.ext === "zip"));
      const highEnt = overall >= 7.9 && sig && !IMG_EXT.has(sig.ext) && !ARCHIVE_EXT.has(sig.ext) && !MEDIA_EXT.has(sig.ext) && sig.ext !== "pdf";
      const macroExt = ["docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xls", "doc", "ppt"];
      const findings = [];
      // flags (highest-consequence first)
      if (mismatch) findings.push(["bad", `Extension .${ext} disguises a ${trueType}`]);
      if (gpsFound) findings.push(["bad", "GPS coordinates embedded in image metadata"]);
      if (isExec) findings.push(["warn", "Executable code: this file can run commands on a machine. A structural inspection cannot tell whether it is benign or malicious."]);
      if (overlayBytes > 16) findings.push(["warn", `${fmtBytes(overlayBytes).replace(/ \(.*\)/, "")} appended after the end-of-file marker`]);
      for (const e of polyglot) findings.push(["warn", `Embedded ${e.n} signature at 0x${e.off.toString(16)} (possible polyglot or hidden payload)`]);
      if (isArchive && macroExt.includes(ext)) findings.push(["warn", "Office container that may carry macros or scripts; expand and inspect its parts"]);
      if (highEnt) findings.push(["warn", `Very high entropy (${overall.toFixed(2)}/8): likely encrypted or packed`]);
      if (buf.length === 0) findings.push(["warn", "Empty file, nothing to analyse"]);
      // neutral observations (always present, so the panel never implies "safe")
      if (buf.length) {
        findings.push(["info", `Identified as ${trueType}`]);
        findings.push(["info", `Entropy ${overall.toFixed(2)} / 8 bits (${entHint})`]);
        if (isArchive && !macroExt.includes(ext)) findings.push(["info", "Compressed container: inspect the files inside individually"]);
      }
      renderFindings(findings);
      const flagCount = findings.filter((f) => f[0] !== "info").length;
      if (flagCount) log(`${flagCount} indicator(s) flagged`, findings.some((f) => f[0] === "bad") ? "err" : "warn");

      setStatus("Done", "done");
      log("analysis complete", "ok");
      await closeScan();
      showDossier();
    } catch (e) {
      setStatus("Failed", "error");
      log(`fatal: ${e.message}`, "err");
      try { await closeScan(); showDossier(); } catch (_) {}
    } finally {
      analyzing = false;
    }
  };

  const renderExif = (exif) => {
    const note = $("upExifNote");
    if (!exif || !Object.keys(exif).some((k) => exif[k] != null)) {
      setVerdict("upExifVerdict", "No metadata", "good");
      addRow("upExif", "EXIF", "none found", "is-good");
      note.textContent = "No camera or location metadata embedded.";
      return;
    }
    const fx = (v, s = "") => (v == null ? null : `${typeof v === "number" ? (Math.round(v * 100) / 100) : v}${s}`);
    if (exif.make || exif.model) addRow("upExif", "Camera", [exif.make, exif.model].filter(Boolean).join(" "));
    if (exif.lens) addRow("upExif", "Lens", exif.lens);
    if (exif.dateOriginal || exif.datetime) addRow("upExif", "Taken", exif.dateOriginal || exif.datetime);
    if (exif.exposure) addRow("upExif", "Exposure", exif.exposure >= 1 ? `${exif.exposure}s` : `1/${Math.round(1 / exif.exposure)}s`);
    if (exif.fnumber) addRow("upExif", "Aperture", `f/${fx(exif.fnumber)}`);
    if (exif.iso) addRow("upExif", "ISO", exif.iso);
    if (exif.focal) addRow("upExif", "Focal length", `${fx(exif.focal)}mm`);
    if (exif.px && exif.py) addRow("upExif", "Dimensions", `${exif.px} × ${exif.py}px`);
    if (exif.software) addRow("upExif", "Software", exif.software);

    if (exif.gps) {
      const { lat, lon } = exif.gps;
      addRow("upExif", "GPS", `${lat.toFixed(6)}, ${lon.toFixed(6)}`, "is-bad");
      setVerdict("upExifVerdict", "Location embedded", "bad");
      note.innerHTML = `⚠ GPS coordinates are embedded in this photo. <a href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" rel="noopener noreferrer" style="color:var(--green)">Open in Maps</a>. Strip EXIF before sharing.`;
      log(`EXIF GPS present: ${lat.toFixed(5)}, ${lon.toFixed(5)}`, "warn");
    } else {
      setVerdict("upExifVerdict", "Camera metadata", "warn");
      note.textContent = "Camera/software metadata present (no GPS).";
    }
  };

  const renderArchive = (zip) => {
    $("upArchiveCard").hidden = false;
    reveal($("upArchiveCard"));
    $("upArchiveTag").textContent = `${zip.entries.toLocaleString("en-US")} entries`;
    const table = $("upArchive");
    table.textContent = "";
    const thead = document.createElement("tr");
    ["Name", "Method", "Size", "Compressed"].forEach((h, i) => {
      const th = document.createElement("th");
      th.textContent = h;
      if (i >= 2) th.style.textAlign = "right";
      thead.append(th);
    });
    table.append(thead);
    for (const e of zip.list) {
      const tr = document.createElement("tr");
      const cells = [
        [e.name, ""],
        [ZIP_METHOD[e.method] || `#${e.method}`, ""],
        [fmtBytes(e.usize).replace(/ \(.*\)/, ""), "up-num"],
        [fmtBytes(e.csize).replace(/ \(.*\)/, ""), "up-num"],
      ];
      for (const [txt, cls] of cells) {
        const td = document.createElement("td");
        if (cls) td.className = cls;
        td.textContent = txt;
        tr.append(td);
      }
      table.append(tr);
    }
  };

  /* ---------------- hex "show more" ---------------- */

  $("upHexMore").addEventListener("click", () => {
    if (!hexState.bytes) return;
    const cap = Math.min(hexState.bytes.length, HEX_CAP);
    hexState.shown = Math.min(cap, hexState.shown + HEX_STEP);
    $("upHex").innerHTML = hexDump(hexState.bytes, hexState.shown);
    $("upHexMore").disabled = hexState.shown >= cap;
  });

  /* ---------------- copy hashes ---------------- */

  $("upCopyHashes").addEventListener("click", async () => {
    const rows = [...$("upHashes").querySelectorAll(".wh-row")]
      .map((r) => `${r.querySelector(".wh-row-k").textContent}: ${r.querySelector(".wh-row-v").textContent}`)
      .join("\n");
    try { await navigator.clipboard.writeText(rows); log("digests copied", "ok"); }
    catch (_) { log("clipboard blocked", "err"); }
  });

  /* ---------------- reset ---------------- */

  $("upReset").addEventListener("click", () => {
    $("upResults").hidden = true;
    const rail = $("upRail"); if (rail) rail.hidden = true;
    $("upInput").value = "";
    disposeCloud();
    killDossier();
    setStatus("Awaiting evidence", "idle");
    goTo("upHero");
  });

  /* ---------------- drag & drop wiring ---------------- */

  const drop = $("upDrop");
  const input = $("upInput");

  input.addEventListener("change", () => { if (input.files && input.files[0]) analyze(input.files[0]); });

  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-drag"); })
  );
  ["dragleave", "dragend"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); if (e.target === drop) drop.classList.remove("is-drag"); })
  );
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("is-drag");
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) analyze(f);
  });
  drop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
  });

  // allow dropping anywhere on the page without navigating away
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    if (e.target && e.target.closest && e.target.closest(".up-drop")) return;
    e.preventDefault();
  });

  /* ===================================================================
     PRESENTATION ENGINE: loader, scan takeover, smooth scroll,
     scroll reveal, chapter rail, custom cursor. Degrades gracefully.
     =================================================================== */

  const prefersReduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const GS = window.gsap, ST = window.ScrollTrigger;
  const hasGSAP = !!(GS && ST);
  if (hasGSAP) { try { GS.registerPlugin(ST); } catch (_) {} }

  /* ---- Lenis smooth scroll (optional) ---- */
  let lenis = null;
  if (!prefersReduce && window.Lenis) {
    try {
      lenis = new window.Lenis({ duration: 1.1, smoothWheel: true });
      if (hasGSAP) {
        lenis.on("scroll", ST.update);
        GS.ticker.add((t) => lenis.raf(t * 1000));
        GS.ticker.lagSmoothing(0);
      } else {
        const raf = (t) => { lenis.raf(t); requestAnimationFrame(raf); };
        requestAnimationFrame(raf);
      }
    } catch (_) { lenis = null; }
  }
  const goTo = (target) => {
    const el = typeof target === "string" ? document.getElementById(target) : target;
    if (!el) return;
    if (lenis) lenis.scrollTo(el, { offset: -40 });
    else el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  /* ---- kinetic hero intro ---- */
  const maskLines = (el) => {
    if (!el) return;
    const lines = el.innerHTML.split(/<br\s*\/?>/i);
    el.innerHTML = lines.map((l) => `<span class="line"><span class="line-in">${l}</span></span>`).join("");
  };
  let introDone = false;
  const intro = () => {
    if (introDone) return; introDone = true;
    if (!hasGSAP || prefersReduce) return;
    try {
      maskLines($("upTitle"));
      GS.timeline({ defaults: { ease: "power3.out" } })
        .from(".ins-hero-eyebrow", { opacity: 0, y: 16, duration: 0.6 })
        .from(".ins-title .line-in", { yPercent: 115, duration: 0.9, stagger: 0.12 }, "-=0.2")
        .from(".ins-lead", { opacity: 0, y: 20, duration: 0.7 }, "-=0.5")
        .from(".ins-drop", { opacity: 0, y: 28, duration: 0.8 }, "-=0.4")
        .from([".ins-ticker", ".ins-scrollcue"], { opacity: 0, y: 16, duration: 0.6, stagger: 0.1 }, "-=0.5");
    } catch (_) {}
  };

  /* ---- intro loader (always resolves) ---- */
  (() => {
    const loader = $("upLoader");
    if (!loader) { intro(); return; }
    const pctEl = $("upLoaderPct"), barEl = $("upLoaderBar");
    let p = 0, done = false;
    const finish = () => {
      if (done) return; done = true;
      loader.classList.add("is-done");
      setTimeout(() => { if (loader.parentNode) loader.remove(); }, 800);
      intro();
    };
    const tickL = () => {
      p = Math.min(100, p + 8 + Math.random() * 20);
      if (pctEl) pctEl.textContent = String(Math.floor(p)).padStart(3, "0");
      if (barEl) barEl.style.width = p + "%";
      if (p < 100) setTimeout(tickL, 95); else setTimeout(finish, 280);
    };
    setTimeout(finish, 2800);
    tickL();
  })();

  /* ---- scan takeover ---- */
  const SCAN_PHASES = ["REQUISITION", "READING", "HASHING", "MAPPING", "ENTROPY", "CONTENT", "COMPLETE"];
  let scanWatchdog = null;
  const openScan = (name) => {
    const o = $("upScan"); if (!o) return;
    if ($("upScanName")) $("upScanName").textContent = name;
    scanPhase("REQUISITION");
    o.hidden = false; o.classList.remove("is-out");
    clearTimeout(scanWatchdog);
    scanWatchdog = setTimeout(() => { o.hidden = true; o.classList.remove("is-out"); }, 12000);
  };
  const scanPhase = (name) => {
    const i = SCAN_PHASES.indexOf(name);
    const pct = Math.max(0, Math.round(((i + 1) / SCAN_PHASES.length) * 100));
    if ($("upScanPhase")) $("upScanPhase").textContent = name.toLowerCase();
    if ($("upScanPct")) $("upScanPct").textContent = String(pct).padStart(3, "0");
    if ($("upScanBar")) $("upScanBar").style.width = pct + "%";
  };
  const closeScan = async () => {
    const o = $("upScan"); if (!o) return;
    scanPhase("COMPLETE"); await sleep(380);
    o.classList.add("is-out"); await sleep(620);
    o.hidden = true; o.classList.remove("is-out");
    clearTimeout(scanWatchdog);
  };

  /* ---- reveal helper for late-shown panels ---- */
  const reveal = (el) => {
    if (!el || !hasGSAP || prefersReduce) return;
    try { GS.from(el, { opacity: 0, y: 30, duration: 0.7, ease: "power3.out" }); } catch (_) {}
  };

  /* ---- dossier reveal + chapter scroll-spy ---- */
  let dTriggers = [];
  const killDossier = () => { dTriggers.forEach((t) => { try { t.kill(); } catch (_) {} }); dTriggers = []; };
  const setRail = (ch) => {
    document.querySelectorAll(".ins-rail-item").forEach((it) => it.classList.toggle("is-active", it.dataset.ch === ch));
  };
  const showDossier = () => {
    const results = $("upResults"); if (results) results.hidden = false;
    const rail = $("upRail"); if (rail) rail.hidden = false;
    setRail("00");
    if (hasGSAP && !prefersReduce) {
      try {
        killDossier();
        GS.set("#upResults [data-reveal]", { opacity: 0, y: 44 });
        const batch = ST.batch("#upResults [data-reveal]", {
          start: "top 88%",
          onEnter: (els) => GS.to(els, { opacity: 1, y: 0, duration: 0.8, ease: "power3.out", stagger: 0.09, overwrite: true }),
        });
        dTriggers = dTriggers.concat(batch);
        document.querySelectorAll("#upResults .chapter").forEach((chEl) => {
          dTriggers.push(ST.create({
            trigger: chEl, start: "top 45%", end: "bottom 45%",
            onToggle: (self) => { if (self.isActive) setRail(chEl.dataset.ch); },
          }));
        });
        ST.refresh();
      } catch (_) {
        try { GS.set("#upResults [data-reveal]", { opacity: 1, y: 0 }); } catch (e2) {}
      }
    }
    goTo("ch-00");
  };

  document.querySelectorAll(".ins-rail-item").forEach((it) => {
    it.addEventListener("click", (e) => { e.preventDefault(); goTo(it.dataset.go); });
  });

  /* ---- custom cursor + spotlight + magnetic + tilt ---- */
  if (!prefersReduce && matchMedia("(pointer: fine)").matches) {
    try {
      const spot = document.createElement("div"); spot.className = "ins-spot";
      const dot = document.createElement("div"); dot.className = "ins-cursor";
      const ring = document.createElement("div"); ring.className = "ins-cursor-ring";
      const label = document.createElement("span"); label.className = "ins-cursor-label"; ring.appendChild(label);
      document.body.append(spot, dot, ring);
      document.documentElement.classList.add("ins-has-cursor");
      let mx = innerWidth / 2, my = innerHeight / 2, rx = mx, ry = my, sx = mx, sy = my, on = false;
      window.addEventListener("pointermove", (e) => {
        mx = e.clientX; my = e.clientY;
        dot.style.transform = `translate(${mx}px,${my}px) translate(-50%,-50%)`;
        if (!on) { spot.style.opacity = "1"; on = true; }
        const hot = e.target.closest && e.target.closest("a,button,label,.ins-cloud,[data-cursor]");
        if (hot) { ring.classList.add("is-hot"); label.textContent = hot.getAttribute("data-cursor") || ""; }
        else { ring.classList.remove("is-hot"); label.textContent = ""; }
      }, { passive: true });
      const tk = () => {
        rx += (mx - rx) * 0.2; ry += (my - ry) * 0.2;
        ring.style.transform = `translate(${rx}px,${ry}px) translate(-50%,-50%)`;
        sx += (mx - sx) * 0.08; sy += (my - sy) * 0.08;
        spot.style.transform = `translate(${sx}px,${sy}px) translate(-50%,-50%)`;
        requestAnimationFrame(tk);
      };
      requestAnimationFrame(tk);
      document.addEventListener("pointermove", (e) => {
        const b = e.target.closest && e.target.closest(".ins-btn");
        document.querySelectorAll(".ins-btn").forEach((x) => { if (x !== b) x.style.transform = ""; });
        if (b) { const r = b.getBoundingClientRect(); b.style.transform = `translate(${(e.clientX - (r.left + r.width / 2)) * 0.3}px, ${(e.clientY - (r.top + r.height / 2)) * 0.45}px)`; }
      }, { passive: true });
      const dz = $("upDrop"), dzb = dz && dz.querySelector(".ins-drop-body");
      if (dz && dzb) {
        dz.addEventListener("pointermove", (e) => { const r = dz.getBoundingClientRect(); const nx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2); const ny = (e.clientY - (r.top + r.height / 2)) / (r.height / 2); dzb.style.transform = `rotateY(${nx * 5}deg) rotateX(${-ny * 5}deg) translateZ(12px)`; });
        dz.addEventListener("pointerleave", () => { dzb.style.transform = ""; });
      }
    } catch (_) { document.documentElement.classList.remove("ins-has-cursor"); }
  }
})();
