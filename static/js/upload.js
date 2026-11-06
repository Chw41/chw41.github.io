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
    { o: 0, b: [0x74, 0x74, 0x63, 0x66], label: "TrueType Collection", ext: "ttc", mime: "font/collection" },
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

  // shared EXIF/TIFF reader (used by JPEG and HEIC); `tiff` = offset of the TIFF header (II/MM)
  const parseTiff = (bytes, tiff) => {
    try {
      if (tiff < 0 || tiff + 8 > bytes.length) return null;
      const le = bytes[tiff] === 0x49;
      if (!le && bytes[tiff] !== 0x4d) return null;
      const u16 = (o) => le ? bytes[o] | (bytes[o + 1] << 8) : (bytes[o] << 8) | bytes[o + 1];
      const u32 = (o) => le
        ? (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0
        : ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
      const TSIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

      const readVal = (type, count, valOff) => {
        const size = (TSIZE[type] || 1) * count;
        const base = size <= 4 ? valOff : tiff + u32(valOff);
        if (type === 2) {
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
        if (type === 5 || type === 10) {
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

      const ifd0 = readIFD(tiff + u32(tiff + 4), { 0x0100: 1, 0x0101: 1, 0x010f: 1, 0x0110: 1, 0x0132: 1, 0x0112: 1, 0x0131: 1, 0x8769: 1, 0x8825: 1 });
      const out = {
        width: ifd0[0x0100], height: ifd0[0x0101],
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
        if (lat != null && lon != null) out.gps = { lat, lon, alt: g[0x0006] };
      }
      return out;
    } catch (_) {
      return null;
    }
  };

  const parseJpegExif = (bytes) => {
    try {
      if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
      let p = 2, app1 = -1;
      while (p + 4 < bytes.length) {
        if (bytes[p] !== 0xff) break;
        const marker = bytes[p + 1];
        if (marker === 0xda || marker === 0xd9) break; // SOS / EOI
        const len = (bytes[p + 2] << 8) | bytes[p + 3];
        if (len < 2) break;
        if (marker === 0xe1 &&
          bytes[p + 4] === 0x45 && bytes[p + 5] === 0x78 && bytes[p + 6] === 0x69 && bytes[p + 7] === 0x66) {
          app1 = p + 10; break;
        }
        p += 2 + len;
      }
      return app1 < 0 ? null : parseTiff(bytes, app1);
    } catch (_) {
      return null;
    }
  };

  // HEIC / HEIF (ISO-BMFF): locate the "Exif" item via meta>iinf/iloc, then read its TIFF block
  const parseHeicExif = (bytes) => {
    try {
      const u16 = (o) => (bytes[o] << 8) | bytes[o + 1];
      const u32 = (o) => ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
      const typeAt = (o) => String.fromCharCode(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]);
      const findBox = (start, end, type) => {
        let p = start;
        while (p + 8 <= end) {
          let size = u32(p), hdr = 8;
          if (size === 1) { size = u32(p + 8) * 4294967296 + u32(p + 12); hdr = 16; }
          else if (size === 0) size = end - p;
          if (size < 8) break;
          if (typeAt(p + 4) === type) return { body: p + hdr, end: p + size };
          p += size;
        }
        return null;
      };
      const meta = findBox(0, bytes.length, "meta");
      if (!meta) return null;
      const metaStart = meta.body + 4; // meta is a FullBox
      const iinf = findBox(metaStart, meta.end, "iinf");
      const iloc = findBox(metaStart, meta.end, "iloc");
      if (!iinf || !iloc) return null;

      // iinf: find the item whose type is "Exif"
      let p = iinf.body; const iinfVer = bytes[p]; p += 4;
      let cnt = iinfVer === 0 ? u16(p) : u32(p); p += iinfVer === 0 ? 2 : 4;
      let exifId = -1, q = p;
      for (let i = 0; i < cnt && q + 8 <= iinf.end; i++) {
        const bs = u32(q);
        if (typeAt(q + 4) === "infe") {
          const iv = bytes[q + 8]; let r = q + 12;
          if (iv >= 2) {
            let id;
            if (iv === 2) { id = u16(r); r += 2; } else { id = u32(r); r += 4; }
            r += 2; // protection index
            if (typeAt(r) === "Exif") exifId = id;
          }
        }
        if (bs < 8) break;
        q += bs;
      }
      if (exifId < 0) return null;

      // iloc: resolve the item's first extent to a file offset + length
      p = iloc.body; const lver = bytes[p]; p += 4;
      const sz1 = bytes[p], sz2 = bytes[p + 1]; p += 2;
      const offSize = sz1 >> 4, lenSize = sz1 & 0xf, baseSize = sz2 >> 4, idxSize = sz2 & 0xf;
      let items = lver < 2 ? u16(p) : u32(p); p += lver < 2 ? 2 : 4;
      const readN = (o, n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + bytes[o + i]; return v; };
      let eOff = -1;
      for (let i = 0; i < items; i++) {
        const id = lver < 2 ? u16(p) : u32(p); p += lver < 2 ? 2 : 4;
        if (lver === 1 || lver === 2) p += 2; // construction_method
        p += 2; // data_reference_index
        const base = readN(p, baseSize); p += baseSize;
        const ec = u16(p); p += 2;
        let o0 = -1;
        for (let e = 0; e < ec; e++) {
          if (idxSize > 0) p += idxSize;
          const eo = readN(p, offSize); p += offSize;
          p += lenSize; // extent length (unused)
          if (e === 0) o0 = base + eo;
        }
        if (id === exifId) { eOff = o0; break; }
      }
      if (eOff < 0 || eOff + 4 > bytes.length) return null;

      // Exif payload: [4-byte BE offset to TIFF][optional "Exif\0\0"][TIFF]
      let tiff = eOff + 4 + u32(eOff);
      if (bytes[tiff] === 0x45 && bytes[tiff + 1] === 0x78 && bytes[tiff + 2] === 0x69 && bytes[tiff + 3] === 0x66) tiff += 6;
      return parseTiff(bytes, tiff);
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

  /* ---------------- document metadata (Office OOXML, PDF) ---------------- */

  const zipFind = (bytes, name) => {
    try {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      let eocd = -1; const minPos = Math.max(0, bytes.length - 65557);
      for (let i = bytes.length - 22; i >= minPos; i--) {
        if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
      }
      if (eocd < 0) return null;
      const entries = dv.getUint16(eocd + 10, true);
      let off = dv.getUint32(eocd + 16, true);
      for (let i = 0; i < entries && off + 46 <= bytes.length; i++) {
        if (dv.getUint32(off, true) !== 0x02014b50) break;
        const method = dv.getUint16(off + 10, true);
        const csize = dv.getUint32(off + 20, true);
        const nameLen = dv.getUint16(off + 28, true), extraLen = dv.getUint16(off + 30, true), commLen = dv.getUint16(off + 32, true);
        const lho = dv.getUint32(off + 42, true);
        let nm = ""; for (let j = 0; j < nameLen && off + 46 + j < bytes.length; j++) nm += String.fromCharCode(bytes[off + 46 + j]);
        if (nm === name) return { lho, csize, method };
        off += 46 + nameLen + extraLen + commLen;
      }
      return null;
    } catch (_) { return null; }
  };

  const inflateRaw = async (bytes) => {
    const ab = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer();
    return new Uint8Array(ab);
  };

  const zipReadText = async (bytes, name) => {
    try {
      const e = zipFind(bytes, name); if (!e) return null;
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      if (dv.getUint32(e.lho, true) !== 0x04034b50) return null;
      const nameLen = dv.getUint16(e.lho + 26, true), extraLen = dv.getUint16(e.lho + 28, true);
      const start = e.lho + 30 + nameLen + extraLen;
      const comp = bytes.subarray(start, start + e.csize);
      let raw;
      if (e.method === 0) raw = comp;
      else if (e.method === 8) { if (typeof DecompressionStream === "undefined") return null; raw = await inflateRaw(comp); }
      else return null;
      return new TextDecoder("utf-8").decode(raw);
    } catch (_) { return null; }
  };

  const xmlTag = (xml, tag) => {
    if (!xml) return null;
    const m = new RegExp("<" + tag + "[^>]*>([\\s\\S]*?)</" + tag + ">").exec(xml);
    return m ? m[1].replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim() : null;
  };

  const parseOfficeMeta = async (buf) => {
    const core = await zipReadText(buf, "docProps/core.xml");
    const app = await zipReadText(buf, "docProps/app.xml");
    if (!core && !app) return null;
    const m = { kind: "office" };
    m.author = xmlTag(core, "dc:creator");
    m.lastBy = xmlTag(core, "cp:lastModifiedBy");
    m.created = xmlTag(core, "dcterms:created");
    m.modified = xmlTag(core, "dcterms:modified");
    m.revision = xmlTag(core, "cp:revision");
    m.title = xmlTag(core, "dc:title");
    m.keywords = xmlTag(core, "cp:keywords");
    m.lastPrinted = xmlTag(core, "cp:lastPrinted");
    m.app = xmlTag(app, "Application");
    m.appVersion = xmlTag(app, "AppVersion");
    m.company = xmlTag(app, "Company");
    m.manager = xmlTag(app, "Manager");
    const tt = xmlTag(app, "TotalTime"); m.editMinutes = tt ? +tt : null;
    m.template = xmlTag(app, "Template");
    return m;
  };

  const decodePdfStr = (raw) => {
    const out = [];
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (c === "\\") {
        const n = raw[i + 1];
        if (n === "n") { out.push("\n"); i++; }
        else if (n === "r") { out.push("\r"); i++; }
        else if (n === "t") { out.push("\t"); i++; }
        else if (n === "(" || n === ")" || n === "\\") { out.push(n); i++; }
        else if (/[0-7]/.test(n)) { let o = n; i++; for (let k = 0; k < 2 && /[0-7]/.test(raw[i + 1]); k++) o += raw[++i]; out.push(String.fromCharCode(parseInt(o, 8) & 0xff)); }
        else { out.push(n); i++; }
      } else out.push(c);
    }
    let s = out.join("");
    if (s.charCodeAt(0) === 0xfe && s.charCodeAt(1) === 0xff) {
      let u = ""; for (let i = 2; i + 1 < s.length; i += 2) u += String.fromCharCode((s.charCodeAt(i) << 8) | s.charCodeAt(i + 1)); return u;
    }
    return s;
  };
  const decodePdfHex = (hex) => {
    const h = hex.replace(/\s+/g, ""); const b = [];
    for (let i = 0; i + 1 < h.length; i += 2) b.push(parseInt(h.substr(i, 2), 16));
    if (b[0] === 0xfe && b[1] === 0xff) { let u = ""; for (let i = 2; i + 1 < b.length; i += 2) u += String.fromCharCode((b[i] << 8) | b[i + 1]); return u; }
    return b.map((x) => String.fromCharCode(x)).join("");
  };
  const normPdfDate = (d) => {
    if (!d) return null;
    const m = /D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/.exec(d);
    if (!m) return d;
    const Y = m[1], Mo = m[2] || "01", Da = m[3] || "01", H = m[4], Mi = m[5] || "00", S = m[6] || "00";
    return `${Y}-${Mo}-${Da}${H ? ` ${H}:${Mi}:${S}` : ""}`;
  };

  // reject strings that are mostly control bytes (e.g. encrypted / binary gibberish)
  const sanePrint = (v) => {
    if (!v) return null;
    let ctl = 0;
    for (let i = 0; i < v.length; i++) { const c = v.charCodeAt(i); if (c < 32 && c !== 9 && c !== 10 && c !== 13) ctl++; }
    return (ctl === 0 || ctl / v.length < 0.05) ? v.trim() : null;
  };

  const parsePdfMeta = (buf) => {
    try {
      const dec = (u) => new TextDecoder("latin1").decode(u);
      const s = buf.length <= 4 * 1024 * 1024
        ? dec(buf)
        : dec(buf.subarray(0, 3 * 1024 * 1024)) + "\u0000" + dec(buf.subarray(buf.length - 1024 * 1024));
      const encrypted = /\/Encrypt\b/.test(s);
      const field = (key) => {
        let m = new RegExp("/" + key + "\\s*\\(((?:\\\\.|[^\\\\)])*)\\)").exec(s);
        if (m) return decodePdfStr(m[1]);
        m = new RegExp("/" + key + "\\s*<([0-9A-Fa-f\\s]+)>").exec(s);
        if (m) return decodePdfHex(m[1]);
        return null;
      };
      const m = { kind: "pdf", encrypted };
      if (!encrypted) { // when encrypted, the Info dictionary strings are ciphertext
        m.author = sanePrint(field("Author"));
        m.creator = sanePrint(field("Creator"));
        m.producer = sanePrint(field("Producer"));
        m.title = sanePrint(field("Title"));
        m.created = normPdfDate(sanePrint(field("CreationDate")));
        m.modified = normPdfDate(sanePrint(field("ModDate")));
      }
      const xmp = /<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/.exec(s); // XMP stream is often plaintext even when Info is encrypted
      if (xmp) {
        const x = xmp[0];
        m.creator = m.creator || sanePrint(xmlTag(x, "xmp:CreatorTool"));
        m.producer = m.producer || sanePrint(xmlTag(x, "pdf:Producer"));
        m.author = m.author || sanePrint(xmlTag(x, "dc:creator"));
        m.title = m.title || sanePrint(xmlTag(x, "dc:title"));
      }
      const has = Object.keys(m).some((k) => k !== "kind" && k !== "encrypted" && m[k]);
      return (has || encrypted) ? m : null;
    } catch (_) { return null; }
  };

  const fmtMetaDate = (d) => {
    if (!d) return null;
    const iso = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(d);
    return iso ? `${iso[1]} ${iso[2]}` : d;
  };
  const META_GENERIC = /^(un-?named|unknown|user|administrator|admin|owner|windows user|microsoft.*|office)$/i;
  const showAttrs = (label, rows, vText, vLevel) => {
    $("upMetaLabel").textContent = label;
    const box = $("upMeta"); box.textContent = "";
    for (const [k, v, cls] of rows) if (v != null && v !== "") addRow("upMeta", k, String(v), cls || "");
    setVerdict("upMetaVerdict", vText, vLevel);
    $("upMetaCard").hidden = false;
    reveal($("upMetaCard"));
  };

  /* ---- PE (exe / dll) ---- */
  const PE_MACH = { 0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xaa64: "ARM64", 0x1c0: "ARM", 0x1c4: "ARMv7", 0x200: "IA-64", 0xebc: "EFI byte code" };
  const peMeta = (b) => {
    try {
      if (b[0] !== 0x4d || b[1] !== 0x5a) return null;
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      const pe = dv.getUint32(0x3c, true);
      if (pe + 24 > b.length || dv.getUint32(pe, true) !== 0x00004550) return null;
      const coff = pe + 4;
      const machineV = dv.getUint16(coff, true);
      const chars = dv.getUint16(coff + 18, true);
      const tds = dv.getUint32(coff + 8, true);
      const optMagic = dv.getUint16(coff + 20, true);
      const isDll = (chars & 0x2000) !== 0;
      const rows = [], findings = [];
      rows.push(["Format", optMagic === 0x20b ? "PE32+ (64-bit)" : "PE32 (32-bit)"]);
      rows.push(["Architecture", PE_MACH[machineV] || ("0x" + machineV.toString(16))]);
      rows.push(["Kind", isDll ? "Dynamic library (DLL)" : "Windows executable"]);
      let compile = null;
      if (tds && tds !== 0xffffffff) { compile = new Date(tds * 1000).toISOString().replace("T", " ").replace(/\..*/, ""); rows.push(["Compiled (header)", compile + " UTC"]); }
      const u16find = (key) => {
        const pat = []; for (const ch of key) pat.push(ch.charCodeAt(0), 0);
        const i = idxSeq(b, pat, 0); if (i < 0) return null;
        let p = i + pat.length; while (p + 1 < b.length && b[p] === 0 && b[p + 1] === 0) p += 2;
        let s = ""; for (let k = 0; k < 256 && p + 1 < b.length; k++) { const c = b[p] | (b[p + 1] << 8); if (c === 0) break; s += String.fromCharCode(c); p += 2; }
        return sanePrint(s);
      };
      const ver = {};
      for (const [k, label] of [["OriginalFilename", "Original filename"], ["InternalName", "Internal name"], ["CompanyName", "Company"], ["ProductName", "Product"], ["FileDescription", "Description"], ["FileVersion", "File version"], ["ProductVersion", "Product version"], ["LegalCopyright", "Copyright"]]) {
        const v = u16find(k); if (v) { ver[k] = v; rows.push([label, v]); }
      }
      const sfull = new TextDecoder("latin1").decode(b.length <= 8 * 1024 * 1024 ? b : b.subarray(0, 8 * 1024 * 1024));
      const pdb = /[A-Za-z]:\\[^\x00-\x1f"<>|]+?\.pdb|\/[^\x00-\x1f"<>|]+?\.pdb/.exec(sfull);
      if (pdb) rows.push(["Debug/build path", pdb[0], "is-bad"]);
      if (compile) findings.push(["info", `Compiled ${compile} UTC (per PE header; can be faked)`]);
      if (ver.OriginalFilename) findings.push(["info", `Original filename: ${ver.OriginalFilename}`]);
      if (ver.CompanyName) findings.push(["info", `Vendor: ${ver.CompanyName}`]);
      if (pdb) findings.push(["bad", `Embedded build path: ${pdb[0]}`]);
      return { label: "executable metadata", rows, verdict: [isDll ? "DLL" : "Executable", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- Mach-O (macho / dylib) and Java class ---- */
  const machoMeta = (b) => {
    try {
      const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const cpuName = (c) => ({ 7: "x86", 16777223: "x86_64", 12: "ARM", 16777228: "ARM64", 18: "PowerPC", 16777234: "PowerPC64" }[c >>> 0] || ("0x" + (c >>> 0).toString(16)));
      const FT = { 1: "Object", 2: "Executable", 6: "Dynamic library (dylib)", 8: "Bundle", 9: "Dylib stub", 10: "dSYM", 5: "Core" };
      const m0 = be(0), rows = [];
      if (m0 === 0xcafebabe) {
        const n = be(4);
        if (n > 0 && n <= 40) {
          const archs = []; for (let i = 0; i < n; i++) { const o = 8 + i * 20; if (o + 4 > b.length) break; const a = cpuName(be(o)); if (!archs.includes(a)) archs.push(a); }
          rows.push(["Container", "Universal (fat) binary"]);
          rows.push(["Architectures", archs.join(", ")]);
          rows.push(["Kind", "Mach-O executable / library"]);
          return { label: "binary metadata", rows, verdict: ["Mach-O universal", "warn"], findings: [["info", `Mach-O universal binary (${archs.join(", ")})`]] };
        }
        const major = (b[6] << 8) | b[7];
        rows.push(["Format", "Java class file"]); rows.push(["Bytecode version", String(major)]);
        return { label: "binary metadata", rows, verdict: ["Java class", "warn"], findings: [["info", "Java class (JVM bytecode)"]] };
      }
      const le = (m0 === 0xcffaedfe || m0 === 0xcefaedfe);
      const u32 = (o) => le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : be(o);
      const is64 = (m0 === 0xfeedfacf || m0 === 0xcffaedfe);
      const cpu = u32(4), ftype = u32(12);
      rows.push(["Format", is64 ? "Mach-O (64-bit)" : "Mach-O (32-bit)"]);
      rows.push(["Architecture", cpuName(cpu)]);
      rows.push(["Kind", FT[ftype] || ("type " + ftype)]);
      return { label: "binary metadata", rows, verdict: ["Mach-O " + (FT[ftype] || ""), "warn"], findings: [["info", `Mach-O ${FT[ftype] || "binary"} (${cpuName(cpu)})`]] };
    } catch (_) { return null; }
  };

  /* ---- ELF ---- */
  const elfMeta = (b) => {
    try {
      if (b[0] !== 0x7f || b[1] !== 0x45 || b[2] !== 0x4c || b[3] !== 0x46) return null;
      const cls = b[4], le = b[5] === 1;
      const u16 = (o) => le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1];
      const u32 = (o) => le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const TYPE = { 1: "Relocatable (.o)", 2: "Executable", 3: "Shared object / PIE", 4: "Core dump" };
      const MACH = { 0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0xf3: "RISC-V", 0x02: "SPARC" };
      const etype = u16(16), emach = u16(18), rows = [];
      rows.push(["Format", cls === 2 ? "ELF (64-bit)" : "ELF (32-bit)"]);
      rows.push(["Endianness", le ? "little-endian" : "big-endian"]);
      rows.push(["Type", TYPE[etype] || ("type " + etype)]);
      rows.push(["Architecture", MACH[emach] || ("0x" + emach.toString(16))]);
      let interp = null;
      try {
        const phoff = cls === 2 ? u32(0x20) : u32(0x1c);
        const phent = u16(cls === 2 ? 0x36 : 0x2a), phnum = u16(cls === 2 ? 0x38 : 0x2c);
        for (let i = 0; i < phnum; i++) {
          const o = phoff + i * phent; if (o + 4 > b.length) break;
          if (u32(o) === 3) { const off = cls === 2 ? u32(o + 8) : u32(o + 4), sz = cls === 2 ? u32(o + 32) : u32(o + 16); let s = ""; for (let k = 0; k < sz && off + k < b.length; k++) { const c = b[off + k]; if (c === 0) break; s += String.fromCharCode(c); } interp = s; break; }
        }
      } catch (_) {}
      if (interp) rows.push(["Interpreter", interp]);
      return { label: "binary metadata", rows, verdict: ["ELF " + (TYPE[etype] || ""), "warn"], findings: [["info", `ELF ${TYPE[etype] || "binary"} (${MACH[emach] || "?"})`]] };
    } catch (_) { return null; }
  };

  /* ---- scripts (ps1 / sh / py / bat / vbs / js) ---- */
  const SCRIPT_EXT = /^(ps1|psm1|sh|bash|zsh|py|rb|pl|bat|cmd|vbs|js|php)$/;
  const scriptMeta = (b, ext) => {
    try {
      const text = new TextDecoder("utf-8").decode(b.subarray(0, Math.min(b.length, 1024 * 1024)));
      const lines = text.split(/\r\n|\r|\n/).length;
      const rows = [["Lines", lines.toLocaleString("en-US")]];
      const shebang = /^#!.*/.exec(text); if (shebang) rows.push(["Shebang", shebang[0].slice(0, 80)]);
      rows.push(["Encoding", b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf ? "UTF-8 (BOM)" : "UTF-8 / ASCII"]);
      const ind = [], has = (re) => re.test(text);
      if (/ps1|psm1/.test(ext)) {
        if (has(/invoke-expression|\biex\b/i)) ind.push("Invoke-Expression");
        if (has(/downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer/i)) ind.push("remote download");
        if (has(/-enc(odedcommand)?\b|frombase64string/i)) ind.push("encoded/base64 command");
        if (has(/-nop|-noprofile|-w(indowstyle)?\s*hidden|-ep\s*bypass|executionpolicy\s+bypass/i)) ind.push("stealth flags");
      } else if (/sh|bash|zsh/.test(ext)) {
        if (has(/(curl|wget)\s+[^\n|]*\|\s*(bash|sh|zsh)/i)) ind.push("curl/wget pipe to shell");
        if (has(/base64\s+-{1,2}d|base64\s+--decode/i)) ind.push("base64 decode");
        if (has(/\/dev\/tcp\/|bash\s+-i|nc\s+-e/i)) ind.push("reverse shell");
      } else if (ext === "py") {
        if (has(/\bexec\s*\(|\beval\s*\(/)) ind.push("exec/eval");
        if (has(/os\.system|subprocess|os\.popen/)) ind.push("process execution");
        if (has(/base64\.b64decode|codecs\.decode/)) ind.push("base64 decode");
        if (has(/urllib|requests\.(get|post)|socket\./)) ind.push("network");
      } else if (/bat|cmd/.test(ext)) {
        if (has(/powershell|pwsh/i)) ind.push("launches PowerShell");
        if (has(/certutil.*-urlcache|bitsadmin|curl|wget/i)) ind.push("remote download");
      } else if (/vbs|js/.test(ext)) {
        if (has(/eval\(|activexobject|wscript\.shell|createobject/i)) ind.push("script host / eval");
      }
      if (ind.length) rows.push(["Indicators", ind.join(", "), "is-warn"]);
      const findings = [["info", `Script: ${lines.toLocaleString("en-US")} lines${shebang ? ", shebang present" : ""}`]];
      if (ind.length) findings.push(["warn", `Script behaviour indicators: ${ind.join(", ")}`]);
      return { label: "script analysis", rows, verdict: ind.length ? ["Active indicators", "warn"] : ["Script", "good"], findings };
    } catch (_) { return null; }
  };

  /* ---- gzip + tar helpers (for .deb) ---- */
  const gunzip = async (bytes) => {
    const ab = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
    return new Uint8Array(ab);
  };
  const tarReadFile = (t, wantEndsWith) => {
    let p = 0;
    while (p + 512 <= t.length) {
      let nm = ""; for (let i = 0; i < 100 && t[p + i]; i++) nm += String.fromCharCode(t[p + i]);
      if (!nm) break;
      const sz = parseInt(new TextDecoder().decode(t.subarray(p + 124, p + 136)).replace(/\0.*$/, "").trim(), 8) || 0;
      const data = p + 512;
      if (nm.replace(/^\.\//, "").replace(/\/$/, "").endsWith(wantEndsWith)) return t.subarray(data, data + sz);
      p = data + Math.ceil(sz / 512) * 512;
    }
    return null;
  };

  /* ---- image: PNG text chunks ---- */
  const pngMeta = (b) => {
    try {
      const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const rows = [], findings = [], texts = []; let p = 8, w, h;
      while (p + 8 <= b.length) {
        const len = be(p); const type = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]); const data = p + 8;
        if (len < 0 || data + len > b.length) break;
        if (type === "IHDR") { w = be(data); h = be(data + 4); }
        else if (type === "tEXt") { let i = data, key = ""; while (i < data + len && b[i] !== 0) key += String.fromCharCode(b[i++]); i++; let v = ""; for (; i < data + len; i++) v += String.fromCharCode(b[i]); texts.push([key, sanePrint(v)]); }
        else if (type === "iTXt") { let i = data, key = ""; while (i < data + len && b[i] !== 0) key += String.fromCharCode(b[i++]); i++; const comp = b[i]; i += 2; while (i < data + len && b[i] !== 0) i++; i++; while (i < data + len && b[i] !== 0) i++; i++; if (!comp) { let v = ""; for (; i < data + len; i++) v += String.fromCharCode(b[i]); texts.push([key, sanePrint(v)]); } }
        else if (type === "tIME") { rows.push(["Modified (tIME)", `${(b[data] << 8) | b[data + 1]}-${String(b[data + 2]).padStart(2, "0")}-${String(b[data + 3]).padStart(2, "0")} ${String(b[data + 4]).padStart(2, "0")}:${String(b[data + 5]).padStart(2, "0")}`]); }
        if (type === "IEND") break;
        p = data + len + 4;
      }
      if (w && h) rows.unshift(["Dimensions", `${w} × ${h}px`]);
      for (const [k, v] of texts) { if (!v) continue; if (/xmp/i.test(k)) rows.push(["XMP", "present"]); else rows.push([k, v.length > 200 ? v.slice(0, 200) + "…" : v]); }
      const soft = texts.find(([k]) => /^software$/i.test(k)); if (soft && soft[1]) findings.push(["info", `Created with ${soft[1]}`]);
      const auth = texts.find(([k]) => /author|creator/i.test(k)); if (auth && auth[1]) findings.push(["warn", `Metadata names: ${auth[1]}`]);
      return { rows: rows.length ? rows : [["Embedded metadata", "none"]], verdict: texts.length ? ["Metadata present", "warn"] : ["Minimal", "good"], findings, note: "" };
    } catch (_) { return null; }
  };

  /* ---- image: GIF comment ---- */
  const gifMeta = (b) => {
    try {
      const rows = [["Dimensions", `${b[6] | (b[7] << 8)} × ${b[8] | (b[9] << 8)}px`], ["Version", String.fromCharCode(b[3], b[4], b[5])]];
      const findings = []; const cap = Math.min(b.length, 2 * 1024 * 1024);
      const animated = new TextDecoder("latin1").decode(b.subarray(0, cap)).includes("NETSCAPE2.0");
      let comment = null;
      for (let i = 13; i + 2 < cap; i++) { if (b[i] === 0x21 && b[i + 1] === 0xFE) { let p = i + 2, c = ""; while (p < b.length) { const bl = b[p++]; if (bl === 0) break; for (let k = 0; k < bl && p < b.length; k++) c += String.fromCharCode(b[p++]); } comment = sanePrint(c); break; } }
      rows.push(["Animated", animated ? "yes" : "no"]);
      if (comment) { rows.push(["Comment", comment.length > 200 ? comment.slice(0, 200) + "…" : comment]); findings.push(["info", `GIF comment: ${comment.slice(0, 80)}`]); }
      return { rows, verdict: comment ? ["Metadata present", "warn"] : ["Minimal", "good"], findings, note: "" };
    } catch (_) { return null; }
  };

  /* ---- image: SVG ---- */
  const svgMeta = (b) => {
    try {
      const t = new TextDecoder("utf-8").decode(b.subarray(0, Math.min(b.length, 2 * 1024 * 1024)));
      const rows = [], findings = [];
      const w = /\bwidth\s*=\s*"([^"]+)"/.exec(t), h = /\bheight\s*=\s*"([^"]+)"/.exec(t), vb = /viewBox\s*=\s*"([^"]+)"/.exec(t);
      if (w && h) rows.push(["Dimensions", `${w[1]} × ${h[1]}`]); else if (vb) rows.push(["viewBox", vb[1]]);
      const title = xmlTag(t, "dc:title"), creator = xmlTag(t, "dc:creator");
      const gen = /<!--\s*Generator:\s*([^>]+?)\s*-->/.exec(t), inkv = /inkscape:version\s*=\s*"([^"]+)"/.exec(t), docname = /sodipodi:docname\s*=\s*"([^"]+)"/.exec(t);
      if (title) rows.push(["Title", title]);
      if (creator) rows.push(["Creator", creator, "is-warn"]);
      if (gen) rows.push(["Generator", gen[1]]);
      if (inkv) rows.push(["Inkscape", inkv[1]]);
      if (docname) rows.push(["Document name", docname[1]]);
      const abs = /(?:sodipodi:absref|xlink:href)\s*=\s*"(file:\/\/[^"]+|[A-Za-z]:\\[^"]+|\/Users\/[^"]+|\/home\/[^"]+)"/.exec(t);
      if (abs) { rows.push(["Linked local path", abs[1], "is-bad"]); findings.push(["bad", `Embedded local path: ${abs[1]}`]); }
      if (gen) findings.push(["info", `Created with ${gen[1]}`]);
      if (creator) findings.push(["warn", `Metadata names: ${creator}`]);
      return { rows: rows.length ? rows : [["Embedded metadata", "none"]], verdict: (abs || creator) ? ["Reveals details", "warn"] : (rows.length ? ["Metadata present", "good"] : ["Minimal", "good"]), findings, note: "" };
    } catch (_) { return null; }
  };

  /* ---- MP4 / MOV (ISO-BMFF) ---- */
  const mp4Meta = (b) => {
    try {
      const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const typeAt = (o) => String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);
      const findBox = (start, end, type) => { let p = start; while (p + 8 <= end) { let size = be(p), hdr = 8; if (size === 1) { size = be(p + 8) * 4294967296 + be(p + 12); hdr = 16; } else if (size === 0) size = end - p; if (size < 8) break; if (typeAt(p + 4) === type) return { body: p + hdr, end: p + size }; p += size; } return null; };
      const moov = findBox(0, b.length, "moov"); if (!moov) return null;
      const rows = [], findings = []; let gps = null;
      const mvhd = findBox(moov.body, moov.end, "mvhd");
      if (mvhd) { const ver = b[mvhd.body]; const ct = ver === 1 ? be(mvhd.body + 4) * 4294967296 + be(mvhd.body + 8) : be(mvhd.body + 4); if (ct > 2082844800) rows.push(["Created", new Date((ct - 2082844800) * 1000).toISOString().replace("T", " ").replace(/\..*/, "") + " UTC"]); }
      const udta = findBox(moov.body, moov.end, "udta");
      if (udta) {
        const xyz = findBox(udta.body, udta.end, "©xyz");
        if (xyz) { const len = (b[xyz.body] << 8) | b[xyz.body + 1]; let s = ""; for (let i = 0; i < len && xyz.body + 4 + i < b.length; i++) s += String.fromCharCode(b[xyz.body + 4 + i]); const m = /([+\-]\d+\.?\d*)([+\-]\d+\.?\d*)/.exec(s); if (m) { gps = { lat: parseFloat(m[1]), lon: parseFloat(m[2]) }; rows.push(["GPS", `${gps.lat}, ${gps.lon}`, "is-bad"]); } }
        for (const [atom, label] of [["©too", "Encoder"], ["©swr", "Software"], ["©mak", "Make"], ["©mod", "Model"], ["©nam", "Title"]]) { const bx = findBox(udta.body, udta.end, atom); if (bx) { const len = (b[bx.body] << 8) | b[bx.body + 1]; let s = ""; for (let i = 0; i < len && bx.body + 4 + i < b.length; i++) s += String.fromCharCode(b[bx.body + 4 + i]); s = sanePrint(s); if (s) rows.push([label, s]); } }
      }
      if (gps) findings.push(["bad", "GPS coordinates embedded in video metadata"]);
      return { label: "media metadata", rows: rows.length ? rows : [["Metadata", "none detected"]], verdict: gps ? ["Location embedded", "bad"] : (rows.length ? ["Metadata present", "warn"] : ["Minimal", "good"]), findings, gps };
    } catch (_) { return null; }
  };

  /* ---- Debian .deb (ar + control.tar.gz) ---- */
  const debMeta = async (b) => {
    try {
      if (new TextDecoder("latin1").decode(b.subarray(0, 8)) !== "!<arch>\n") return null;
      const rows = [], findings = [], members = []; let p = 8, control = null;
      while (p + 60 <= b.length) {
        const hdr = new TextDecoder("latin1").decode(b.subarray(p, p + 60));
        const name = hdr.substr(0, 16).trim(); const size = parseInt(hdr.substr(48, 10).trim(), 10) || 0;
        if (!name) break;
        members.push(name);
        if (/^control\.tar/.test(name)) control = { name, start: p + 60, size };
        p = p + 60 + size + (size % 2);
      }
      rows.push(["Package format", "Debian .deb (ar archive)"]);
      rows.push(["Members", members.join(", ")]);
      if (control) {
        const raw = b.subarray(control.start, control.start + control.size);
        let tar = null;
        if (control.name.endsWith(".gz") && typeof DecompressionStream !== "undefined") tar = await gunzip(raw);
        else if (control.name.endsWith(".tar")) tar = raw;
        if (tar) {
          const cf = tarReadFile(tar, "control");
          if (cf) { const text = new TextDecoder("utf-8").decode(cf); for (const f of ["Package", "Version", "Architecture", "Maintainer", "Installed-Size", "Section", "Homepage", "Depends", "Description"]) { const m = new RegExp("^" + f + ":\\s*(.+)$", "m").exec(text); if (m) { rows.push([f, m[1].trim()]); if (f === "Maintainer") findings.push(["warn", `Maintainer: ${m[1].trim()}`]); } } }
        } else rows.push(["Control", `compressed as ${control.name.split(".").pop()} (not readable in-browser)`, "is-warn"]);
      }
      return { label: "package metadata", rows, verdict: ["Debian package", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- RPM header ---- */
  const rpmMeta = (b) => {
    try {
      if (b[0] !== 0xed || b[1] !== 0xab || b[2] !== 0xee || b[3] !== 0xdb) return null;
      const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const parseHdr = (start) => { if (b[start] !== 0x8e || b[start + 1] !== 0xad || b[start + 2] !== 0xe8) return null; const nindex = be(start + 8), hsize = be(start + 12); const idx = start + 16, store = idx + nindex * 16; return { nindex, idx, store, end: store + hsize }; };
      let p = 96; const sig = parseHdr(p); if (!sig) return null; p = Math.ceil(sig.end / 8) * 8; const hdr = parseHdr(p); if (!hdr) return null;
      const TAGS = { 1000: "Package", 1001: "Version", 1002: "Release", 1004: "Summary", 1007: "Build host", 1011: "Vendor", 1014: "License", 1016: "Group", 1022: "Architecture", 1006: "Build time", 1020: "URL" };
      const rows = [], findings = [];
      for (let i = 0; i < hdr.nindex; i++) {
        const e = hdr.idx + i * 16, tag = be(e), type = be(e + 4), off = be(e + 8);
        if (!TAGS[tag]) continue;
        let v = null;
        if (type === 6 || type === 8 || type === 9) { let s = "", q = hdr.store + off; while (q < hdr.end && b[q]) s += String.fromCharCode(b[q++]); v = sanePrint(s); }
        else if (type === 4) { const n = be(hdr.store + off); v = tag === 1006 ? new Date(n * 1000).toISOString().replace("T", " ").replace(/\..*/, "") + " UTC" : String(n); }
        if (v) rows.push([TAGS[tag], v]);
      }
      const host = rows.find((r) => r[0] === "Build host"); if (host) findings.push(["info", `Built on host: ${host[1]}`]);
      return { label: "package metadata", rows: rows.length ? rows : [["RPM", "header parsed"]], verdict: ["RPM package", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- fonts (sfnt: ttf / otf / ttc) ---- */
  const parseNameTable = (b, nameOff) => {
    const be16 = (o) => (b[o] << 8) | b[o + 1];
    const count = be16(nameOff + 2), strOff = nameOff + be16(nameOff + 4);
    const NAMES = { 0: "Copyright", 1: "Family", 2: "Subfamily", 4: "Full name", 5: "Version", 8: "Manufacturer", 9: "Designer", 11: "Vendor URL", 13: "License" };
    const got = {};
    for (let i = 0; i < count; i++) {
      const e = nameOff + 6 + i * 12; const plat = be16(e), nid = be16(e + 6), len = be16(e + 8), off = be16(e + 10);
      if (NAMES[nid] === undefined) continue;
      const s = strOff + off; let str = "";
      if (plat === 3 || plat === 0) { for (let k = 0; k + 1 < len; k += 2) str += String.fromCharCode((b[s + k] << 8) | b[s + k + 1]); }
      else { for (let k = 0; k < len; k++) str += String.fromCharCode(b[s + k]); }
      str = sanePrint(str); if (str && (got[nid] === undefined || plat === 3)) got[nid] = str;
    }
    const rows = []; for (const id of [1, 2, 4, 5, 8, 9, 13, 0]) if (got[id]) rows.push([NAMES[id], got[id].length > 120 ? got[id].slice(0, 120) + "…" : got[id]]);
    return rows;
  };
  const fontMeta = (b, ext) => {
    try {
      const be16 = (o) => (b[o] << 8) | b[o + 1], be32 = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const tag0 = String.fromCharCode(b[0], b[1], b[2], b[3]);
      if (ext === "woff2" || tag0 === "wOF2") return { label: "font metadata", rows: [["Format", "WOFF2"], ["Note", "tables are Brotli-compressed; name table not read in-browser", "is-warn"]], verdict: ["WOFF2 font", "good"], findings: [] };
      if (ext === "woff" || tag0 === "wOFF") return { label: "font metadata", rows: [["Format", "WOFF"], ["Note", "tables are compressed; name table not read in-browser", "is-warn"]], verdict: ["WOFF font", "good"], findings: [] };
      let base = 0, fmtLabel = tag0 === "OTTO" ? "OpenType (CFF)" : "TrueType / OpenType";
      if (tag0 === "ttcf") { base = be32(12); fmtLabel = "TrueType Collection"; }
      const numTables = be16(base + 4); let nameOff = 0;
      for (let i = 0; i < numTables; i++) { const e = base + 12 + i * 16; if (String.fromCharCode(b[e], b[e + 1], b[e + 2], b[e + 3]) === "name") { nameOff = be32(e + 8); break; } }
      const rows = [["Format", fmtLabel]];
      if (nameOff) for (const r of parseNameTable(b, nameOff)) rows.push(r);
      const findings = []; const mfr = rows.find((r) => r[0] === "Manufacturer"); if (mfr) findings.push(["info", `Font vendor: ${mfr[1]}`]);
      return { label: "font metadata", rows, verdict: ["Font", "good"], findings };
    } catch (_) { return null; }
  };

  /* ---- audio ---- */
  const wavMeta = (b) => {
    try {
      const le32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0, le16 = (o) => b[o] | (b[o + 1] << 8);
      const tag = (o) => String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);
      const rows = [], findings = []; let p = 12, byteRate = 0;
      while (p + 8 <= b.length) {
        const id = tag(p), sz = le32(p + 4), d = p + 8;
        if (id === "fmt ") { const fmt = le16(d); rows.push(["Codec", fmt === 1 ? "PCM" : fmt === 3 ? "IEEE float" : "code " + fmt]); rows.push(["Sample rate", le32(d + 4).toLocaleString("en-US") + " Hz"]); rows.push(["Channels", String(le16(d + 2))]); rows.push(["Bit depth", le16(d + 14) + "-bit"]); byteRate = le32(d + 8); }
        else if (id === "data" && byteRate) rows.push(["Duration", (sz / byteRate).toFixed(2) + " s"]);
        else if (id === "LIST" && tag(d) === "INFO") { let q = d + 4; const MAP = { INAM: "Title", IART: "Artist", ICMT: "Comment", ISFT: "Software", ICOP: "Copyright", ICRD: "Date" }; while (q + 8 <= d + sz) { const sid = tag(q), ssz = le32(q + 4); let v = ""; for (let i = 0; i < ssz && b[q + 8 + i]; i++) v += String.fromCharCode(b[q + 8 + i]); v = sanePrint(v); if (MAP[sid] && v) rows.push([MAP[sid], v]); q += 8 + ssz + (ssz % 2); } }
        p = d + sz + (sz % 2); if (sz <= 0) break;
      }
      const soft = rows.find((r) => r[0] === "Software"); if (soft) findings.push(["info", `Created with ${soft[1]}`]);
      return { label: "audio metadata", rows: rows.length ? rows : [["Audio", "WAV"]], verdict: ["Audio", "good"], findings };
    } catch (_) { return null; }
  };
  const mp3Meta = (b) => {
    try {
      const rows = [], findings = [];
      if (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) {
        const ver = b[3], size = ((b[6] & 0x7f) << 21) | ((b[7] & 0x7f) << 14) | ((b[8] & 0x7f) << 7) | (b[9] & 0x7f);
        const end = Math.min(10 + size, b.length); let p = 10;
        const MAP = { TIT2: "Title", TPE1: "Artist", TALB: "Album", TYER: "Year", TDRC: "Year", TCON: "Genre", TSSE: "Encoder", TENC: "Encoder", COMM: "Comment", TCOM: "Composer", TPUB: "Publisher" };
        const readText = (o, len) => { const enc = b[o]; let s = ""; if (enc === 1 || enc === 2) { let st = o + 1, bom = 0; if ((b[st] === 0xff && b[st + 1] === 0xfe) || (b[st] === 0xfe && b[st + 1] === 0xff)) bom = 2; const beo = b[st] === 0xfe; for (let k = st + bom; k + 1 < o + len; k += 2) s += String.fromCharCode(beo ? (b[k] << 8) | b[k + 1] : b[k] | (b[k + 1] << 8)); } else { s = new TextDecoder(enc === 3 ? "utf-8" : "latin1").decode(b.subarray(o + 1, o + len)); } return sanePrint(s.replace(/\0+$/, "")); };
        while (p + 10 <= end) { const id = String.fromCharCode(b[p], b[p + 1], b[p + 2], b[p + 3]); if (!/^[A-Z0-9]{4}$/.test(id)) break; const fsize = ver === 4 ? (((b[p + 4] & 0x7f) << 21) | ((b[p + 5] & 0x7f) << 14) | ((b[p + 6] & 0x7f) << 7) | (b[p + 7] & 0x7f)) : ((b[p + 4] << 24) | (b[p + 5] << 16) | (b[p + 6] << 8) | b[p + 7]) >>> 0; const data = p + 10; if (MAP[id] && fsize > 0) { const v = readText(data, fsize); if (v) rows.push([MAP[id], v.length > 120 ? v.slice(0, 120) + "…" : v]); } p = data + fsize; if (fsize <= 0) break; }
      }
      if (!rows.length && b.length > 128 && b[b.length - 128] === 0x54 && b[b.length - 127] === 0x41 && b[b.length - 126] === 0x47) { const t = b.length - 128, g = (o, n) => sanePrint(new TextDecoder("latin1").decode(b.subarray(o, o + n)).replace(/\0.*$/, "").trim()); const ti = g(t + 3, 30), ar = g(t + 33, 30), al = g(t + 63, 30); if (ti) rows.push(["Title", ti]); if (ar) rows.push(["Artist", ar]); if (al) rows.push(["Album", al]); }
      const enc = rows.find((r) => r[0] === "Encoder"); if (enc) findings.push(["info", `Encoder: ${enc[1]}`]);
      return { label: "audio metadata", rows: rows.length ? rows : [["Audio", "MP3"]], verdict: ["Audio", "good"], findings };
    } catch (_) { return null; }
  };
  const flacMeta = (b) => {
    try {
      if (!(b[0] === 0x66 && b[1] === 0x4c && b[2] === 0x61 && b[3] === 0x43)) return null;
      const be24 = (o) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]; const rows = []; let p = 4, last = false;
      while (!last && p + 4 <= b.length) {
        const h = b[p]; last = (h & 0x80) !== 0; const type = h & 0x7f, size = be24(p + 1), d = p + 4;
        if (type === 0) { const sr = (b[d + 10] << 12) | (b[d + 11] << 4) | (b[d + 12] >> 4); const ch = ((b[d + 12] >> 1) & 0x7) + 1; const bits = (((b[d + 12] & 1) << 4) | (b[d + 13] >> 4)) + 1; const total = (b[d + 13] & 0xf) * 4294967296 + (((b[d + 14] << 24) | (b[d + 15] << 16) | (b[d + 16] << 8) | b[d + 17]) >>> 0); rows.push(["Sample rate", sr.toLocaleString("en-US") + " Hz"], ["Channels", String(ch)], ["Bit depth", bits + "-bit"]); if (sr) rows.push(["Duration", (total / sr).toFixed(2) + " s"]); }
        else if (type === 4) { let q = d; const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; const vlen = u32(q); q += 4; const vendor = sanePrint(new TextDecoder("utf-8").decode(b.subarray(q, q + vlen))); q += vlen; if (vendor) rows.push(["Encoder", vendor]); const cnt = u32(q); q += 4; for (let i = 0; i < cnt && q + 4 <= d + size; i++) { const l = u32(q); q += 4; const kv = new TextDecoder("utf-8").decode(b.subarray(q, q + l)); q += l; const eq = kv.indexOf("="); if (eq > 0) { const k = kv.slice(0, eq), v = sanePrint(kv.slice(eq + 1)); if (v && /^(title|artist|album|date|genre|comment|albumartist|tracknumber)$/i.test(k)) rows.push([k[0].toUpperCase() + k.slice(1).toLowerCase(), v]); } } }
        p = d + size; if (size <= 0) break;
      }
      return { label: "audio metadata", rows: rows.length ? rows : [["Audio", "FLAC"]], verdict: ["Audio", "good"], findings: [] };
    } catch (_) { return null; }
  };
  const oggMeta = (b) => {
    try {
      const i = idxSeq(b, [0x03, 0x76, 0x6f, 0x72, 0x62, 0x69, 0x73], 0); if (i < 0) return null;
      const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
      let q = i + 7; const vlen = u32(q); q += 4; const vendor = sanePrint(new TextDecoder("utf-8").decode(b.subarray(q, q + vlen))); q += vlen; const cnt = u32(q); q += 4;
      const rows = []; if (vendor) rows.push(["Encoder", vendor]);
      for (let k = 0; k < cnt && q + 4 <= b.length && k < 30; k++) { const l = u32(q); q += 4; const kv = new TextDecoder("utf-8").decode(b.subarray(q, q + l)); q += l; const eq = kv.indexOf("="); if (eq > 0) { const key = kv.slice(0, eq), v = sanePrint(kv.slice(eq + 1)); if (v && /^(title|artist|album|date|genre|comment)$/i.test(key)) rows.push([key[0].toUpperCase() + key.slice(1).toLowerCase(), v]); } }
      return { label: "audio metadata", rows: rows.length ? rows : [["Audio", "OGG"]], verdict: ["Audio", "good"], findings: [] };
    } catch (_) { return null; }
  };

  /* ---- SQLite ---- */
  const sqliteMeta = (b) => {
    try {
      const be16 = (o) => (b[o] << 8) | b[o + 1], be32 = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const rows = [], findings = []; let ps = be16(16); if (ps === 1) ps = 65536;
      rows.push(["Page size", ps.toLocaleString("en-US") + " B"]);
      rows.push(["Page count", be32(28).toLocaleString("en-US")]);
      const enc = be32(56); rows.push(["Text encoding", enc === 1 ? "UTF-8" : enc === 2 ? "UTF-16le" : enc === 3 ? "UTF-16be" : String(enc)]);
      if (be32(60)) rows.push(["User version", String(be32(60))]);
      const sv = be32(96); if (sv) rows.push(["SQLite version", `${Math.floor(sv / 1000000)}.${Math.floor(sv / 1000) % 1000}.${sv % 1000}`]);
      const s = new TextDecoder("latin1").decode(b.subarray(0, Math.min(b.length, 512 * 1024)));
      const tbls = [...s.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`\[]?([A-Za-z_][A-Za-z0-9_]*)/gi)].map((m) => m[1]);
      const uniq = [...new Set(tbls)].filter((n) => !/^sqlite_/.test(n));
      if (uniq.length) { rows.push(["Tables", `${uniq.length}: ${uniq.slice(0, 12).join(", ")}${uniq.length > 12 ? "…" : ""}`]); findings.push(["info", `SQLite tables: ${uniq.slice(0, 8).join(", ")}${uniq.length > 8 ? "…" : ""}`]); }
      return { label: "database metadata", rows, verdict: ["SQLite database", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- archives: gzip (orig name) + tar (entries) ---- */
  const gzipMeta = (b) => {
    try {
      if (b[0] !== 0x1f || b[1] !== 0x8b) return null;
      const rows = [], findings = [], flg = b[3];
      const mtime = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
      if (mtime) rows.push(["Modified", new Date(mtime * 1000).toISOString().replace("T", " ").replace(/\..*/, "") + " UTC"]);
      rows.push(["Source OS", ({ 0: "FAT / Windows", 3: "Unix", 7: "macOS", 11: "NTFS", 255: "unknown" }[b[9]]) || ("code " + b[9])]);
      let p = 10; if (flg & 0x04) { p += 2 + (b[p] | (b[p + 1] << 8)); }
      if (flg & 0x08) { let name = ""; while (p < b.length && b[p] !== 0) name += String.fromCharCode(b[p++]); name = sanePrint(name); if (name) { rows.push(["Original filename", name]); findings.push(["info", `Original filename: ${name}`]); } }
      return { label: "archive metadata", rows: rows.length ? rows : [["Archive", "GZIP"]], verdict: ["GZIP archive", "good"], findings };
    } catch (_) { return null; }
  };
  const tarMeta = (b) => {
    try {
      const readSize = (o) => { if (b[o] & 0x80) { let v = 0; for (let i = 1; i < 12; i++) v = v * 256 + b[o + i]; return v; } return parseInt(new TextDecoder().decode(b.subarray(o, o + 12)).replace(/\0.*$/, "").trim(), 8) || 0; };
      const names = []; let p = 0, total = 0;
      while (p + 512 <= b.length && names.length < 4000) {
        let nm = ""; for (let i = 0; i < 100 && b[p + i]; i++) nm += String.fromCharCode(b[p + i]);
        if (!nm) break;
        if (!/^[\x20-\x7e]+$/.test(nm)) break; // not a clean tar header; stop rather than emit garbage
        const sz = readSize(p + 124);
        if (nm !== "././@LongLink" && !/^(\.\/)?PaxHeader/.test(nm)) { names.push(nm.replace(/^\.\//, "")); total += sz; }
        p += 512 + Math.ceil(sz / 512) * 512;
      }
      if (!names.length) return { label: "archive metadata", rows: [["Format", "TAR archive"], ["Note", "entry table not cleanly readable"]], verdict: ["TAR archive", "good"], findings: [] };
      const kb = total / 1024; const size = kb >= 1024 ? (kb / 1024).toFixed(1) + " MB" : kb.toFixed(1) + " KB";
      return { label: "archive metadata", rows: [["Entries", String(names.length)], ["Total size", size], ["Files", names.slice(0, 10).join(", ") + (names.length > 10 ? "…" : "")]], verdict: ["TAR archive", "good"], findings: [] };
    } catch (_) { return null; }
  };

  /* ---- TIFF (reuses parseTiff) ---- */
  const tiffMeta = (b) => {
    try {
      const ex = parseTiff(b, 0); const rows = [], findings = [];
      if (ex) { if (ex.width && ex.height) rows.push(["Dimensions", `${ex.width} × ${ex.height}px`]); if (ex.make || ex.model) rows.push(["Camera", [ex.make, ex.model].filter(Boolean).join(" ")]); if (ex.software) rows.push(["Software", ex.software]); if (ex.datetime) rows.push(["Date", ex.datetime]); if (ex.gps) { rows.push(["GPS", `${ex.gps.lat.toFixed(6)}, ${ex.gps.lon.toFixed(6)}`, "is-bad"]); findings.push(["bad", "GPS coordinates embedded in image metadata"]); } }
      return { label: "image metadata", rows: rows.length ? rows : [["TIFF", "image"]], verdict: ex && ex.gps ? ["Location embedded", "bad"] : ["Image", "good"], findings, gps: ex && ex.gps };
    } catch (_) { return null; }
  };

  /* ---- small image dimension readers ---- */
  const bmpMeta = (b) => { try { const le32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) | 0; return { rows: [["Dimensions", `${Math.abs(le32(18))} × ${Math.abs(le32(22))}px`], ["Colour depth", (b[28] | (b[29] << 8)) + "-bit"]], verdict: ["Image", "good"], findings: [], note: "" }; } catch (_) { return null; } };
  const icoMeta = (b) => { try { const n = b[4] | (b[5] << 8); const sizes = []; for (let i = 0; i < n && 6 + i * 16 + 2 <= b.length; i++) { const o = 6 + i * 16; sizes.push(`${b[o] || 256}×${b[o + 1] || 256}`); } return { rows: [["Images", String(n)], ["Sizes", sizes.join(", ")]], verdict: ["Icon", "good"], findings: [], note: "" }; } catch (_) { return null; } };
  const webpMeta = (b) => { try { const le16 = (o) => b[o] | (b[o + 1] << 8); const c = String.fromCharCode(b[12], b[13], b[14], b[15]); let w, h, kind; if (c === "VP8X") { w = (b[24] | (b[25] << 8) | (b[26] << 16)) + 1; h = (b[27] | (b[28] << 8) | (b[29] << 16)) + 1; kind = "Extended"; } else if (c === "VP8L") { const bits = (b[21] | (b[22] << 8) | (b[23] << 16) | (b[24] << 24)) >>> 0; w = (bits & 0x3FFF) + 1; h = ((bits >> 14) & 0x3FFF) + 1; kind = "Lossless"; } else if (c === "VP8 ") { w = le16(26) & 0x3FFF; h = le16(28) & 0x3FFF; kind = "Lossy"; } const rows = []; if (w && h) rows.push(["Dimensions", `${w} × ${h}px`]); if (kind) rows.push(["Compression", kind]); return { rows: rows.length ? rows : [["WebP", "image"]], verdict: ["Image", "good"], findings: [], note: "" }; } catch (_) { return null; } };
  const avifMeta = (b) => { try { const exif = parseHeicExif(b); const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; const rows = [], findings = []; const i = idxSeq(b, [0x69, 0x73, 0x70, 0x65], 0); if (i > 0) { const w = be(i + 8), h = be(i + 12); if (w && h && w < 1e5 && h < 1e5) rows.push(["Dimensions", `${w} × ${h}px`]); } if (exif) { if (exif.make || exif.model) rows.push(["Camera", [exif.make, exif.model].filter(Boolean).join(" ")]); if (exif.gps) { rows.push(["GPS", `${exif.gps.lat.toFixed(6)}, ${exif.gps.lon.toFixed(6)}`, "is-bad"]); findings.push(["bad", "GPS coordinates embedded in image metadata"]); } } return { rows: rows.length ? rows : [["AVIF", "image"]], verdict: exif && exif.gps ? ["Location embedded", "bad"] : ["Image", "good"], findings, note: "", gps: exif && exif.gps }; } catch (_) { return null; } };
  const icnsMeta = (b) => { try { const be = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; const total = be(4); const types = []; let p = 8; while (p + 8 <= Math.min(total, b.length)) { types.push(String.fromCharCode(b[p], b[p + 1], b[p + 2], b[p + 3])); const sz = be(p + 4); if (sz < 8) break; p += sz; if (types.length > 60) break; } return { label: "image metadata", rows: [["Icon entries", String(types.length)], ["Types", types.slice(0, 12).join(", ")]], verdict: ["Icon", "good"], findings: [] }; } catch (_) { return null; } };

  /* ---- WebAssembly ---- */
  const wasmMeta = (b) => {
    try {
      const rows = [["Format", "WebAssembly"], ["Version", String((b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0)]]; const findings = [];
      const leb = (o) => { let r = 0, s = 0, q = o; for (; ;) { const by = b[q++]; r |= (by & 0x7f) << s; if (!(by & 0x80)) break; s += 7; if (s > 35) break; } return [r >>> 0, q]; };
      const SEC = { 1: "Type", 2: "Import", 3: "Function", 4: "Table", 5: "Memory", 6: "Global", 7: "Export", 8: "Start", 9: "Element", 10: "Code", 11: "Data", 12: "DataCount", 0: "Custom" };
      let p = 8; const present = new Set(); let imports = 0, exports = 0, producer = null;
      while (p < b.length) { const id = b[p++]; let sz; [sz, p] = leb(p); const content = p; if (sz <= 0 || content + sz > b.length) break; if (id === 2) { imports = leb(content)[0]; } else if (id === 7) { exports = leb(content)[0]; } else if (id === 0) { const [nl, q] = leb(content); let nm = ""; for (let k = 0; k < nl; k++) nm += String.fromCharCode(b[q + k]); if (nm === "producers") { const sub = new TextDecoder("latin1").decode(b.subarray(q + nl, content + sz)); const pm = /(clang|rustc|wasi-sdk|emscripten|LLVM|binaryen|AssemblyScript|TinyGo)[^\x00]{0,40}/i.exec(sub); if (pm) producer = pm[0]; } } present.add(SEC[id] || ("#" + id)); p = content + sz; }
      rows.push(["Sections", [...present].join(", ")]);
      if (imports) rows.push(["Imports", String(imports)]);
      if (exports) rows.push(["Exports", String(exports)]);
      if (producer) { rows.push(["Producer", producer]); findings.push(["info", `Built with ${producer}`]); }
      return { label: "binary metadata", rows, verdict: ["WebAssembly", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- packet captures ---- */
  const pcapMeta = (b) => {
    try {
      const le = (b[0] === 0xd4 && b[1] === 0xc3) || (b[0] === 0x4d && b[1] === 0x3c);
      const u32 = (o) => le ? (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0 : ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
      const LINK = { 0: "loopback/null", 1: "Ethernet", 101: "raw IP", 105: "802.11 Wi-Fi", 113: "Linux SLL", 127: "802.11 radiotap", 147: "user", 228: "IPv4" };
      const rows = [["Format", "PCAP"], ["Byte order", le ? "little-endian" : "big-endian"], ["Link type", LINK[u32(20)] || ("type " + u32(20))], ["Snap length", u32(16).toLocaleString("en-US")]];
      let p = 24, n = 0, firstT = null, lastT = null;
      while (p + 16 <= b.length && n < 2000000) { const ts = u32(p), incl = u32(p + 8); if (firstT === null) firstT = ts; lastT = ts; p += 16 + incl; n++; if (incl <= 0 || incl > 1e7) break; }
      rows.push(["Packets", n.toLocaleString("en-US") + (p < b.length ? "+" : "")]);
      if (firstT && lastT && lastT >= firstT) rows.push(["Duration", (lastT - firstT) + " s"]);
      if (firstT) rows.push(["First packet", new Date(firstT * 1000).toISOString().replace("T", " ").replace(/\..*/, "") + " UTC"]);
      return { label: "capture metadata", rows, verdict: ["PCAP capture", "warn"], findings: [] };
    } catch (_) { return null; }
  };
  const pcapngMeta = (b) => {
    try { const u32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; let p = 0, n = 0; while (p + 12 <= b.length && n < 4000000) { const type = u32(p), len = u32(p + 4); if (len < 12 || p + len > b.length) break; if (type === 6 || type === 3) n++; p += len; } return { label: "capture metadata", rows: [["Format", "PCAPNG"], ["Packet blocks", n.toLocaleString("en-US")]], verdict: ["PCAPNG capture", "warn"], findings: [] }; } catch (_) { return null; }
  };

  /* ---- ISO 9660 ---- */
  const isoMeta = (b) => {
    try {
      const pvd = 0x8000;
      if (!(b[pvd] === 1 && b[pvd + 1] === 0x43 && b[pvd + 2] === 0x44 && b[pvd + 3] === 0x30 && b[pvd + 4] === 0x30 && b[pvd + 5] === 0x31)) return null;
      const str = (o, n) => sanePrint(new TextDecoder("latin1").decode(b.subarray(o, o + n)).trim());
      const le32 = (o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
      const le16 = (o) => b[o] | (b[o + 1] << 8);
      const date = (o) => { const s = new TextDecoder("latin1").decode(b.subarray(o, o + 16)); return (/^\d{8}/.test(s) && !/^0{8}/.test(s)) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(8, 10)}:${s.slice(10, 12)}` : null; };
      const rows = [], findings = [];
      const volId = str(pvd + 40, 32); if (volId) rows.push(["Volume ID", volId]);
      const sysId = str(pvd + 8, 32); if (sysId) rows.push(["System ID", sysId]);
      const blocks = le32(pvd + 80), bsize = le16(pvd + 128);
      if (blocks && bsize) { const mb = (blocks * bsize) / (1024 * 1024); rows.push(["Volume size", mb >= 1024 ? (mb / 1024).toFixed(2) + " GB" : mb.toFixed(1) + " MB"]); }
      if (bsize) rows.push(["Block size", bsize + " B"]);
      const pub = str(pvd + 318, 128); if (pub) rows.push(["Publisher", pub]);
      const prep = str(pvd + 446, 128); if (prep) rows.push(["Data preparer", prep]);
      const app = str(pvd + 574, 128); if (app) rows.push(["Application", app]);
      const cd = date(pvd + 813); if (cd) rows.push(["Created", cd]);
      const md = date(pvd + 830); if (md) rows.push(["Modified", md]);
      try {
        const rootLBA = le32(pvd + 158), rootLen = le32(pvd + 166);
        if (rootLBA && bsize) {
          const start = rootLBA * bsize, end = Math.min(start + rootLen, b.length); const names = []; let p = start;
          while (p < end) { const rl = b[p]; if (rl === 0) { p = start + (Math.floor((p - start) / bsize) + 1) * bsize; continue; } const nlen = b[p + 32]; if (!(nlen === 1 && (b[p + 33] === 0 || b[p + 33] === 1))) { let nm = ""; for (let i = 0; i < nlen; i++) nm += String.fromCharCode(b[p + 33 + i]); nm = nm.replace(/;1$/, ""); if (nm) names.push(nm); } p += rl; if (names.length > 300) break; }
          if (names.length) rows.push(["Root contents", names.slice(0, 15).join(", ") + (names.length > 15 ? "…" : "")]);
        }
      } catch (_) {}
      const who = [app, pub, prep].filter(Boolean)[0]; if (who) findings.push(["info", `ISO prepared by: ${who}`]);
      return { label: "disk image metadata", rows: rows.length ? rows : [["ISO 9660", "disk image"]], verdict: ["ISO 9660", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- RAR (v5 entry listing; v4 noted) ---- */
  const rarMeta = (b) => {
    try {
      const rows = [], findings = [], names = [];
      if (!(b[6] === 0x01 && b[7] === 0x00)) { rows.push(["Format", "RAR (v4 or older)"], ["Note", "entry list needs a RAR4 parser", "is-warn"]); return { label: "archive metadata", rows, verdict: ["RAR archive", "warn"], findings }; }
      rows.push(["Format", "RAR5"]);
      const vint = (o) => { let r = 0, s = 0, q = o; for (; ;) { const by = b[q++]; r += (by & 0x7f) * Math.pow(2, s); if (!(by & 0x80)) break; s += 7; if (s > 63 || q > b.length) break; } return [r, q]; };
      let p = 8, guard = 0;
      while (p + 5 < b.length && guard++ < 100000) {
        let [hsize, q] = vint(p + 4); const headerStart = q; if (hsize <= 0) break;
        let [htype, q2] = vint(q); let [hflags, q3] = vint(q2); let pos = q3, dataSize = 0;
        if (hflags & 0x01) { const r = vint(pos); pos = r[1]; }
        if (hflags & 0x02) { const r = vint(pos); dataSize = r[0]; pos = r[1]; }
        if (htype === 2 || htype === 3) {
          let [fflags, a] = vint(pos); let [unp, c] = vint(a); let [attr, d] = vint(c); let pp = d;
          if (fflags & 0x02) pp += 4; if (fflags & 0x04) pp += 4;
          let [cinfo, e] = vint(pp); let [hos, f] = vint(e); let [nlen, g] = vint(f);
          let nm = ""; for (let i = 0; i < nlen && g + i < b.length; i++) nm += String.fromCharCode(b[g + i]);
          try { nm = decodeURIComponent(escape(nm)); } catch (_) {}
          if (htype === 2 && nm) names.push(nm);
        }
        if (htype === 5) break;
        p = headerStart + hsize + dataSize; if (p <= headerStart) break;
      }
      if (names.length) { rows.push(["Entries", String(names.length)], ["Files", names.slice(0, 12).join(", ") + (names.length > 12 ? "…" : "")]); }
      return { label: "archive metadata", rows, verdict: ["RAR archive", "warn"], findings };
    } catch (_) { return null; }
  };

  /* ---- compressor headers (contents need decoders not in the browser) ---- */
  const xzMeta = (b) => { try { const CHK = { 0: "none", 1: "CRC32", 4: "CRC64", 10: "SHA-256" }; return { label: "archive metadata", rows: [["Format", "XZ stream"], ["Integrity check", CHK[b[7]] || ("type " + b[7])], ["Note", "contents (often a tar) need an XZ decoder", "is-warn"]], verdict: ["XZ archive", "warn"], findings: [] }; } catch (_) { return null; } };
  const zstdMeta = (b) => { try { const d = b[4], dictFlag = d & 0x3, ssFlag = (d >> 5) & 1, fcsFlag = (d >> 6) & 0x3; const rows = [["Format", "Zstandard frame"]]; let p = 5; if (!ssFlag) p += 1; const dsz = [0, 1, 2, 4][dictFlag]; if (dsz) { let id = 0; for (let i = 0; i < dsz; i++) id += b[p + i] * Math.pow(256, i); p += dsz; if (id) rows.push(["Dictionary ID", String(id)]); } const fsz = [ssFlag ? 1 : 0, 2, 4, 8][fcsFlag]; if (fsz) { let cs = 0; for (let i = 0; i < fsz; i++) cs += b[p + i] * Math.pow(256, i); if (fcsFlag === 1) cs += 256; rows.push(["Uncompressed size", cs >= 1048576 ? (cs / 1048576).toFixed(1) + " MB" : (cs / 1024).toFixed(1) + " KB"]); } rows.push(["Note", "entry list (if archive) needs a Zstd decoder", "is-warn"]); return { label: "archive metadata", rows, verdict: ["Zstandard archive", "warn"], findings: [] }; } catch (_) { return null; } };
  const bz2Meta = (b) => { try { const bs = String.fromCharCode(b[3]); return { label: "archive metadata", rows: [["Format", "BZIP2"], ["Block size", /[1-9]/.test(bs) ? bs + "00 KB" : "?"], ["Note", "contents need a BZIP2 decoder", "is-warn"]], verdict: ["BZIP2 archive", "warn"], findings: [] }; } catch (_) { return null; } };
  const lz4Meta = (b) => { try { const flg = b[4], bd = b[5]; const rows = [["Format", "LZ4 frame"], ["Max block size", ({ 4: "64 KB", 5: "256 KB", 6: "1 MB", 7: "4 MB" }[(bd >> 4) & 0x7]) || "?"]]; let p = 6; if (flg & 0x08) { let cs = 0; for (let i = 0; i < 8; i++) cs += b[p + i] * Math.pow(256, i); rows.push(["Uncompressed size", cs >= 1048576 ? (cs / 1048576).toFixed(1) + " MB" : (cs / 1024).toFixed(1) + " KB"]); } rows.push(["Note", "contents need an LZ4 decoder", "is-warn"]); return { label: "archive metadata", rows, verdict: ["LZ4 archive", "warn"], findings: [] }; } catch (_) { return null; } };
  const sevenZipMeta = (b) => { try { return { label: "archive metadata", rows: [["Format", "7-Zip"], ["Version", `${b[6]}.${String(b[7]).padStart(2, "0")}`], ["Note", "entry list is LZMA-compressed; needs a 7z decoder", "is-warn"]], verdict: ["7-Zip archive", "warn"], findings: [] }; } catch (_) { return null; } };

  const imgMetaRows = (rows, vText, vLevel) => {
    const box = $("upExif"); box.textContent = "";
    for (const [k, v, cls] of rows) if (v != null && v !== "") addRow("upExif", k, String(v), cls || "");
    setVerdict("upExifVerdict", vText, vLevel);
  };

  const renderMeta = (m) => {
    $("upMetaLabel").textContent = "document metadata";
    const box = $("upMeta"); box.textContent = "";
    const row = (k, v, cls) => { if (v != null && v !== "") addRow("upMeta", k, String(v), cls || ""); };
    const named = (v) => v && !META_GENERIC.test(String(v).trim());
    if (m.encrypted) row("Encryption", "Document is encrypted; embedded metadata is not readable", "is-warn");
    row("Author", m.author, named(m.author) ? "is-warn" : "");
    if (m.lastBy && m.lastBy !== m.author) row("Last edited by", m.lastBy, named(m.lastBy) ? "is-warn" : "");
    row("Created", fmtMetaDate(m.created));
    row("Modified", fmtMetaDate(m.modified));
    row("Revision", m.revision);
    row("Edit time", m.editMinutes ? `${m.editMinutes} min` : null);
    row("Application", m.app || m.creator);
    row("App version", m.appVersion);
    row("Producer", m.producer);
    row("Company", m.company);
    row("Manager", m.manager);
    row("Template", m.template);
    row("Title", m.title);
    row("Keywords", m.keywords);
    row("Last printed", fmtMetaDate(m.lastPrinted));
    const person = named(m.author) || named(m.lastBy);
    setVerdict("upMetaVerdict", person ? "Identifies a person" : (m.encrypted ? "Encrypted" : "Metadata present"), person ? "warn" : "good");
    $("upMetaCard").hidden = false;
    reveal($("upMetaCard"));
  };

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
    $("upMeta").textContent = "";
    $("upMetaCard").hidden = true;
    $("upEntLine").setAttribute("d", "");
    $("upEntArea").setAttribute("d", "");
    $("upFindings").textContent = "";
    disposeCloud();
    document.querySelectorAll(".up-canvas-wrap, .up-entropy").forEach((e) => e.classList.remove("is-reveal"));
  };

  let hexState = { bytes: null, shown: 0 };

  const renderHex = (toNew) => {
    if (!hexState.bytes) return;
    const el = $("upHex");
    const prevH = el.scrollHeight;
    el.innerHTML = hexDump(hexState.bytes, hexState.shown);
    const cap = Math.min(hexState.bytes.length, HEX_CAP);
    const btn = $("upHexMore");
    btn.disabled = hexState.shown >= cap;
    btn.textContent = btn.disabled ? "End of view" : "Show more";
    const tag = $("upHexTag");
    if (tag) {
      const f = (n) => fmtBytes(n).replace(/ \(.*\)/, "");
      tag.textContent = `${f(hexState.shown)} of ${f(hexState.bytes.length)}${hexState.bytes.length > HEX_CAP ? " · cap 64 KB" : ""}`;
    }
    if (toNew) el.scrollTop = prevH;
  };

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
      let mismatch = false, gpsFound = false, typedFindings = [];
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
      renderHex(false);

      /* image preview + exif */
      const imgExt = { png: 1, jpg: 1, gif: 1, webp: 1, bmp: 1, ico: 1, svg: 1, avif: 1, heic: 1 };
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

        if (sig.ext === "jpg" || sig.ext === "heic") {
          const exif = sig.ext === "jpg" ? parseJpegExif(buf) : parseHeicExif(buf);
          renderExif(exif);
          if (exif && exif.gps) gpsFound = true;
        } else {
          let r = null;
          if (sig.ext === "png") r = pngMeta(buf);
          else if (sig.ext === "gif") r = gifMeta(buf);
          else if (sig.ext === "svg") r = svgMeta(buf);
          else if (sig.ext === "webp") r = webpMeta(buf);
          else if (sig.ext === "bmp") r = bmpMeta(buf);
          else if (sig.ext === "ico") r = icoMeta(buf);
          else if (sig.ext === "avif") { r = avifMeta(buf); if (r && r.gps) gpsFound = true; }
          if (r) { imgMetaRows(r.rows, r.verdict[0], r.verdict[1]); $("upExifNote").textContent = r.note || ""; if (r.findings) for (const f of r.findings) typedFindings.push(f); }
          else imgMetaRows([["Embedded metadata", "none detected"]], "No metadata", "good");
        }
      }

      /* archive listing */
      if (sig && sig.ext === "zip") {
        const zip = parseZip(buf);
        if (zip && zip.list.length) renderArchive(zip);
      }

      /* document metadata (Office OOXML / PDF) + typed binary/script analysis */
      let docMeta = null;
      const isOffice = sig && sig.ext === "zip" && ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "potx", "xltx", "odt", "ods", "odp"].includes(ext);
      if (isOffice) docMeta = await parseOfficeMeta(buf);
      else if (sig && sig.ext === "pdf") docMeta = parsePdfMeta(buf);
      if (docMeta) { renderMeta(docMeta); log("document metadata extracted", "ok"); }
      else {
        let r = null;
        if (sig && sig.ext === "exe") r = peMeta(buf);
        else if (sig && sig.ext === "elf") r = elfMeta(buf);
        else if (sig && (sig.ext === "macho" || sig.ext === "class")) r = machoMeta(buf);
        else if (sig && (sig.ext === "mp4" || sig.ext === "mov")) { r = mp4Meta(buf); if (r && r.gps) gpsFound = true; }
        else if (sig && sig.ext === "deb") r = await debMeta(buf);
        else if (sig && sig.ext === "rpm") r = rpmMeta(buf);
        else if (sig && sig.ext === "tiff") { r = tiffMeta(buf); if (r && r.gps) gpsFound = true; }
        else if (sig && sig.ext === "icns") r = icnsMeta(buf);
        else if (sig && ["ttf", "otf", "ttc", "woff", "woff2"].includes(sig.ext)) r = fontMeta(buf, sig.ext);
        else if (sig && sig.ext === "wav") r = wavMeta(buf);
        else if (sig && sig.ext === "mp3") r = mp3Meta(buf);
        else if (sig && sig.ext === "flac") r = flacMeta(buf);
        else if (sig && sig.ext === "ogg") r = oggMeta(buf);
        else if (sig && sig.ext === "sqlite") r = sqliteMeta(buf);
        else if (sig && sig.ext === "gz") r = gzipMeta(buf);
        else if (sig && sig.ext === "tar") r = tarMeta(buf);
        else if (sig && sig.ext === "wasm") r = wasmMeta(buf);
        else if (sig && sig.ext === "pcap") r = pcapMeta(buf);
        else if (sig && sig.ext === "pcapng") r = pcapngMeta(buf);
        else if (sig && sig.ext === "iso") r = isoMeta(buf);
        else if (sig && sig.ext === "rar") r = rarMeta(buf);
        else if (sig && sig.ext === "xz") r = xzMeta(buf);
        else if (sig && sig.ext === "zst") r = zstdMeta(buf);
        else if (sig && sig.ext === "bz2") r = bz2Meta(buf);
        else if (sig && sig.ext === "lz4") r = lz4Meta(buf);
        else if (sig && sig.ext === "7z") r = sevenZipMeta(buf);
        else if (buf.length && looksTextual(buf) && SCRIPT_EXT.test(ext)) r = scriptMeta(buf, ext);
        if (r) { showAttrs(r.label, r.rows, r.verdict[0], r.verdict[1]); if (r.findings) for (const f of r.findings) typedFindings.push(f); log(`${r.label} extracted`, "ok"); }
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
      if (docMeta) {
        const persons = [...new Set([docMeta.author, docMeta.lastBy].filter((v) => v && !META_GENERIC.test(String(v).trim())).map((v) => v.trim()))];
        if (persons.length) findings.push(["warn", `Metadata names a person: ${persons.join(", ")}`]);
        const soft = docMeta.app || docMeta.creator || docMeta.producer;
        if (soft) findings.push(["info", `Authoring software: ${soft}`]);
        const pm = /(?:[A-Za-z]:\\[^\s)"'<>]+|\/Users\/[^\s)"'<>]+|\/home\/[^\s)"'<>]+|file:\/\/[^\s)"'<>]+)/.exec([docMeta.title, docMeta.producer, docMeta.creator].filter(Boolean).join("  "));
        if (pm) findings.push(["bad", `Embedded local path: ${pm[0]}`]);
        if (docMeta.encrypted) findings.push(["info", "PDF is encrypted; embedded metadata is not readable"]);
      }
      for (const f of typedFindings) findings.push(f);
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
    renderHex(true);
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
