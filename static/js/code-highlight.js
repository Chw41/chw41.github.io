/* Client-side highlighting for languages Chroma does not support.
   Token colors: /css/code-theme.css (.hl-*) */
(() => {
  "use strict";

  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
  const esc = s => s.replace(/[&<>"]/g, c => ESC[c]);
  const tok = (cls, s) => (s ? `<span class="hl-${cls}">${esc(s)}</span>` : "");
  const perLine = fn => text => text.split("\n").map(fn).join("\n");

  // rules: [[source, className | (match) => html]]; earlier rules win. Use non-capturing groups only.
  function lexer(rules) {
    const src = rules.map(([s]) => `(${s})`).join("|");
    return text => {
      const re = new RegExp(src, "g");
      let out = "", last = 0, m;
      while ((m = re.exec(text))) {
        if (m[0] === "") { re.lastIndex++; continue; }
        const i = m.slice(1).findIndex(g => g !== undefined);
        const how = rules[i][1];
        out += esc(text.slice(last, m.index));
        out += typeof how === "function" ? how(m[0]) : tok(how, m[0]);
        last = m.index + m[0].length;
      }
      return out + esc(text.slice(last));
    };
  }

  /* ---- x86 ---- */
  const REG = String.raw`(?:[re]?(?:ax|bx|cx|dx|si|di|sp|bp|ip)|[abcd][lh]|r(?:[89]|1[0-5])[dwb]?|[cdefgs]s|efl|iopl|[xy]mm\d{1,2})`;

  const MNEM = new RegExp("^(?:" + [
    "mov(?:s[bwdq]?|zx|sx|sxd|ap[sd]|up[sd]|dq[au]|[dq])?", "push(?:ad?|fd?|fq)?", "pop(?:ad?|fd?|fq)?",
    "call", "ret[fn]?", "jmp", "j(?:n?[abceglopsz]|n?[abgl]e|p[eo]|[er]?cxz)", "loop(?:n?[ez])?",
    "lea", "xor", "add", "adc", "sub", "sbb", "inc", "dec", "cmp", "cmps[bwdq]?", "test", "and", "or", "not", "neg", "nop",
    "int[3o]?", "sysenter", "syscall", "sysexit", "leave", "enter", "i?mul", "i?div", "sh[lr]d?", "sa[lr]", "ro[lr]", "rc[lr]",
    "xchg", "xadd", "cmpxchg(?:8b|16b)?", "cdqe?", "cwde?", "cbw", "cqo", "lods[bwdq]?", "stos[bwdq]?", "scas[bwdq]?",
    "set(?:n?[abceglopsz]|n?[abgl]e)", "cmov(?:n?[abceglopsz]|n?[abgl]e)", "bt[crs]?", "bs[fr]", "bswap", "cpuid", "rdtsc",
    "hlt", "cl[cdi]", "st[cdi]", "[ls]ahf", "f(?:ld[a-z0-9]*|i?stp?|n?stenv|n?init|xch|add|sub|mul|div|nop|wait|i?ld)",
    "in[sbwd]*", "out[sbwd]*", "iret[dq]?", "da[as]", "aa[adms]", "arpl", "bound", "ud2", "wait", "xlatb?",
    "endbr(?:32|64)", "p(?:xor|or|andn?|add[bwdq]|sub[bwdq]|cmpeq[bwd]|shufd)", "\\?\\?\\?",
  ].join("|") + ")$");
  const PREFIX = /^(?:rep(?:n?[ez])?|lock)$/;

  /* ---- WinDbg ---- */
  const DBG_RULES = [
    [String.raw`"[^"]*"|'[^'\n]*'`, "str"],
    [String.raw`@?\$[A-Za-z_]\w*|@?\b${REG}\b`, "reg"],
    [String.raw`\b[A-Za-z_][\w.]*!(?:\x60[^'\s]*'|[\w:$@?<>~]+)+(?:\+0x[0-9a-fA-F]+)?|\b[A-Za-z_][\w.]*\+0x[0-9a-fA-F]+\b`, "sym"],
    [String.raw`\b(?:byte|word|dword|qword|xmmword|ymmword|tbyte|fword)\s+ptr\b`, "kw"],
    [String.raw`\b0x[0-9a-fA-F]+\b|\b0n\d+\b|\b[0-9a-fA-F]{8}\x60[0-9a-fA-F]{8}\b|\b\d[0-9a-fA-F]*h\b|\b(?=[0-9a-f]*\d)[0-9a-f]+\b|\b[0-9a-f]{8}\b|\bL(?=[0-9a-fx]*\d)(?:0x)?[0-9a-f]+\b|\b0y[01]+\b|\(null\)`, "num"],
  ];
  const dbgInline = lexer(DBG_RULES);
  const dtRest = lexer([
    [String.raw`\b(?:Ptr32|Ptr64|U?[Ii]nt[1248]B|UChar|Char|Wchar|Void|Float|Double|Bitfield|Pos)\b|\b_[A-Z][A-Z0-9_]*\b`, "type"],
    ...DBG_RULES,
  ]);

  const DBG = {
    prompt: /^(\s*)((?:\d+:\s?)?kd>|\d*:\d{3}(?::x86)?>)(\s*)(\S*)(.*)$/,
    except: /^\([0-9a-f]+\.[0-9a-f]+\):|^(?:Access violation|Break instruction exception)/i,
    event:  /^Breakpoint \d+ hit/,
    note:   /^(?:\.*\*{3}|\*{5,}|First chance exceptions|This exception may be expected|ModLoad:|Unable to |Press ctrl-c|Run !sym|You can troubleshoot|You should also verify|Reloading current modules|Browse full module list|Module name\s+Error|\s*#\s+Child|start\s+end\s+module name|\s*\.{3,}\s*$)/,
    label:  /^(\s*)(\S*(?:!|\+0x)\S*?)(:)(\s*)$/,
    regs:   /^(.*?\biopl=\S+)(\s+)((?:(?:nv|ov|up|dn|ei|di|pl|ng|nz|zr|na|ac|po|pe|nc|cy)\b\s*)+)$/,
    dt:     /^(\s+)(\+0x[0-9a-f]+)(\s+)([\w[\]]+)(\s*:\s?)(.*)$/,
    addr:   /^(\s*)([0-9a-f]{8}(?:`[0-9a-f]{8})?)(:?)( +)(.*)$/,
    meta:   /^(\s*)(\.[a-z]\w*)(.*)$/,
    bare:   /^(\s*)(d[abcdquwW]|dd[ps]|dp[sp]?|dq[s]?|d[st]|dx|b[pumlcde]|ba|e[bdqwau]|u[bf]?|k[bpvn]?|lm|ln|s|!\w+|\?)(\s+\S.*)$/,
  };
  function dbgAfterAddr(sep, rest) {
    if (sep.length === 1) {
      const d = rest.match(/^([0-9a-f]{2,}|\?\?)(\s+)(\S+)(\s*)(.*)$/);
      if (d) {
        let [, bytes, gap1, mn, gap2, ops] = d, pre = "";
        if (PREFIX.test(mn)) {
          const w = ops.match(/^(\S+)(\s*)(.*)$/);
          if (w) { pre = mn + gap2; [, mn, gap2, ops] = w; }
        }
        if (MNEM.test(mn)) return tok("bytes", bytes) + gap1 + tok("op", pre + mn) + gap2 + dbgInline(ops);
      }
      return dbgInline(rest);
    }
    const dump = rest.match(/^((?:[0-9a-f?`]+[ -])*[0-9a-f?`]+)(?=\s{2}|\s*$)(\s*)(.*)$/);
    if (dump) {
      const data = dump[1].split(/([ -])/).map(p =>
        /^[ -]$/.test(p) ? p : tok(/^\?+$/.test(p) ? "dim" : "num", p)).join("");
      return data + dump[2] + tok("dim", dump[3]);
    }
    return dbgInline(rest);
  }

  function dbgLine(line) {
    let m;
    if ((m = line.match(DBG.prompt))) return m[1] + tok("prompt", m[2]) + m[3] + tok("cmd", m[4]) + dbgInline(m[5]);
    if (DBG.except.test(line)) return tok("err", line);
    if (DBG.event.test(line)) return tok("event", line);
    if (DBG.note.test(line)) return tok("note", line);
    if ((m = line.match(DBG.label))) return m[1] + tok("label", m[2]) + tok("dim", m[3]) + m[4];
    if ((m = line.match(DBG.regs))) return dbgInline(m[1]) + m[2] + tok("dim", m[3]);
    if ((m = line.match(DBG.dt))) return m[1] + tok("num", m[2]) + m[3] + tok("field", m[4]) + esc(m[5]) + dtRest(m[6]);
    if ((m = line.match(DBG.addr))) {
      return m[1] + tok("addr", m[2]) + tok("dim", m[3]) + m[4] + (m[3] ? dbgInline(m[5]) : dbgAfterAddr(m[4], m[5]));
    }
    if ((m = line.match(DBG.meta))) return m[1] + tok("cmd", m[2]) + dbgInline(m[3]);
    if ((m = line.match(DBG.bare))) return m[1] + tok("cmd", m[2]) + dbgInline(m[3]);
    return dbgInline(line);
  }

  /* ---- Shell ---- */
  const KEEP_CMD = new Set(["sudo", "time", "nohup", "exec", "env", "watch", "xargs", "proxychains", "proxychains4", "runas"]);
  const KALI_PROMPT = /^(\s*)(┌──\()([^)]*)(\)-\[)([^\]]*)(\].*)$/;
  const MIMI_PROMPT = /^(\s*)(mimikatz\s*#)(\s*)(\S*)(.*)$/;
  const SHELL_PROMPT = new RegExp("^(\\s*)(" + [
    "└─[$#]",
    "\\*Evil-WinRM\\* PS [^>]*>",
    "PS [A-Za-z]:\\\\[^>]*>",
    "[A-Za-z]:\\\\[^>]*>(?=\\s*\\S)",
    "[\\w.-]+@[\\w.-]+:[^$#\\s]*[$#](?=\\s|$)",
    "[\\w.-]+@[\\w.-]+ \\S+ [%$#](?=\\s)",
    "msf\\d?(?: \\w+\\([^)]*\\))? >",
    "meterpreter >",
    "\\$(?=\\s)",
    "[\\w-]+=[#>](?=\\s)",
    "SQL>", "mysql>", "MariaDB \\[[^\\]]*\\]>", "sqlite>", "rpcclient \\$>", "smb: [^>]*>", "ftp>",
    "\\(gdb\\)", "\\(Pdb\\)", "gef➤", "pwndbg>", ">>>",
  ].join("|") + ")(\\s*)(.*)$");
  const CONTINUES = /[\\`^]\s*$/;

  function shellCmd(text, cmdStart = true) {
    let code = text, comment = "", q = null;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; continue; }
      if ((i === 0 || /\s/.test(text[i - 1])) && (c === "#" || text.startsWith("//", i))) {
        code = text.slice(0, i);
        comment = text.slice(i);
        break;
      }
    }

    let cmdPos = cmdStart;
    const lex = lexer([
      [String.raw`"(?:[^"\\]|\\.)*"|'[^']*'`, s => { cmdPos = false; return tok("str", s); }],
      [String.raw`\|\||&&|[|;]|\d?>>?(?:&\d)?|<(?=\s)`, s => { if (/^(?:\|\|?|&&|;)$/.test(s)) cmdPos = true; return tok("opr", s); }],
      [String.raw`\$\{?\w+\}?|%\w+%|\{[\w .-]+\}|<[A-Za-z][\w -]*>`, s => { if (s[0] === "$") cmdPos = false; return tok("var", s); }],
      [String.raw`(?<=^|\s)--?[A-Za-z][\w.-]*=?`, s => { cmdPos = false; return tok("flag", s); }],
      [String.raw`\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+`, s => { cmdPos = false; return tok("host", s); }],
      [String.raw`(?<=^|\s)[A-Za-z_][\w.-]*(?==)`, s => (cmdPos ? tok("var", s) : tok("flag", s))],
      [String.raw`[^\s"'|;&<>(){}\[\]=,$]+`, s => {
        if (cmdPos) { cmdPos = KEEP_CMD.has(s); return tok("cmd", s); }
        if (/^\d+(?:\.\d+){0,3}(?:\/\d{1,2})?(?::\d+)?$/.test(s)) return tok("num", s);
        if (/^[\w.-]+@[\w.-]+$/.test(s)) return tok("host", s);
        return esc(s);
      }],
    ]);
    return lex(code) + tok("comment", comment);
  }

  function asmLine(line) {
    const m = line.match(/^(\s*)(\S+)(.*?)(\s*;.*)?$/);
    return m[1] + tok("op", m[2]) + dbgInline(m[3]) + tok("comment", m[4] || "");
  }

  function commandLine(line) {
    if (/^\s*(?:\/\/|#)/.test(line)) return tok("comment", line);
    const first = line.trim().split(/\s+/)[0];
    if (MNEM.test(first)) return asmLine(line);
    if (/^[A-Z][a-z]+$/.test(first) && /:(?:\s|$)/.test(line)) return esc(line);
    return shellCmd(line);
  }

  const STATUS = { "+": "ok", "-": "bad", "!": "warn", "*": "op" };

  const outputLine = lexer([[String.raw`(?<=^|\s)\[[+\-!*]\](?=\s|$)`, s => tok(STATUS[s[1]], s)]]);

  // Net count of unclosed brackets outside quotes.
  function openDepth(s) {
    let d = 0, q = null;
    for (const c of s) {
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if ("{([".includes(c)) d++;
      else if ("})]".includes(c)) d--;
    }
    return d;
  }

  // Lines with a prompt are input; in a session, every other line is program output
  // unless it continues a multi-line command.
  function commandBlock(text) {
    const lines = text.split("\n");
    const isPrompt = l => KALI_PROMPT.test(l) || MIMI_PROMPT.test(l) || SHELL_PROMPT.test(l);
    const session = lines.some(isPrompt);
    let depth = 0, cont = false, prev = "";
    const track = cmd => {
      depth = Math.max(0, depth + openDepth(cmd));
      cont = depth > 0 || CONTINUES.test(cmd) || /\|\s*$/.test(cmd);
      prev = cmd;
    };
    return lines.map(line => {
      let m;
      if (cont && !isPrompt(line)) {
        const args = /[\\`^,(|]\s*$/.test(prev) && !/\|\s*$/.test(prev);
        track(line);
        return shellCmd(line, !args);
      }
      depth = 0; cont = false;
      if (!line.trim()) return esc(line);
      if ((m = line.match(KALI_PROMPT))) {
        return m[1] + tok("prompt", m[2]) + tok("host", m[3]) + tok("prompt", m[4]) + tok("field", m[5]) + tok("prompt", m[6]);
      }
      if ((m = line.match(MIMI_PROMPT))) return m[1] + tok("prompt", m[2]) + m[3] + tok("cmd", m[4]) + mimiArgs(m[5]);
      if ((m = line.match(SHELL_PROMPT))) {
        track(m[4]);
        return m[1] + tok("prompt", m[2]) + m[3] + shellCmd(m[4]);
      }
      if (session) return outputLine(line);
      track(line);
      return commandLine(line);
    }).join("\n");
  }

  /* ---- URL ---- */
  function pct(s, cls) {
    return s.split(/(%[0-9A-Fa-f]{2})/).map((p, i) => (i % 2 ? tok("esc", p) : cls ? tok(cls, p) : esc(p))).join("");
  }

  function query(q) {
    return q.split(/(&)/).map(p => {
      if (p === "&") return tok("opr", p);
      const i = p.indexOf("=");
      if (i < 0) return pct(p, null);
      return tok("flag", p.slice(0, i)) + tok("opr", "=") + pct(p.slice(i + 1), "str");
    }).join("");
  }

  function urlLine(line) {
    const m = line.match(/^(\s*)([a-z][\w+.-]*)(:\/\/)([^/?#\s:]+)(:\d+)?([^?#]*)(\?[^#]*)?(#.*)?$/i);
    if (!m) return /^[/?]/.test(line) ? reqTarget(line) : /^[^\s=]+=/.test(line) ? query(line) : esc(line);
    return m[1] + tok("kw", m[2]) + tok("dim", m[3]) + tok("host", m[4])
      + (m[5] ? tok("dim", ":") + tok("num", m[5].slice(1)) : "")
      + pct(m[6] || "", null)
      + (m[7] ? tok("opr", "?") + query(m[7].slice(1)) : "")
      + tok("dim", m[8] || "");
  }

  /* ---- HTTP ---- */
  const jsonLine = lexer([
    [String.raw`"(?:[^"\\]|\\.)*"(?=\s*:)`, "kw"],
    [String.raw`"(?:[^"\\]|\\.)*"`, "str"],
    [String.raw`\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b`, "num"],
  ]);

  function reqTarget(t) {
    if (/^[a-z]+:\/\//i.test(t)) return urlLine(t);
    const i = t.indexOf("?");
    return i < 0 ? pct(t, null) : pct(t.slice(0, i), null) + tok("opr", "?") + query(t.slice(i + 1));
  }
  function headerValue(name, v) {
    const n = name.toLowerCase();
    if (/^(?:host|origin|referer|location)$/.test(n)) return /:\/\//.test(v) ? urlLine(v) : tok("host", v);
    if (/^\d+\s*$/.test(v)) return tok("num", v);
    return lexer([
      [String.raw`[\w.-]+(?==)`, "flag"],
      [String.raw`=`, "opr"],
      [String.raw`(?<==)(?:"[^"]*"|[^;,\s]+)`, "str"],
    ])(v);
  }

  const HEADER = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)(:)(\s*)(.*)$/;

  function httpBlock(text) {
    let state = "start", prev = "", body = "", inPart = false;
    return text.split("\n").map(line => {
      let m;
      if (state === "start") {
        if (!line.trim()) return esc(line);
        if ((m = line.match(/^(\s*)([A-Z]+)(\s+)(\S+)(?:(\s+)(HTTP\/[\d.]+))?(\s*)$/))) {
          state = "head"; prev = "request";
          return m[1] + tok("method", m[2]) + m[3] + reqTarget(m[4]) + (m[5] || "") + tok("dim", m[6] || "") + m[7];
        }
        if ((m = line.match(/^(\s*)(HTTP\/[\d.]+)(\s+)(\d{3})(.*)$/))) {
          state = "head"; prev = "status";
          const c = m[4][0];
          return m[1] + tok("dim", m[2]) + m[3] + tok(c === "2" ? "ok" : c === "3" ? "warn" : "45".includes(c) ? "bad" : "num", m[4]) + esc(m[5]);
        }
        state = "head";
      }

      if (state === "head") {
        if (!line.trim()) { state = "body"; return esc(line); }
        if ((m = line.match(HEADER))) {
          prev = m[1];
          return tok("field", m[1]) + tok("dim", m[2]) + m[3] + headerValue(m[1], m[4]);
        }
        if (prev === "request") return pct(line, "str");
        if (/^[\w*-]+\s*$/.test(line)) return tok("field", line);
        return esc(line);
      }

      if (!body && line.trim()) body = /^\s*[[{]/.test(line) ? "json" : "text";
      if (/^--\S/.test(line)) { inPart = true; return tok("dim", line); }
      if (inPart) {
        if (!line.trim()) { inPart = false; return esc(line); }
        if ((m = line.match(HEADER))) return tok("field", m[1]) + tok("dim", m[2]) + m[3] + headerValue(m[1], m[4]);
      }
      if (body === "json") return jsonLine(line);
      if (/^[^\s=&]+=\S*(?:&|$)/.test(line)) return query(line);
      return esc(line);
    }).join("\n");
  }

  /* ---- Mimikatz ---- */
  const mimiArgs = lexer([
    [String.raw`"[^"]*"|'[^']*'`, "str"],
    [String.raw`(?<=^|\s)\/[\w-]+`, "flag"],
    [String.raw`(?<=^|\s)(?:[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|\d+(?:[./:]\d+)*)(?=\s|$)`, "num"],
  ]);

  function mimiKV(s) {
    const m = s.match(/^(\s*)([A-Za-z][\w ()-]*?)(\s*:\s*)(.*)$/);
    return m ? m[1] + tok("field", m[2]) + esc(m[3]) + mimiArgs(m[4]) : mimiArgs(s);
  }

  function mimikatzLine(line) {
    let m;
    if ((m = line.match(/^(\s*)(mimikatz\s*#)(\s*)(\S*)(.*)$/))) return m[1] + tok("prompt", m[2]) + m[3] + tok("cmd", m[4]) + mimiArgs(m[5]);
    if ((m = line.match(/^(\s*)([>*])(\s*)(.*)$/))) return m[1] + tok("dim", m[2]) + m[3] + mimiKV(m[4]);
    return mimiKV(line);
  }

  /* ---- iCalendar ---- */
  const icsValue = lexer([[String.raw`\{[A-Za-z_]+\}`, "var"]]);

  function icsLine(line) {
    const m = line.match(/^([A-Za-z][\w-]*)((?:;[^:]*)?)(:)(.*)$/);
    if (!m) return icsValue(line);
    const params = m[2].split(/(;)/).map(p => {
      if (!p) return "";
      if (p === ";") return tok("dim", p);
      const i = p.indexOf("=");
      return i < 0 ? esc(p) : tok("flag", p.slice(0, i)) + tok("opr", "=") + tok("str", p.slice(i + 1));
    }).join("");
    const name = m[1].toUpperCase();
    if (name === "BEGIN" || name === "END") return tok("kw", m[1]) + params + tok("dim", ":") + tok("type", m[4]);
    const v = m[4];
    const val = /^\d{8}(?:T\d{6}Z?)?\s*$/.test(v) ? tok("num", v)
      : /^(?:mailto|https?):/i.test(v) ? tok("host", v)
      : icsValue(v);
    return tok("field", m[1]) + params + tok("dim", ":") + val;
  }

  /* ---- Hex ---- */
  const hexLine = lexer([
    [String.raw`\b0x[0-9a-fA-F]+\b|\\x[0-9a-fA-F]{2}|\b[0-9a-fA-F]{2}\b`, "num"],
    [String.raw`\.{3}`, "dim"],
  ]);

  const LANGS = {
    dbg: perLine(dbgLine),
    command: commandBlock,
    mimikatz: perLine(mimikatzLine),
    url: perLine(urlLine),
    ics: perLine(icsLine),
    hex: perLine(hexLine),
    http: httpBlock,
  };

  document.querySelectorAll(".chw-article pre > code[data-lang]").forEach(code => {
    const fn = LANGS[code.dataset.lang];
    if (!fn || code.dataset.hl) return;
    try {
      code.innerHTML = fn(code.textContent);
      code.dataset.hl = code.dataset.lang;
    } catch (e) {
      console.warn("[code-highlight]", e);
    }
  });
})();
