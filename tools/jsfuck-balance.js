"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const MAX_TERMS = 256;
const JSFUCK_RE = /^[\[\]()!+\s]*$/;
const LPAREN = 40, RPAREN = 41, PLUS = 43, LBRACKET = 91, RBRACKET = 93, SPACE = 32;

function findLongChains(s) {
  const chains = [];
  const stack = [{ open: -1, plus: [] }];
  let prev = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === LPAREN || c === LBRACKET) stack.push({ open: i, plus: [] });
    else if (c === RPAREN || c === RBRACKET) {
      const frame = stack.pop();
      if (stack.length === 0) throw new Error(`unbalanced brackets at offset ${i}`);
      if (frame.plus.length >= MAX_TERMS) chains.push({ start: frame.open + 1, end: i, plus: frame.plus });
    } else if (c === PLUS && (prev === ")" || prev === "]")) stack[stack.length - 1].plus.push(i);
    if (c > SPACE) prev = s[i];
  }
  if (stack.length !== 1) throw new Error("unbalanced brackets at end of input");
  const top = stack[0];
  if (top.plus.length >= MAX_TERMS) chains.push({ start: 0, end: s.length, plus: top.plus });
  return chains.sort((a, b) => a.start - b.start);
}

function balance(terms) {
  let level = terms;
  while (level.length > MAX_TERMS) {
    const next = [];
    for (let i = 0; i < level.length; i += MAX_TERMS) {
      const group = level.slice(i, i + MAX_TERMS);
      next.push(group.length === 1 ? group[0] : "(" + group.join("+") + ")");
    }
    level = next;
  }
  return level.join("+");
}

function rewrite(s, start, end, chains) {
  let out = "";
  let pos = start;
  for (const ch of chains) {
    if (ch.start < pos || ch.end > end) continue;
    const inner = chains.filter(c => c !== ch && c.start >= ch.start && c.end <= ch.end);
    const cuts = [ch.start, ...ch.plus.map(p => p + 1)];
    const terms = cuts.map((c, i) => rewrite(s, c, i + 1 < cuts.length ? ch.plus[i] : ch.end, inner));
    out += s.slice(pos, ch.start) + balance(terms);
    pos = ch.end;
  }
  return out + s.slice(pos, end);
}

function decodeTrace(code) {
  const log = [];
  const ctx = vm.createContext({ __log: x => log.push(x) });
  vm.runInContext(`(() => {
    const RF = Function;
    const fake = function (...args) {
      const body = String(args[args.length - 1]);
      __log("Function:" + args.map(String).join("\\u0000"));
      if (body === "return eval") return () => src => { __log("eval:" + String(src)); };
      if (body.length > 1000) return () => () => {};
      return RF(...args);
    };
    Object.defineProperty(RF.prototype, "constructor", { value: fake, writable: true, configurable: true });
  })();`, ctx);
  vm.runInContext(code, ctx, { timeout: 120000 });
  return log;
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const files = args.filter(a => a !== "--check");
  if (!files.length) {
    console.error("usage: node tools/jsfuck-balance.js [--check] <file.js>...");
    process.exit(2);
  }
  let bad = 0;
  for (const file of files) {
    const name = path.relative(process.cwd(), file);
    const src = fs.readFileSync(file, "utf8").trim();
    if (!JSFUCK_RE.test(src)) { console.log(`skip  ${name} (not JSFuck)`); continue; }
    const chains = findLongChains(src);
    const longest = chains.reduce((m, c) => Math.max(m, c.plus.length + 1), 0);
    if (!chains.length) { console.log(`ok    ${name}`); continue; }
    if (check) { console.log(`FAIL  ${name}: + chain of ${longest} terms exceeds the JavaScriptCore limit`); bad++; continue; }

    const out = rewrite(src, 0, src.length, chains);
    const before = decodeTrace(src).join("\n");
    const after = decodeTrace(out).join("\n");
    if (before !== after || !before.includes("eval:") && !before.includes("Function:")) {
      console.log(`FAIL  ${name}: decoded output differs after rewriting; file not modified`);
      bad++;
      continue;
    }
    fs.writeFileSync(file, out);
    console.log(`fixed ${name}: longest + chain ${longest} -> <= ${MAX_TERMS} terms (${src.length} -> ${out.length} bytes, decoded output identical)`);
  }
  process.exit(bad ? 1 : 0);
}

module.exports = { MAX_TERMS, balance, findLongChains };
if (require.main === module) main();
