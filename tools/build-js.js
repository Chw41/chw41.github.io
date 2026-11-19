"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const esbuild = require("esbuild");
const { JSFuck } = require("jsfuck");
const { MAX_TERMS, balance, findLongChains } = require("./jsfuck-balance.js");

const ROOT = path.resolve(__dirname, "..");
const SRC_DIR = path.join(ROOT, "_js-src");
const OUT_DIR = path.join(ROOT, "static", "js");

const num = k => (k === 0 ? "+[]" : k === 1 ? "+!+[]" : Array(k).fill("!+[]").join("+"));

const TERM = {
  a: "(![]+[])[+!+[]]", d: "([][[]]+[])[!+[]+!+[]]", e: "(!![]+[])[!+[]+!+[]+!+[]]", f: "(![]+[])[+[]]",
  i: "([![]]+[][[]])[+!+[]+[+[]]]", l: "(![]+[])[!+[]+!+[]]", n: "([][[]]+[])[+!+[]]", r: "(!![]+[])[+!+[]]",
  s: "(![]+[])[!+[]+!+[]+!+[]]", t: "(!![]+[])[+[]]", u: "([][[]]+[])[+[]]", N: "(+[![]]+[])[+[]]",
};
for (let d = 0; d <= 9; d++) TERM[d] = "[" + num(d) + "]";
for (const [c, t] of Object.entries(TERM)) if (String(eval(t)) !== c) throw new Error(`invalid TERM entry for "${c}"`);

const E = s => "(" + JSFuck.encode(s) + ")";
const term = c => TERM[c] || E(c);
const chain = terms => "(" + balance(terms) + "+[])";
const FN = `[][${E("filter")}][${E("constructor")}]`;
const EVAL = `${FN}(${E("return eval")})()`;

const KEEP = /^[0-9adefilnrsuN]$/;

function octalEscape(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i], code = text.charCodeAt(i);
    if (KEEP.test(c)) { out += c; continue; }
    if (code > 255) { out += "tu" + code.toString(16).padStart(4, "0"); continue; }
    let o = code.toString(8);
    if (o.length < 3 && /[0-7]/.test(text[i + 1] || "")) o = o.padStart(3, "0");
    out += "t" + o;
  }
  return out;
}

function loader(text) {
  const terms = [...octalEscape(text)].map(term);
  return `${FN}(${E('return"')}+${chain(terms)}[${E("split")}](${E("t")})[${E("join")}](${E("\\")})+${E('"')})()`;
}

const encodeOctal = src => `${EVAL}(${loader(src)})`;

const TOKENS = Object.keys(TERM).sort((a, b) => TERM[a].length - TERM[b].length || (a < b ? -1 : 1));
const pairCost = w => TERM[w[0]].length + TERM[w[1]].length;
const PAIRS = TOKENS.flatMap(x => TOKENS.map(y => x + y)).sort((p, q) => pairCost(p) - pairCost(q) || (p < q ? -1 : 1));

function encodePrefix(src) {
  const freq = new Map();
  for (let i = 0; i < src.length; i++) freq.set(src[i], (freq.get(src[i]) || 0) + 1);
  const chars = [...freq.keys()].sort((a, b) => freq.get(b) - freq.get(a) || (a < b ? -1 : 1));
  if (chars.length > PAIRS.length) return null;
  const code = new Map(chars.map((c, k) => [c, PAIRS[k]]));
  const tokens = [];
  for (let i = 0; i < src.length; i++) { const w = code.get(src[i]); tokens.push(TERM[w[0]], TERM[w[1]]); }
  const K = JSON.stringify(chars.join("")), P = JSON.stringify(PAIRS.slice(0, chars.length).join(""));
  const decoder = `return function(T){var K=${K},P=${P},M={},o=[],i;` +
    `for(i=0;i<K.length;i++)M[P.substr(2*i,2)]=K.charAt(i);` +
    `for(i=0;i<T.length;i+=2)o.push(M[T.substr(i,2)]);return o.join("")}`;
  return `${EVAL}(${FN}(${loader(decoder)})()(${chain(tokens)}))`;
}

function decode(code) {
  let got = null;
  const ctx = vm.createContext({ __got: s => { got = s; } });
  vm.runInContext(`(() => {
    const RF = Function;
    Object.defineProperty(RF.prototype, "constructor", { writable: true, configurable: true, value: function (...a) {
      if (String(a[a.length - 1]) === "return eval") return () => s => { __got(String(s)); };
      return RF(...a);
    } });
  })();`, ctx);
  vm.runInContext(code, ctx, { timeout: 120000 });
  return got;
}

function build(name) {
  const srcFile = path.join(SRC_DIR, name);
  const outFile = path.join(OUT_DIR, name);
  const src = fs.readFileSync(srcFile, "utf8");
  const min = esbuild.transformSync(src, { loader: "js", minify: true, charset: "utf8", legalComments: "none" }).code;

  const candidates = [encodeOctal(min), encodePrefix(min)].filter(Boolean);
  const out = candidates.reduce((a, b) => (b.length < a.length ? b : a));

  if (!/^[\[\]()!+]+$/.test(out)) throw new Error(`${name}: output contains characters outside the JSFuck alphabet`);
  if (findLongChains(out).length) throw new Error(`${name}: output contains a + chain longer than ${MAX_TERMS} terms`);
  if (decode(out) !== min) throw new Error(`${name}: decoded output does not match the minified source; file not written`);

  const before = fs.existsSync(outFile) ? fs.statSync(outFile).size : 0;
  fs.writeFileSync(outFile, out);
  const kind = out === candidates[0] ? "octal" : "prefix";
  console.log(`${name.padEnd(20)} ${String(src.length).padStart(7)} -> min ${String(min.length).padStart(7)} -> ${String(out.length).padStart(8)} bytes  [${kind}]` +
    (before ? `  (previously ${before})` : ""));
}

function main() {
  const args = process.argv.slice(2).map(a => path.basename(a));
  const names = args.length ? args : fs.readdirSync(SRC_DIR).filter(f => f.endsWith(".js")).sort();
  let failed = 0;
  for (const name of names) {
    try { build(name); } catch (e) { console.error(`FAIL ${e.message}`); failed++; }
  }
  process.exit(failed ? 1 : 0);
}

main();
