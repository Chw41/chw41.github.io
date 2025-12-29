(function () {
    "use strict";

  
    const navbar = document.querySelector(".custom-navbar");
    const progress = document.getElementById("progress-bar");
    const shrinkAt = 30;
  
    function onScroll() {
      const y = window.scrollY || document.documentElement.scrollTop || 0;
  
      if (navbar) {
        navbar.classList.toggle("shrink", y > shrinkAt);
        navbar.classList.toggle("is-scrolled", y > 4);
      }
  
      if (progress) {
        const doc = document.documentElement;
        const scrollTop = doc.scrollTop || document.body.scrollTop;
        const height = doc.scrollHeight - doc.clientHeight;
        const pct = height > 0 ? (scrollTop / height) * 100 : 0;
        progress.style.width = pct + "%";
      }
    }
  
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();

    const terminal = document.getElementById("terminal");
    const cursor = document.querySelector(".cursor");
    if (!terminal || !cursor) return;
  
    const PROMPT = "chw㉿world:~$ ";
    const TYPE_SPEED = 55;
    const LINE_PAUSE = 800;
  
    const script = [
      { cmd: "id", out: "uid=0(root) gid=0(root) groups=0(root)" },
      {
        cmd: "./skill",
        out: "CTF Player · Web Security · Red Team",
        exec: true,
      },
      {
        cmd: "./source",
        out: "Research notes, Writeups, and Experiments.",
        exec: true,
      },
    ];
  
    function sleep(ms) {
      return new Promise((r) => setTimeout(r, ms));
    }
  
    function printPrompt() {
      terminal.appendChild(document.createTextNode(PROMPT));
    }
  
    async function typeCommand(text, className = "") {
      const span = document.createElement("span");
      if (className) span.className = className;
      terminal.appendChild(span);
  
      for (let i = 0; i < text.length; i++) {
        span.textContent += text[i];
        await sleep(TYPE_SPEED);
      }
    }
  
    function newline(count = 1) {
      terminal.appendChild(document.createTextNode("\n".repeat(count)));
    }
  
    async function runTerminal() {
        terminal.textContent = "";
      
        for (let i = 0; i < script.length; i++) {
          const entry = script[i];

          printPrompt();
      
          await typeCommand(entry.cmd, entry.exec ? "exec" : "");
          await sleep(LINE_PAUSE);
      
          newline();
      
          terminal.appendChild(document.createTextNode(entry.out));
      
          newline(2); 
          await sleep(LINE_PAUSE);
        }

        printPrompt();
        terminal.appendChild(cursor);
      }
      
      
  
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", runTerminal);
    } else {
      runTerminal();
    }
  
    document.querySelectorAll(".post-cover").forEach((img) => {
      img.addEventListener("error", () => {
        const wrap = img.closest(".post-cover-wrap");
        if (wrap) wrap.classList.add("no-cover");
      });
    });
  })();
  