document.addEventListener("DOMContentLoaded", () => {

    document.querySelectorAll("pre").forEach(pre => {
      const code = pre.querySelector("code");
      if (!code) return;
  
      pre.setAttribute("data-title", "chw㉿world — zsh");
  
      const btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.innerText = "Copy";
  
      btn.onclick = () => {
        navigator.clipboard.writeText(code.innerText);
        btn.innerText = "Copied";
        setTimeout(() => (btn.innerText = "Copy"), 1200);
      };
  
      pre.appendChild(btn);
  
      code.innerHTML = code.innerHTML
        .replace(/^(\$|\#)/gm, `<span class="chw-prompt">$1</span>`);
    });
  
  });
  