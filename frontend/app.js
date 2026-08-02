/* OpenGuardian 前端逻辑 */
(function () {
  "use strict";

  const chatEl = document.getElementById("chat");
  const inputEl = document.getElementById("input");
  const sendBtn = document.getElementById("send");
  const statusText = document.getElementById("status-text");
  const statusDot = document.querySelector(".dot");
  const modal = document.getElementById("confirm-modal");
  const confirmText = document.getElementById("confirm-text");
  const confirmOk = document.getElementById("confirm-ok");
  const confirmCancel = document.getElementById("confirm-cancel");

  let sessionId = "";
  let pendingExecute = null;

  const LEVEL_CLASS = { critical: "critical", high: "high", medium: "medium", low: "low" };
  const LEVEL_ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" };

  /* ---- 工具 ---- */
  function addMsg(role, html) {
    const div = document.createElement("div");
    div.className = "msg " + role;
    const avatar = role === "user" ? "🧑" : "🛡️";
    div.innerHTML = `<div class="avatar">${avatar}</div><div class="bubble">${html}</div>`;
    chatEl.appendChild(div);
    chatEl.scrollTop = chatEl.scrollHeight;
    return div;
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function addTyping() {
    const div = document.createElement("div");
    div.className = "msg bot typing";
    div.innerHTML = `<div class="avatar">🛡️</div><div class="bubble">正在思考</div>`;
    chatEl.appendChild(div);
    chatEl.scrollTop = chatEl.scrollHeight;
    return div;
  }

  function renderRisks(risks) {
    if (!risks || !risks.length) return "";
    let html = "";
    for (const r of risks) {
      const cls = LEVEL_CLASS[r.level] || "low";
      const icon = LEVEL_ICON[r.level] || "⚪";
      html += `
        <div class="risk-card ${cls}">
          <div class="r-name">${icon} ${escapeHtml(r.name)}</div>
          <div class="r-detail">${escapeHtml(r.detail)}</div>
          ${r.suggestion ? `<div class="r-suggest">💡 ${escapeHtml(r.suggestion)}</div>` : ""}
          ${r.pid ? `<button class="btn-term" data-pid="${r.pid}" data-name="${escapeHtml(r.name)}">🛑 结束该进程（PID ${r.pid}）</button>` : ""}
        </div>`;
    }
    return html;
  }

  /* ---- 事件绑定 ---- */
  chatEl.addEventListener("click", function (e) {
    const btn = e.target.closest(".btn-term");
    if (!btn) return;
    const pid = parseInt(btn.dataset.pid, 10);
    const name = btn.dataset.name || `PID ${pid}`;
    pendingExecute = { pid };
    confirmText.textContent = `确定要结束进程「${name}」（PID ${pid}）吗？该操作会立即终止此程序。`;
    modal.classList.remove("hidden");
  });

  confirmOk.addEventListener("click", async function () {
    if (!pendingExecute) return;
    modal.classList.add("hidden");
    const { pid } = pendingExecute;
    pendingExecute = null;
    try {
      const resp = await fetch("/api/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pid, action: "terminate" }),
      });
      const data = await resp.json();
      addMsg("bot", escapeHtml(data.message || "执行完成"));
    } catch (err) {
      addMsg("bot", "⚠️ 执行失败：" + escapeHtml(err.message));
    }
  });

  confirmCancel.addEventListener("click", function () {
    modal.classList.add("hidden");
    pendingExecute = null;
  });

  /* ---- 发送 ---- */
  async function send() {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = "";
    addMsg("user", escapeHtml(text));

    const typing = addTyping();
    sendBtn.disabled = true;

    try {
      // 流式接口（SSE）
      const resp = await fetch("/api/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text, session_id: sessionId }),
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      if (!resp.body) throw new Error("无响应体");

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let botMsg = null;
      let botText = "";
      let finalData = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // 按 SSE 事件边界拆分（空行分隔）
        const events = buffer.split("\n\n");
        buffer = events.pop();

        for (const evt of events) {
          for (const line of evt.split("\n")) {
            if (!line.startsWith("data:")) continue;
            let data;
            try { data = JSON.parse(line.slice(5).trim()); } catch { continue; }

            if (data.type === "token") {
              botText += data.text;
              if (!botMsg) {
                typing.remove();
                botMsg = addMsg("bot", "");
              }
              botMsg.querySelector(".bubble").innerHTML = escapeHtml(botText).replace(/\n/g, "<br>");
              chatEl.scrollTop = chatEl.scrollHeight;
            } else if (data.type === "result") {
              finalData = data;
            }
          }
        }
      }
      // 处理剩余 buffer
      for (const line of buffer.split("\n")) {
        if (!line.startsWith("data:")) continue;
        try {
          const data = JSON.parse(line.slice(5).trim());
          if (data.type === "result") finalData = data;
        } catch { /* ignore */ }
      }

      if (finalData) {
        if (!botMsg) typing.remove();
        let html = escapeHtml(finalData.reply || "").replace(/\n/g, "<br>");
        html += renderRisks(finalData.risks || []);
        if (botMsg) {
          botMsg.querySelector(".bubble").innerHTML = html;
        } else {
          addMsg("bot", html);
        }
        sessionId = finalData.session_id || sessionId;

        if (finalData.needs_confirmation && finalData.execute_hint) {
          const { pid } = finalData.execute_hint;
          pendingExecute = { pid };
          confirmText.textContent = `OpenGuardian 建议处置进程（PID ${pid}）。确定要结束它吗？`;
          modal.classList.remove("hidden");
        }
      } else if (!botMsg) {
        typing.remove();
        addMsg("bot", "⚠️ 未收到有效回复");
      }
    } catch (err) {
      typing.remove();
      addMsg("bot", "⚠️ 连接服务器失败：" + escapeHtml(err.message));
    } finally {
      sendBtn.disabled = false;
      inputEl.focus();
    }
  }

  sendBtn.addEventListener("click", send);
  inputEl.addEventListener("keydown", function (e) {
    if (e.key === "Enter") send();
  });

  /* ---- 健康检查 ---- */
  async function checkHealth() {
    try {
      const resp = await fetch("/api/health");
      const data = await resp.json();
      if (data.status === "ok") {
        statusText.textContent = `在线 · v${data.version}`;
        statusDot.classList.add("ok");
      }
    } catch (err) {
      statusText.textContent = "离线";
      statusDot.classList.add("err");
    }
  }

  checkHealth();
  inputEl.focus();
})();
