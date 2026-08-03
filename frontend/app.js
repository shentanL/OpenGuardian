/* OpenGuardian 前端逻辑 */
(function () {
  "use strict";

  // 注入 SVG 图标库（icons.js 定义的 ICONS sprite）
  document.body.insertAdjacentHTML("afterbegin", ICONS);

  // tab / 按钮图标
  const tabChatEl = document.getElementById("tab-chat");
  const tabDashEl = document.getElementById("tab-dash");
  if (tabChatEl) tabChatEl.innerHTML = ic("ic-chat") + "安全助手";
  if (tabDashEl) tabDashEl.innerHTML = ic("ic-gauge") + "监控台";
  const sendBtnEl = document.getElementById("send");
  if (sendBtnEl) sendBtnEl.innerHTML = "发送 " + ic("ic-send");

  // 系统时钟（等宽）
  const clockEl = document.getElementById("sys-clock");
  if (clockEl) {
    setInterval(() => {
      const d = new Date();
      clockEl.textContent = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
    }, 1000);
  }

  const chatEl = document.getElementById("chat");
  const inputEl = document.getElementById("input");
  const sendBtn = document.getElementById("send");
  const statusText = document.getElementById("status-text");
  const statusDot = document.querySelector(".dot");
  const modal = document.getElementById("confirm-modal");
  const confirmText = document.getElementById("confirm-text");
  const confirmOk = document.getElementById("confirm-ok");
  const confirmCancel = document.getElementById("confirm-cancel");

  let pendingExecute = null;

  const LEVEL_CLASS = { critical: "critical", high: "high", medium: "medium", low: "low" };
  const LEVEL_ICON = { critical: "ic-bolt", high: "ic-alert", medium: "ic-alert", low: "ic-check" };

  /* ---- 工具 ---- */
  function addMsg(role, html) {
    const div = document.createElement("div");
    div.className = "msg " + role;
    const avatar = role === "user" ? ic("ic-shield") : ic("ic-radar");
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
    div.innerHTML = `<div class="avatar">${ic("ic-radar")}</div><div class="bubble">正在思考</div>`;
    chatEl.appendChild(div);
    chatEl.scrollTop = chatEl.scrollHeight;
    return div;
  }

  function renderRisks(risks) {
    if (!risks || !risks.length) return "";
    let html = "";
    for (const r of risks) {
      const cls = LEVEL_CLASS[r.level] || "low";
      const icon = LEVEL_ICON[r.level] ? ic(LEVEL_ICON[r.level], `lv-${cls}`) : ic("ic-alert");
      html += `
        <div class="risk-card ${cls}">
          <div class="r-name">${icon} ${escapeHtml(r.name)}</div>
          <div class="r-detail">${escapeHtml(r.detail)}</div>
          ${r.suggestion ? `<div class="r-suggest">${ic("ic-shield")} ${escapeHtml(r.suggestion)}</div>` : ""}
          ${r.pid ? `<button class="btn-term" data-pid="${r.pid}" data-name="${escapeHtml(r.name)}">${ic("ic-bolt")} 结束该进程（PID ${r.pid}）</button>` : ""}
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
      addMsg("bot", ic("ic-alert") + " 执行失败：" + escapeHtml(err.message));
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
        body: JSON.stringify({ message: text, session_id: currentSessionId }),
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
        if (finalData.session_id) {
          currentSessionId = finalData.session_id;
          localStorage.setItem("og_session", currentSessionId);
          if (!sessionMeta[currentSessionId]) sessionMeta[currentSessionId] = { title: "" };
          if (!sessionMeta[currentSessionId].title) sessionMeta[currentSessionId].title = text.slice(0, 18);
          loadSessions();
        }

        if (finalData.needs_confirmation && finalData.execute_hint) {
          const { pid } = finalData.execute_hint;
          pendingExecute = { pid };
          confirmText.textContent = `OpenGuardian 建议处置进程（PID ${pid}）。确定要结束它吗？`;
          modal.classList.remove("hidden");
        }
      } else if (!botMsg) {
        typing.remove();
        addMsg("bot", ic("ic-alert") + " 未收到有效回复");
      }
    } catch (err) {
      typing.remove();
      addMsg("bot", ic("ic-alert") + " 连接服务器失败：" + escapeHtml(err.message));
    } finally {
      sendBtn.disabled = false;
      inputEl.focus();
    }
  }

  sendBtn.addEventListener("click", send);
  inputEl.addEventListener("keydown", function (e) {
    if (e.key === "Enter") send();
  });

  /* ---- 仪表盘 ---- */
  const chatMain = document.getElementById("chat");
  const dashMain = document.getElementById("dashboard");
  const tabChat = document.getElementById("tab-chat");
  const tabDash = document.getElementById("tab-dash");

  function switchTab(showDash) {
    chatMain.classList.toggle("hidden", showDash);
    dashMain.classList.toggle("hidden", !showDash);
    tabChat.classList.toggle("active", !showDash);
    tabDash.classList.toggle("active", showDash);
    if (showDash) loadDashboard();
  }
  tabChat.addEventListener("click", () => switchTab(false));
  tabDash.addEventListener("click", () => switchTab(true));

  function renderRiskBars(dist) {
    const el = document.getElementById("risk-bars");
    const total = Math.max(dist.total || 0, 1);
    const high = dist.high || 0;
    const other = dist.other || 0;
    const pct = (v) => Math.round((v / total) * 100);
    el.innerHTML = `
      <div class="bar-row"><span class="lbl"><i class="sw sw-high"></i>高危</span>
        <div class="bar-track"><div class="bar-fill high" style="width:${pct(high)}%"></div></div>
        <span class="val">${high}</span></div>
      <div class="bar-row"><span class="lbl"><i class="sw sw-other"></i>其他</span>
        <div class="bar-track"><div class="bar-fill other" style="width:${pct(other)}%"></div></div>
        <span class="val">${other}</span></div>
      <div class="bar-row"><span class="lbl"><i class="sw sw-total"></i>累计</span>
        <div class="bar-track"><div class="bar-fill" style="width:100%;background:#2a2a2a"></div></div>
        <span class="val">${dist.total || 0}</span></div>`;
  }

  function renderResChart(samples) {
    const svg = document.getElementById("res-chart");
    if (!samples || samples.length < 2) {
      svg.innerHTML = `<text x="200" y="80" text-anchor="middle" fill="#64748b" font-size="13">运行检测后显示趋势图</text>`;
      return;
    }
    const W = 400, H = 150, PAD = 10;
    const n = samples.length;
    const x = (i) => PAD + (i * (W - 2 * PAD)) / (n - 1);
    const y = (v) => H - PAD - (v / 100) * (H - 2 * PAD);
    const path = (key) => samples.map((s, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(s[key]).toFixed(1)}`).join(" ");
    // 网格线（0/50/100%）
    let grid = "";
    for (const g of [0, 50, 100]) {
      grid += `<line x1="${PAD}" y1="${y(g)}" x2="${W - PAD}" y2="${y(g)}" stroke="#1e293b" stroke-width="1"/>`;
      grid += `<text x="${W - PAD - 2}" y="${y(g) + 4}" fill="#475569" font-size="9" text-anchor="end">${g}%</text>`;
    }
    svg.innerHTML = grid +
      `<polyline points="${path("cpu")}" stroke="#38bdf8"/>` +
      `<polyline points="${path("mem")}" stroke="#a78bfa"/>` +
      `<polyline points="${path("disk")}" stroke="#34d399"/>`;
  }

  function renderScanList(scans) {
    const el = document.getElementById("scan-list");
    if (!scans || !scans.length) {
      el.innerHTML = `<div class="scan-item">暂无检测记录 — 在助手页说「帮我检测一下电脑」</div>`;
      return;
    }
    el.innerHTML = scans.map((s) => {
      const cls = s.high > 0 ? "crit" : s.total > 0 ? "warn" : "ok";
      const lbl = s.high > 0 ? `${s.high} 高危` : s.total > 0 ? `${s.total} 项` : "安全";
      const time = (s.time || "").replace("T", " ").slice(5, 16);
      return `<div class="scan-item"><span>${time}</span><span>${escapeHtml((s.summary || "").slice(0, 40))}</span><span class="badge ${cls}">${lbl}</span></div>`;
    }).join("");
  }

  async function loadDashboard() {
    try {
      const resp = await fetch("/api/stats");
      const data = await resp.json();
      renderRiskBars(data.risk_distribution || {});
      renderResChart(data.resources || []);
      renderScanList(data.scans || []);
      // KPI 卡片
      const dist = data.risk_distribution || {};
      const setKpi = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      setKpi("kpi-high", dist.high || 0);
      setKpi("kpi-total", dist.total || 0);
      setKpi("kpi-audit", data.audit_count || 0);
      setKpi("kpi-scans", (data.scans || []).length);
    } catch (err) {
      document.getElementById("risk-bars").innerHTML = `<div style="color:#f87171">加载失败：${escapeHtml(err.message)}</div>`;
    }
  }

  /* ---- 会话管理 ---- */
  const sessionListEl = document.getElementById("session-list");
  const newSessionBtn = document.getElementById("new-session");
  let currentSessionId = localStorage.getItem("og_session") || "";

  async function loadSessions() {
    try {
      const resp = await fetch("/api/sessions");
      const data = await resp.json();
      const sessions = data.sessions || [];
      sessionListEl.innerHTML = sessions.length
        ? sessions.map((s) => {
            const title = sessionTitle(s.id) || s.id.slice(0, 10);
            return `<div class="session-item ${s.id === currentSessionId ? "active" : ""}" data-id="${s.id}">
              ${ic("ic-chat")}<span class="s-title">${escapeHtml(title)}</span>
              <button class="s-del" data-del="${s.id}" title="删除会话">${ic("ic-trash")}</button>
            </div>`;
          }).join("")
        : `<div style="color:#757575;font-size:11px;padding:8px">暂无会话</div>`;
    } catch { /* 静默 */ }
  }

  function sessionTitle(id) {
    // 从当前已加载的消息里取第一条用户消息作为标题
    const meta = sessionMeta[id];
    return meta ? meta.title : "";
  }

  const sessionMeta = {}; // id -> {title}

  async function switchSession(id) {
    if (!id) return;
    currentSessionId = id;
    localStorage.setItem("og_session", id);
    chatEl.innerHTML = "";
    try {
      const resp = await fetch(`/api/sessions/${id}/messages`);
      const data = await resp.json();
      const messages = data.messages || [];
      sessionMeta[id] = { title: "" };
      messages.forEach((m) => {
        if (m.role === "user" && !sessionMeta[id].title) {
          sessionMeta[id].title = m.content.slice(0, 18);
        }
        addMsg(m.role === "user" ? "user" : "bot", escapeHtml(m.content).replace(/\n/g, "<br>"));
      });
      if (!messages.length) addWelcome();
    } catch (err) {
      addMsg("bot", ic("ic-alert") + " 加载会话失败：" + escapeHtml(err.message));
    }
    loadSessions();
  }

  function newSession() {
    currentSessionId = "";
    localStorage.removeItem("og_session");
    chatEl.innerHTML = "";
    addWelcome();
    loadSessions();
  }

  function addWelcome() {
    addMsg("bot",
      "你好！我是 OpenGuardian，你的 AI 个人数字安全助手。<br><br>" +
      "你可以对我说：<br>" +
      "· <b>「帮我检测一下电脑」</b> — 扫描进程/网络/资源风险<br>" +
      "· <b>「什么是钓鱼邮件？」</b> — 安全知识咨询<br>" +
      "· <b>「检查密码 123456」</b> — 密码强度评估<br>" +
      "· <b>「讲讲勒索病毒」</b> — 安全案例科普");
  }

  sessionListEl.addEventListener("click", (e) => {
    const delBtn = e.target.closest(".s-del");
    if (delBtn) {
      e.stopPropagation();
      const id = delBtn.dataset.del;
      fetch(`/api/sessions/${id}`, { method: "DELETE" }).then(() => {
        if (id === currentSessionId) newSession();
        else loadSessions();
      });
      return;
    }
    const item = e.target.closest(".session-item");
    if (item) switchSession(item.dataset.id);
  });
  newSessionBtn.addEventListener("click", newSession);

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

  // 会话初始化：有历史会话则恢复，否则欢迎消息
  loadSessions();
  if (currentSessionId) {
    switchSession(currentSessionId);
  } else {
    addWelcome();
  }
})();
