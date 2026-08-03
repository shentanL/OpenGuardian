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
    if (showDash) {
      loadDashboard();
      if (!window._dashTimer) {
        window._dashTimer = setInterval(loadDashboard, 3000); // 每 3s 自动刷新（1s 采样实时趋势）
      }
    }
  }
  // 离开监控台时停止刷新
  function stopDashRefresh() {
    if (window._dashTimer) { clearInterval(window._dashTimer); window._dashTimer = null; }
  }
  tabChat.addEventListener("click", () => { switchTab(false); stopDashRefresh(); });
  tabDash.addEventListener("click", () => switchTab(true));

  function renderRiskBars(dist) {
    const el = document.getElementById("risk-bars");
    if (!dist || !dist.levels) {
      el.innerHTML = `<div style="color:#757575;font-size:11px">运行检测后显示分布</div>`;
      return;
    }
    const levels = dist.levels;
    const types = dist.types || {};
    const total = Math.max(dist.total || 1, 1);
    const pct = (v) => Math.round((v / total) * 100);
    const LEVELS = [
      ["critical", "严重", "bar-crit"],
      ["high", "高危", "bar-high"],
      ["medium", "中危", "bar-med"],
      ["low", "低危", "bar-low"],
    ];
    const TYPES = [
      ["process", "进程", "sw-process"],
      ["network", "网络", "sw-network"],
      ["resource", "资源", "sw-resource"],
      ["asset", "资产", "sw-asset"],
    ];
    const bar = (key, label, cls, val) => `
      <div class="bar-row"><span class="lbl">${label}</span>
        <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct(val)}%"></div></div>
        <span class="val">${val}</span></div>`;
    // 明细化：仅渲染有数据的项（排掉 0 值空行），类别全 0 时整组隐藏
    const lvRows = LEVELS.filter(([k]) => (levels[k] || 0) > 0)
      .map(([k, l, c]) => bar(k, l, c, levels[k])).join("");
    const typeRows = TYPES.filter(([k]) => (types[k] || 0) > 0)
      .map(([k, l, c]) => bar(k, l, c, types[k])).join("");
    // 最近风险明细（来自最近检测的真实风险项）
    const last = dist.last_risks || [];
    const LV_CLS = { critical: "lv-crit", high: "lv-high", medium: "lv-med", low: "lv-low" };
    const detailRows = last.slice(0, 8).map((r) => {
      const lv = String(r.level || "low").toLowerCase();
      const name = r.name || r.process || r.item || "未知";
      const desc = r.detail || r.description || r.reason || r.message || "";
      return `<div class="risk-item"><span class="lv-badge ${LV_CLS[lv] || "lv-low"}">${lv}</span>
        <span class="risk-name">${escapeHtml(name)}</span>
        <span class="risk-desc">${escapeHtml(desc)}</span></div>`;
    }).join("");
    // 按需显示：0 风险时不渲染空条形（累计/级别/类别），仅简洁空状态
    if ((dist.total || 0) === 0) {
      el.innerHTML = `<div class="dist-empty">最近检测 0 风险，系统状态干净</div>`;
      return;
    }
    el.innerHTML = `
      ${lvRows ? `<div class="dist-group">按级别</div>${lvRows}` : ""}
      ${typeRows ? `<div class="dist-group">按类别</div>${typeRows}` : ""}
      ${bar("total", "累计", "bar-total", dist.total || 0)}
      ${detailRows ? `<div class="dist-group">最近风险明细</div>${detailRows}` : ""}`;
  }

  function renderResChart(samples) {
    const svg = document.getElementById("res-chart");
    const legendEl = document.querySelector(".legend");
    if (!samples || samples.length < 2) {
      svg.innerHTML = `<text x="200" y="80" text-anchor="middle" fill="#757575" font-size="12" font-family="monospace">采样中…（每 1s 自动记录）</text>`;
      if (legendEl) legendEl.innerHTML = `<span class="lg-cpu">CPU --%</span><span class="lg-mem">MEM --%</span><span class="lg-disk">DISK --%</span>`;
      return;
    }
    const W = 400, H = 150, PAD = 14;
    const n = samples.length;
    const last = samples[n - 1];
    const x = (i) => PAD + (i * (W - 2 * PAD)) / (n - 1);
    const y = (v) => H - PAD - (v / 100) * (H - 2 * PAD);

    // Catmull-Rom → 贝塞尔平滑曲线（ECharts smooth 风格）
    const smoothPath = (key) => {
      const pts = samples.map((s, i) => ({ x: x(i), y: y(s[key]) }));
      let d = `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[i - 1] || pts[i];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[i + 2] || p2;
        const c1x = p1.x + (p2.x - p0.x) / 6;
        const c1y = p1.y + (p2.y - p0.y) / 6;
        const c2x = p2.x - (p3.x - p1.x) / 6;
        const c2y = p2.y - (p3.y - p1.y) / 6;
        d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
      }
      return d;
    };
    const areaPath = (key) => {
      const p = smoothPath(key);
      return `${p} L${x(n - 1).toFixed(1)},${H - PAD} L${x(0).toFixed(1)},${H - PAD} Z`;
    };

    // 统计：avg / max（Netdata 风格）
    const stats = (key) => {
      const vals = samples.map((s) => s[key]);
      const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
      return { avg, max: Math.max(...vals) };
    };
    const stCpu = stats("cpu"), stMem = stats("mem"), stDisk = stats("disk");

    // 网格 + 阈值线 + 时间刻度
    let grid = `<defs>
        <linearGradient id="grad-cpu" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#76b900"/><stop offset="100%" stop-color="#76b900" stop-opacity="0"/></linearGradient>
        <linearGradient id="grad-mem" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#bff230"/><stop offset="100%" stop-color="#bff230" stop-opacity="0"/></linearGradient>
        <linearGradient id="grad-disk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#a7a7a7"/><stop offset="100%" stop-color="#a7a7a7" stop-opacity="0"/></linearGradient>
      </defs>`;
    for (const g of [0, 50, 100]) {
      grid += `<line x1="${PAD}" y1="${y(g)}" x2="${W - PAD}" y2="${y(g)}" stroke="#1f1f1f" stroke-width="1"/>`;
      grid += `<text x="${W - PAD - 2}" y="${y(g) + 4}" fill="#757575" font-size="9" font-family="monospace" text-anchor="end">${g}%</text>`;
    }
    // 85% 告警阈值虚线
    grid += `<line x1="${PAD}" y1="${y(85)}" x2="${W - PAD}" y2="${y(85)}" stroke="#df6500" stroke-width="1" stroke-dasharray="4,3" opacity="0.6"/>`;
    grid += `<text x="${PAD + 2}" y="${y(85) - 3}" fill="#df6500" font-size="8" font-family="monospace" opacity="0.8">ALERT 85%</text>`;
    // X 轴时间刻度（5 个等分）
    const tStep = Math.max(Math.floor(n / 5), 1);
    for (let i = 0; i < n; i += tStep) {
      const t = (samples[i].time || "").slice(11, 19);
      grid += `<text x="${x(i)}" y="${H - 2}" fill="#757575" font-size="8" font-family="monospace" text-anchor="middle" opacity="0.7">${t}</text>`;
    }

    const dot = (key, color) => `<circle cx="${x(n - 1).toFixed(1)}" cy="${y(last[key]).toFixed(1)}" r="3" fill="#000" stroke="${color}" stroke-width="2"/>`;
    svg.innerHTML = grid +
      `<polygon points="${areaPath("cpu")}" fill="url(#grad-cpu)" opacity="0.22"/>` +
      `<polygon points="${areaPath("mem")}" fill="url(#grad-mem)" opacity="0.22"/>` +
      `<polygon points="${areaPath("disk")}" fill="url(#grad-disk)" opacity="0.22"/>` +
      `<path d="${smoothPath("cpu")}" fill="none" stroke="#76b900" stroke-width="2"/>` +
      `<path d="${smoothPath("mem")}" fill="none" stroke="#bff230" stroke-width="2"/>` +
      `<path d="${smoothPath("disk")}" fill="none" stroke="#a7a7a7" stroke-width="2"/>` +
      dot("cpu", "#76b900") + dot("mem", "#bff230") + dot("disk", "#a7a7a7");

    // 图例：色点 + 当前值大字 + avg/max 次要统计（Netdata 风格）
    if (legendEl) {
      legendEl.innerHTML =
        `<span class="lg lg-cpu" data-k="cpu"><i class="sw sw-cpu"></i>CPU <b>${last.cpu.toFixed(1)}%</b><em>avg ${stCpu.avg.toFixed(1)}% · max ${stCpu.max.toFixed(1)}%</em></span>` +
        `<span class="lg lg-mem" data-k="mem"><i class="sw sw-mem"></i>MEM <b>${last.mem.toFixed(1)}%</b><em>avg ${stMem.avg.toFixed(1)}% · max ${stMem.max.toFixed(1)}%</em></span>` +
        `<span class="lg lg-disk" data-k="disk"><i class="sw sw-disk"></i>DISK <b>${last.disk.toFixed(1)}%</b><em>avg ${stDisk.avg.toFixed(1)}% · max ${stDisk.max.toFixed(1)}%</em></span>`;
    }

    // 悬停十字线 + tooltip（Grafana 风格）
    bindChartHover(svg, samples, x, y);
  }

  // 图表悬停交互：十字线 + 数值 tooltip
  function bindChartHover(svg, samples, x, y) {
    const box = svg.closest(".panel");
    if (!box) return;
    let cross = document.getElementById("chart-cross");
    let tip = document.getElementById("chart-tip");
    if (!cross) {
      cross = document.createElementNS("http://www.w3.org/2000/svg", "line");
      cross.id = "chart-cross";
      cross.setAttribute("stroke", "#a7a7a7");
      cross.setAttribute("stroke-width", "1");
      cross.setAttribute("stroke-dasharray", "3,3");
      cross.setAttribute("opacity", "0.7");
      svg.appendChild(cross);
      tip = document.createElement("div");
      tip.id = "chart-tip";
      tip.className = "chart-tip";
      box.appendChild(tip);
    }
    const onMove = (e) => {
      const rect = svg.getBoundingClientRect();
      const px = e.clientX - rect.left;
      const ratio = (px - 14) / (rect.width - 28);
      const idx = Math.round(ratio * (samples.length - 1));
      if (idx < 0 || idx >= samples.length) { cross.setAttribute("opacity", "0"); tip.style.display = "none"; return; }
      const s = samples[idx];
      cross.setAttribute("x1", x(idx)); cross.setAttribute("x2", x(idx));
      cross.setAttribute("y1", 0); cross.setAttribute("y2", 140);
      cross.setAttribute("opacity", "0.7");
      const t = (s.time || "").slice(11, 19);
      tip.innerHTML = `<b>${t}</b><br>CPU <span class="tc">${s.cpu.toFixed(1)}%</span><br>MEM <span class="tm">${s.mem.toFixed(1)}%</span><br>DISK <span class="td">${s.disk.toFixed(1)}%</span>`;
      tip.style.display = "block";
      tip.style.left = `${px + 12}px`;
      tip.style.top = `${e.clientY - rect.top - 8}px`;
      // 图例联动：悬停值高亮
      document.querySelectorAll(".legend .lg").forEach((el) => {
        const k = el.dataset.k;
        const b = el.querySelector("b");
        if (b && k && s[k] !== undefined) { b.textContent = `${s[k].toFixed(1)}%`; el.classList.add("active"); }
      });
    };
    svg.addEventListener("mousemove", onMove);
    svg.addEventListener("mouseleave", () => {
      cross.setAttribute("opacity", "0");
      tip.style.display = "none";
      // 图例恢复最新值
      const lastS = samples[samples.length - 1];
      document.querySelectorAll(".legend .lg").forEach((el) => {
        const k = el.dataset.k;
        const b = el.querySelector("b");
        if (b && k && lastS[k] !== undefined) { b.textContent = `${lastS[k].toFixed(1)}%`; el.classList.remove("active"); }
      });
    });
  }

  function renderStatusBanner(data) {
    const banner = document.getElementById("status-banner");
    const title = document.getElementById("sb-title");
    const sub = document.getElementById("sb-sub");
    const time = document.getElementById("sb-time");
    const scans = data.scans || [];
    const latest = scans[0];
    const dist = data.risk_distribution || {};
    const total = dist.total || 0;
    if (!latest) {
      banner.className = "status-banner neutral";
      title.textContent = "尚未运行检测";
      sub.textContent = "在安全助手页输入「帮我检测一下电脑」开始首次扫描";
      time.textContent = "";
      return;
    }
    const t = (latest.time || "").replace("T", " ").slice(0, 19);
    if (total > 0) {
      const lv = dist.levels || {};
      const crit = (lv.critical || 0) + (lv.high || 0);
      banner.className = "status-banner danger";
      title.textContent = `检测到 ${total} 项风险${crit ? `（含 ${crit} 项高危）` : ""}`;
      sub.textContent = (latest.summary || "").slice(0, 60);
    } else {
      banner.className = "status-banner safe";
      title.textContent = "系统状态：安全";
      sub.textContent = "最近检测未发现风险，请保持良好安全习惯";
    }
    time.textContent = `最近检测 ${t}`;
  }

  function renderDonut(dist) {
    const svg = document.getElementById("risk-donut");
    const totalEl = document.getElementById("donut-total");
    if (!svg) return;
    const total = dist.total || 0;
    totalEl.textContent = total;
    const lv = dist.levels || {};
    const SEGS = [
      ["critical", "#e52020"],
      ["high", "#df6500"],
      ["medium", "#ef9100"],
      ["low", "#3f8500"],
    ];
    const R = 44, CX = 60, CY = 60, W = 12;
    if (total === 0) {
      svg.innerHTML = `<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="#1f1f1f" stroke-width="${W}"/>`;
      return;
    }
    let acc = 0;
    let paths = "";
    for (const [k, color] of SEGS) {
      const v = lv[k] || 0;
      if (v <= 0) continue;
      const frac = v / total;
      const a0 = (acc * 2 * Math.PI) - Math.PI / 2;
      const a1 = ((acc + frac) * 2 * Math.PI) - Math.PI / 2;
      const x0 = CX + R * Math.cos(a0), y0 = CY + R * Math.sin(a0);
      const x1 = CX + R * Math.cos(a1), y1 = CY + R * Math.sin(a1);
      const large = frac > 0.5 ? 1 : 0;
      paths += `<path d="M${x0.toFixed(1)},${y0.toFixed(1)} A${R},${R} 0 ${large} 1 ${x1.toFixed(1)},${y1.toFixed(1)}" fill="none" stroke="${color}" stroke-width="${W}"/>`;
      acc += frac;
    }
    svg.innerHTML = paths;
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
      const time = (s.time || "").replace("T", " ").slice(0, 19);
      return `<div class="scan-item">
        <span class="scan-time">${time}</span>
        <span class="scan-sum">${escapeHtml((s.summary || "").slice(0, 46))}</span>
        <span class="badge ${cls}">${lbl}</span>
      </div>`;
    }).join("");
  }

  async function loadDashboard() {
    try {
      const resp = await fetch("/api/stats");
      const data = await resp.json();
      const dist = data.risk_distribution || {};
      renderStatusBanner(data);
      renderDonut(dist);
      renderRiskBars(Object.assign({}, dist, { last_risks: data.last_risks || [] }));
      renderResChart(data.resources || []);
      renderScanList(data.scans || []);
      // KPI 卡片
      const setKpi = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      const lv = dist.levels || {};
      const high = (lv.critical || 0) + (lv.high || 0);
      setKpi("kpi-high", high);
      setKpi("kpi-total", dist.total || 0);
      setKpi("kpi-audit", data.audit_count || 0);
      setKpi("kpi-scans", (data.scans || []).length);
      // 实时内存（来自最近资源采样）
      const res = data.resources || [];
      if (res.length) setKpi("kpi-mem", `${res[res.length - 1].mem.toFixed(0)}%`);
      // 高危状态灯
      const dot = document.getElementById("kpi-high-dot");
      if (dot) { dot.className = "kpi-dot " + (high > 0 ? "on" : "off"); }
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
