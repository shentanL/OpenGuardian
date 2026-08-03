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
    div.innerHTML = `<div class="avatar">${avatar}</div>
      <div class="bubble">
        <button class="msg-copy" title="复制">${ic("ic-copy")}</button>
        <div class="bubble-inner">${html}</div>
      </div>`;
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
    // 复制按钮（GitHub 代码块风格）
    const copyBtn = e.target.closest(".msg-copy");
    if (copyBtn) {
      const inner = copyBtn.closest(".bubble").querySelector(".bubble-inner");
      const text = inner ? inner.textContent.trim() : "";
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.innerHTML = `${ic("ic-check")}`;
          copyBtn.classList.add("copied");
          setTimeout(() => { copyBtn.innerHTML = `${ic("ic-copy")}`; copyBtn.classList.remove("copied"); }, 1500);
        });
      }
      return;
    }
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

  // 等级卡元数据（Splunk/Defender 风格）
  const LEVEL_CARDS = [
    ["critical", "严重", "lv-crit"],
    ["high", "高危", "lv-high"],
    ["medium", "中危", "lv-med"],
    ["low", "低危", "lv-low"],
  ];
  // 类别细分 7 类
  const TYPES = [
    ["process", "进程异常", "sw-process"],
    ["network", "可疑网络", "sw-network"],
    ["malicious_ip", "恶意 IP", "sw-ip"],
    ["malicious_domain", "恶意域名", "sw-domain"],
    ["port", "危险端口", "sw-port"],
    ["resource", "资源占用", "sw-resource"],
    ["asset", "资产安全", "sw-asset"],
  ];

  function renderRiskBars(dist) {
    const el = document.getElementById("risk-bars");
    if (!dist || !dist.levels) {
      el.innerHTML = `<div style="color:#757575;font-size:11px">运行检测后显示分布</div>`;
      return;
    }
    const levels = dist.levels;
    const types = dist.types || {};
    const total = dist.total || 0;
    const pct = (v) => (total === 0 ? 0 : Math.round((v / total) * 100));
    // 按需显示：0 风险仅简洁空状态
    if (total === 0) {
      el.innerHTML = `<div class="lv-cards">
        ${LEVEL_CARDS.map(([k, l, c]) => `<div class="lv-card ${c}"><div class="lv-num">0</div><div class="lv-name">${l}</div></div>`).join("")}
      </div>
      <div class="dist-empty">最近检测 0 风险，系统状态干净</div>`;
      return;
    }
    // 等级卡（Splunk/Defender 风格：大数字 + 占比）
    const lvCards = LEVEL_CARDS.map(([k, l, c]) => {
      const v = levels[k] || 0;
      return `<div class="lv-card ${c} ${v > 0 ? "on" : ""}">
        <div class="lv-num">${v}</div>
        <div class="lv-name">${l}</div>
        <div class="lv-pct">${pct(v)}%</div></div>`;
    }).join("");
    // 类别分布（7 类条形，仅显示有数据的）
    const typeRows = TYPES.filter(([k]) => (types[k] || 0) > 0)
      .map(([k, l, sw]) => {
        const v = types[k];
        return `<div class="bar-row"><span class="lbl"><i class="sw ${sw}"></i>${l}</span>
          <div class="bar-track"><div class="bar-fill ${sw}" style="width:${pct(v)}%"></div></div>
          <span class="val">${v}</span>
          <span class="pct">${pct(v)}%</span></div>`;
      }).join("");
    // Top 风险项（最危险的 6 条）
    const LV_CLS = { critical: "lv-crit", high: "lv-high", medium: "lv-med", low: "lv-low" };
    const LV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
    const top = (dist.last_risks || []).slice()
      .sort((a, b) => (LV_ORDER[String(a.level).toLowerCase()] ?? 3) - (LV_ORDER[String(b.level).toLowerCase()] ?? 3))
      .slice(0, 6);
    const topRows = top.map((r) => {
      const lv = String(r.level || "low").toLowerCase();
      const name = r.name || r.process || r.item || "未知";
      const desc = r.detail || r.description || r.reason || r.message || "";
      const sug = r.suggestion || "";
      return `<div class="risk-item clickable" data-expand="0">
        <span class="lv-badge ${LV_CLS[lv] || "lv-low"}">${lv}</span>
        <span class="risk-name">${escapeHtml(name)}</span>
        <span class="risk-desc">${escapeHtml(desc)}</span>
        <span class="expand-hint">${ic("ic-gauge")}<i>查看</i></span>
        <div class="risk-sug">${sug ? `建议：${escapeHtml(sug)}` : ""}</div>
      </div>`;
    }).join("");
    el.innerHTML = `
      <div class="dist-group">等级分布</div>
      <div class="lv-cards">${lvCards}</div>
      ${typeRows ? `<div class="dist-group">类别分布</div>${typeRows}` : ""}
      <div class="dist-group">Top 风险项</div>
      ${topRows || `<div class="dist-empty">暂无风险明细</div>`}`;
    // Top 风险项点击展开建议
    el.querySelectorAll(".risk-item.clickable").forEach((item) => {
      item.addEventListener("click", () => {
        const sug = item.querySelector(".risk-sug");
        const hint = item.querySelector(".expand-hint");
        if (!sug || !sug.textContent.trim()) return;
        const open = item.dataset.expand === "1";
        item.dataset.expand = open ? "0" : "1";
        sug.style.display = open ? "none" : "block";
        if (hint) hint.innerHTML = `${ic("ic-gauge")}<i>${open ? "查看" : "收起"}</i>`;
      });
    });
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
    const latest = data.last_scan || (data.scans || [])[0];
    const total = latest ? (latest.total || 0) : 0;
    const high = latest ? (latest.high || 0) : 0;
    if (!latest) {
      banner.className = "status-banner neutral";
      title.textContent = "尚未运行检测";
      sub.textContent = "在安全助手页输入「帮我检测一下电脑」开始首次扫描";
      time.textContent = "";
      return;
    }
    const t = (latest.time || "").replace("T", " ").slice(0, 19);
    if (total > 0) {
      banner.className = "status-banner danger";
      title.textContent = `检测到 ${total} 项风险${high ? `（含 ${high} 项高危）` : ""}`;
      sub.textContent = (latest.summary || "").slice(0, 60);
    } else {
      banner.className = "status-banner safe";
      title.textContent = "系统状态：安全";
      sub.textContent = "最近检测未发现风险，请保持良好安全习惯";
    }
    time.textContent = `最近检测 ${t}`;
  }

  function renderSecurity(sec) {
    if (!sec || sec.score === undefined) return;
    const scoreEl = document.getElementById("sec-score");
    const gradeEl = document.getElementById("sec-grade");
    const subEl = document.getElementById("sec-sub");
    const barEl = document.getElementById("sec-bar-fill");
    const sugEl = document.getElementById("sec-suggestions");
    if (!scoreEl) return;
    scoreEl.textContent = sec.score;
    gradeEl.textContent = sec.label;
    const grade = sec.grade || "medium";
    const panel = document.querySelector(".security-panel");
    panel.className = "security-panel sec-" + grade;
    if (barEl) barEl.style.width = sec.score + "%";
    const tip = sec.risk_count > 0
      ? `发现 ${sec.risk_count} 项风险${sec.threat_hits ? ` · ${sec.threat_hits} 项威胁情报命中` : ""}`
      : "当前状态良好，坚持以下习惯更安心";
    if (subEl) subEl.textContent = tip;
    if (sugEl) {
      const ICONS = { process: "ic-term", port: "ic-net", asset: "ic-lock", network: "ic-net",
                      malicious_ip: "ic-alert", malicious_domain: "ic-alert", resource: "ic-gauge",
                      update: "ic-bolt", firewall: "ic-shield", password: "ic-lock",
                      phishing: "ic-alert", backup: "ic-check" };
      sugEl.innerHTML = (sec.suggestions || []).map((s) =>
        `<div class="sec-sug-item">${ic(ICONS[s.icon] || "ic-check")}<span>${escapeHtml(s.text)}</span></div>`
      ).join("") || `<div class="sec-sug-item">暂无建议</div>`;
    }
  }

  function renderKbStatus(kb) {
    const el = document.getElementById("kb-text");
    if (!el) return;
    if (!kb || !kb.last_update) {
      el.innerHTML = `<span class="kb-dim">威胁情报自动更新：等待首次同步…</span>`;
      return;
    }
    const src = kb.sources || {};
    const urlhaus = src.urlhaus || {};
    const firehol = src.firehol || {};
    const okAll = urlhaus.ok !== false && firehol.ok !== false;
    const mark = okAll ? `<span class="kb-ok">同步正常</span>` : `<span class="kb-warn">部分同步失败（沿用本地数据）</span>`;
    el.innerHTML =
      `威胁情报自动更新 · 恶意域名 <b>${kb.domains}</b> · 恶意 IP/CIDR <b>${kb.ips}</b>` +
      ` · 上次更新 <b>${kb.last_update}</b> · ${mark}`;
  }

  function renderScanList(scans) {
    const el = document.getElementById("scan-list");
    if (!scans || !scans.length) {
      el.innerHTML = `<div class="scan-item">暂无检测记录 — 在助手页说「帮我检测一下电脑」</div>`;
      return;
    }
    el.innerHTML = scans.map((s, i) => {
      const cls = s.high > 0 ? "crit" : s.total > 0 ? "warn" : "ok";
      const lbl = s.high > 0 ? `${s.high} 高危` : s.total > 0 ? `${s.total} 项` : "安全";
      const time = (s.time || "").replace("T", " ").slice(0, 19);
      const hasDetail = (s.risks || []).length > 0;
      return `<div class="scan-item clickable" data-i="${i}" data-expand="0">
        <span class="scan-time">${time}</span>
        <span class="scan-sum">${escapeHtml((s.summary || "").slice(0, 46))}</span>
        <span class="badge ${cls}">${lbl}</span>
        ${hasDetail ? `<span class="expand-hint">${ic("ic-gauge")}<i>查看</i></span>` : ""}
        <div class="scan-detail"></div>
      </div>`;
    }).join("");
    // 点击展开：该次检测的风险明细（GitHub 列表项交互）
    el.querySelectorAll(".scan-item.clickable").forEach((item) => {
      item.addEventListener("click", () => {
        const i = +item.dataset.i;
        const s = scans[i];
        const detail = item.querySelector(".scan-detail");
        const hint = item.querySelector(".expand-hint");
        if (item.dataset.expand === "1") {
          item.dataset.expand = "0";
          detail.innerHTML = "";
          if (hint) hint.innerHTML = `${ic("ic-gauge")}<i>查看</i>`;
          return;
        }
        item.dataset.expand = "1";
        const risks = s.risks || [];
        detail.innerHTML = risks.length
          ? risks.map((r) => {
              const lv = String(r.level || "low").toLowerCase();
              const nm = r.name || r.process || r.item || "未知";
              const ds = r.detail || r.description || "";
              const sg = r.suggestion || "";
              return `<div class="scan-risk lv-${lv}">
                <div class="sr-top"><b>${escapeHtml(nm)}</b><span class="sr-lv">${lv}</span></div>
                <div class="sr-detail">${escapeHtml(ds)}</div>
                ${sg ? `<div class="sr-sug">建议：${escapeHtml(sg)}</div>` : ""}
              </div>`;
            }).join("")
          : `<div class="scan-risk none">本次检测 0 风险</div>`;
        if (hint) hint.innerHTML = `${ic("ic-gauge")}<i>收起</i>`;
      });
    });
  }

  async function loadDashboard() {
    try {
      const resp = await fetch("/api/stats");
      const data = await resp.json();
      const dist = data.risk_distribution || {};
      renderStatusBanner(data);
      renderKbStatus(data.kb_status);
      renderSecurity(data.security);
      renderRiskBars(Object.assign({}, dist, { last_risks: data.last_risks || [] }));
      renderResChart(data.resources || []);
      renderScanList(data.scans || []);
      // KPI 卡片：高危/检测项基于最近一次检测（与分布同源）
      const setKpi = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      const latest = data.last_scan || {};
      const high = latest.high || 0;
      setKpi("kpi-high", high);
      setKpi("kpi-total", latest.total || 0);
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
    const qs = [
      { icon: "ic-scan", text: "帮我检测一下电脑" },
      { icon: "ic-book", text: "什么是钓鱼邮件？" },
      { icon: "ic-lock", text: "检查密码 123456" },
      { icon: "ic-shield", text: "讲讲勒索病毒" },
    ];
    const cards = qs.map((q) =>
      `<button class="wcard" data-q="${escapeHtml(q.text)}"><span class="wcard-ic">${ic(q.icon)}</span>${escapeHtml(q.text)}</button>`
    ).join("");
    const wrap = document.createElement("div");
    wrap.className = "msg bot";
    wrap.innerHTML = `<div class="avatar">${ic("ic-radar")}</div>
      <div class="bubble">
        <button class="msg-copy" title="复制">${ic("ic-copy")}</button>
        <div class="bubble-inner">
          <div class="welcome-title">你好，我是 OpenGuardian</div>
          <div class="welcome-sub">你的 AI 个人数字安全助手 —— 点一下试试，或直接输入你的问题</div>
          <div class="wcards">${cards}</div>
        </div>
      </div>`;
    chatEl.appendChild(wrap);
    chatEl.scrollTop = chatEl.scrollHeight;
    // 示例问题点击即问
    wrap.querySelectorAll(".wcard").forEach((btn) => {
      btn.addEventListener("click", () => {
        inputEl.value = btn.dataset.q;
        send();
      });
    });
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
        const verEl = document.querySelector(".logo .ver");
        if (verEl) verEl.textContent = `v${data.version}`;
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
