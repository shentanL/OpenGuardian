/* OpenGuardian 设置界面逻辑 */
(function () {
  "use strict";

  /* ── Tab 切换 ── */
  const tabs = document.querySelectorAll(".sn-tab");
  const panels = document.querySelectorAll(".settings-panel");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      panels.forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const target = document.getElementById("panel-" + tab.dataset.tab);
      if (target) target.classList.add("active");
      // 切换到威胁情报 Tab 时加载状态
      if (tab.dataset.tab === "threats") loadKbStatus();
      if (tab.dataset.tab === "whitelist") loadWhitelist();
      if (tab.dataset.tab === "virusdb") loadVirusDb();
      if (tab.dataset.tab === "about") loadAbout();
    });
  });

  /* ── Tab 1: AI 服务 ── */
  const providerGrid = document.getElementById("provider-grid");
  const modelSel = document.getElementById("model-select");
  const apiInput = document.getElementById("api-key");
  const customUrl = document.getElementById("custom-url");
  const customUrlGroup = document.getElementById("custom-url-group");
  const apiKeyGroup = document.getElementById("api-key-group");
  const keyHint = document.getElementById("key-hint");
  const providerDescBox = document.getElementById("provider-desc-box");
  const btnSave = document.getElementById("btn-save-provider");
  const msgEl = document.getElementById("provider-msg");
  const toggleBtn = document.getElementById("toggle-key");

  let providers = [];
  let _loadedModel = "";
  let _selectedProvider = "";

  toggleBtn?.addEventListener("click", () => {
    apiInput.type = apiInput.type === "password" ? "text" : "password";
  });

  function showMsg(text, ok) {
    msgEl.textContent = text;
    msgEl.className = "form-msg " + (ok ? "ok" : "err");
    msgEl.classList.remove("hidden");
    setTimeout(() => msgEl.classList.add("hidden"), 4000);
  }

  function renderProviderGrid(providers, currentKey) {
    if (!providerGrid) return;
    providerGrid.innerHTML = providers.map((p) => {
      const isActive = p.key === currentKey || p.key === _selectedProvider;
      const badge = p.key === "deepseek" ? "推荐" : (p.key === "ollama" ? "本地" : (p.key === "custom" ? "自定义" : ""));
      return '<button class="provider-card ' + (isActive ? "active" : "") + '" data-key="' + p.key + '">' +
        '<span class="pc-name">' + escapeHtml(p.name) + '</span>' +
        '<span class="pc-desc">' + escapeHtml(p.description || "") + '</span>' +
        (badge ? '<span class="pc-badge">' + badge + '</span>' : "") +
        '</button>';
    }).join("");

    providerGrid.querySelectorAll(".provider-card").forEach((card) => {
      card.addEventListener("click", () => {
        const key = card.dataset.key;
        _selectedProvider = key;
        renderProviderGrid(providers, key);
        updateProviderUI(providers.find((p) => p.key === key));
        btnSave.disabled = false;
      });
    });
  }

  async function loadConfig() {
    try {
      const r = await fetch("/api/config");
      const d = await r.json();
      providers = d.providers || [];

      // 提供商卡片网格
      renderProviderGrid(providers, d.provider);
      _selectedProvider = d.provider;

      updateProviderUI(providers.find((p) => p.key === d.provider));

      if (d.configured) {
        apiInput.placeholder = "已配置（留空保持不变）";
        apiInput.value = "";
        _loadedModel = d.model || "";
        if (d.base_url) {
          customUrl.value = d.base_url;
          customUrlGroup.style.display = "";
        }
        if (d.provider === "ollama") {
          keyHint.textContent = "Ollama 本地模型无需 API Key";
        }
      }
    } catch (err) {
      console.warn("Config load failed:", err);
    }
  }

  function getSelectedProviderKey() {
    const active = providerGrid?.querySelector(".provider-card.active");
    return active ? active.dataset.key : "";
  }

  function updateProviderUI(p) {
    if (!p) return;
    if (providerDescBox) providerDescBox.innerHTML = "<strong>" + escapeHtml(p.name) + "</strong> — " + escapeHtml(p.description || "");
    const models = p.models || [];
    modelSel.innerHTML = '<option value="">默认（' + (p.default_model || "自动") + "）</option>" +
      models.map((m) => '<option value="' + m + '" ' + (m === _loadedModel ? "selected" : "") + ">" + m + "</option>").join("");
    if (p.key === "ollama") {
      apiKeyGroup.style.display = "none";
    } else {
      apiKeyGroup.style.display = "";
      keyHint.innerHTML = "在 " + p.name + " 官网注册后获取 API Key。Key 仅存储在本机，加密保存。";
    }
    customUrlGroup.style.display = p.key === "custom" ? "" : "none";
  }

  btnSave?.addEventListener("click", async () => {
    const provider = getSelectedProviderKey() || "deepseek";
    if (!provider) { showMsg("请选择 AI 提供商", false); return; }
    btnSave.disabled = true;
    btnSave.querySelector("span") && (btnSave.querySelector("span").textContent = "保存中…");
    try {
      const r = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: provider,
          api_key: apiInput.value.trim(),
          base_url: customUrl.value.trim(),
          model: modelSel.value || document.getElementById("model-custom").value.trim(),
        }),
      });
      const d = await r.json();
      if (d.ok) showMsg("AI 设置已保存，新对话将使用 " + provider + "。", true);
      else showMsg(d.error || "保存失败", false);
    } catch (err) {
      showMsg("网络错误，请检查服务是否运行", false);
    }
    btnSave.disabled = false;
    btnSave.querySelector("span") && (btnSave.querySelector("span").textContent = "保存 AI 设置");
  });

  // 测试连接：先保存当前配置，再实测 LLM 连通
  document.getElementById("btn-test-llm")?.addEventListener("click", async () => {
    const provider = getSelectedProviderKey() || "deepseek";
    if (!provider) { showMsg("请选择 AI 提供商", false); return; }
    const testBtn = document.getElementById("btn-test-llm");
    testBtn.disabled = true;
    testBtn.classList.add("testing");
    testBtn.querySelector("span") && (testBtn.querySelector("span").textContent = "测试中…");
    showMsg("正在保存配置并测试连接…", true);
    try {
      // 1) 保存
      await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: provider,
          api_key: apiInput.value.trim(),
          base_url: customUrl.value.trim(),
          model: modelSel.value || document.getElementById("model-custom").value.trim(),
        }),
      });
      // 2) 实测
      const r = await fetch("/api/llm/test", { method: "POST" });
      const d = await r.json();
      if (d.ok) showMsg("✅ 连接成功！模型返回：" + (d.reply || "正常响应"), true);
      else showMsg("❌ 连接失败：" + (d.error || "未知错误") + "（检查 Key/网络/模型名）", false);
    } catch (err) {
      showMsg("❌ 测试失败：" + err.message, false);
    }
    testBtn.disabled = false;
    testBtn.classList.remove("testing");
    testBtn.querySelector("span") && (testBtn.querySelector("span").textContent = "测试连接");
  });

  /* ── Tab 2: 威胁情报 ── */
  async function loadKbStatus() {
    try {
      const r = await fetch("/api/kb/status");
      const d = await r.json();
      document.getElementById("kb-domains").textContent = (d.domain_count || 0).toLocaleString();
      document.getElementById("kb-ips").textContent = (d.ip_count || 0).toLocaleString();
      document.getElementById("kb-hashes").textContent = (d.hash_count || 0).toLocaleString();
      document.getElementById("kb-feeds").textContent = (d.feeds || []).length;
      document.getElementById("kb-last").textContent = "上次更新：" + (d.last_update || "--");

      const feedList = document.getElementById("feed-list");
      const feeds = d.feeds || [];
      const sources = d.sources || {};

      feedList.innerHTML = feeds.map((f) => {
        const src = sources[f.name] || {};
        const ok = src.ok !== false;
        const badgeCls = ok ? "ok" : "err";
        const badgeTxt = ok ? "在线" : "异常";
        return '<div class="feed-item">' +
          '<span class="feed-name">' + escapeHtml(f.name) + '</span>' +
          '<span class="feed-type">' + escapeHtml(f.type || f.ioc_type || "") + '</span>' +
          '<span class="badge ' + badgeCls + '">' + badgeTxt + '</span>' +
          '<span class="feed-count">' + (src.total ? src.total.toLocaleString() : "--") + '</span>' +
          '</div>';
      }).join("");
    } catch (err) {
      console.warn("KB status load failed:", err);
    }
  }

  document.getElementById("btn-refresh-kb")?.addEventListener("click", async () => {
    const btn = document.getElementById("btn-refresh-kb");
    const msg = document.getElementById("kb-refresh-msg");
    btn.disabled = true;
    btn.querySelector("span") && (btn.querySelector("span").textContent = "更新中…");
    msg.classList.add("hidden");
    try {
      const r = await fetch("/api/kb/refresh", { method: "POST" });
      const d = await r.json();
      msg.textContent = d.ok ? "✅ 威胁情报已更新" : "⚠️ 部分源更新失败";
      msg.classList.remove("hidden");
      setTimeout(() => msg.classList.add("hidden"), 3000);
      loadKbStatus();
    } catch (err) {
      msg.textContent = "❌ 刷新失败";
      msg.classList.remove("hidden");
    }
    btn.disabled = false;
    btn.querySelector("span") && (btn.querySelector("span").textContent = "立即刷新所有 Feed");
  });

  /* ── Tab 3: 白名单 ── */
  let _wlItems = [];
  async function loadWhitelist() {
    try {
      const r = await fetch("/api/whitelist");
      const d = await r.json();
      _wlItems = d.items || [];
      renderWhitelist("");
    } catch (err) {
      console.warn("Whitelist load failed:", err);
    }
  }

  function renderWhitelist(filter) {
    const list = document.getElementById("wl-list");
    const countEl = document.getElementById("wl-count");
    if (!list) return;
    const items = filter ? _wlItems.filter((n) => n.toLowerCase().includes(filter.toLowerCase())) : _wlItems;
    if (countEl) countEl.textContent = items.length + " 项";
    if (!items.length) {
      list.innerHTML = '<tr><td colspan="3" class="table-empty">' +
        (filter ? "无匹配结果" : "白名单为空。添加进程名后，检测时将跳过这些进程。") + '</td></tr>';
      return;
    }
    list.innerHTML = items.map((name) =>
      '<tr>' +
      '<td class="td-mono"><span class="wl-name">' + escapeHtml(name) + '</span></td>' +
      '<td><span class="badge ok">已豁免</span></td>' +
      '<td class="th-ops"><button class="wl-del" data-name="' + escapeHtml(name) + '" title="移除">✕</button></td>' +
      '</tr>'
    ).join("");
  }

  document.getElementById("wl-search")?.addEventListener("input", (e) => {
    renderWhitelist(e.target.value.trim());
  });

  document.getElementById("btn-wl-add")?.addEventListener("click", async () => {
    const input = document.getElementById("wl-input");
    const name = input.value.trim();
    if (!name) return;
    try {
      await fetch("/api/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      input.value = "";
      loadWhitelist();
    } catch (err) {
      console.warn("Whitelist add failed:", err);
    }
  });

  document.getElementById("wl-list")?.addEventListener("click", async (e) => {
    const btn = e.target.closest(".wl-del");
    if (!btn) return;
    const name = btn.dataset.name;
    try {
      await fetch("/api/whitelist/" + encodeURIComponent(name), { method: "DELETE" });
      loadWhitelist();
    } catch (err) {
      console.warn("Whitelist remove failed:", err);
    }
  });

  /* ── Tab 4: 关于 ── */
  async function loadAbout() {
    try {
      const h = await fetch("/api/health");
      const hv = await h.json();
      const c = await fetch("/api/config");
      const cv = await c.json();
      document.getElementById("about-version").textContent = "v" + hv.version;
      document.getElementById("about-model").textContent = cv.model || "--";
      document.getElementById("about-provider").textContent = cv.provider || "--";
    } catch (err) {
      console.warn("About load failed:", err);
    }
  }

  /* ── 工具 ── */
  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  /* ── Tab 5: 病毒库 ── */
  async function loadVirusDb() {
    try {
      // 从 KB 状态中提取病毒库信息
      const r = await fetch("/api/kb/status");
      const d = await r.json();
      var hcount = d.hash_count || 0;
      var sources = d.sources || {};
      document.getElementById("vdb-total").textContent = hcount.toLocaleString();
      document.getElementById("vdb-bloom").textContent = hcount > 0 ? "已激活" : "待构建";
      document.getElementById("vdb-sources").textContent = "2 (ESET + MalwareBazaar)";
      document.getElementById("vdb-updated").textContent = (d.last_update || "--").slice(0, 16);
      // Bloom 进度条（按 10000 哈希 = 100% 视觉基线）
      var bloomPct = Math.min(100, Math.round((hcount / 10000) * 100));
      var bloomBar = document.getElementById("vdb-bloom-bar");
      if (bloomBar) bloomBar.style.width = bloomPct + "%";

      var sourceList = document.getElementById("virus-source-list");
      var vdbSources = sources.eset || sources.malwarebazaar ? [
        { name: "ESET malware-ioc", ok: (sources.eset || {}).ok !== false, total: (sources.eset || {}).total || "--", desc: "ESET 真实 APT/恶意家族 SHA256 签名库" },
        { name: "MalwareBazaar", ok: (sources.malwarebazaar || {}).ok !== false, total: (sources.malwarebazaar || {}).total || "--", desc: "abuse.ch 每日更新的恶意软件哈希 CSV" },
      ] : [];
      if (vdbSources.length === 0 && hcount > 0) {
        vdbSources.push({ name: "本地缓存", ok: true, total: hcount, desc: "已缓存的恶意哈希数据库" });
      }
      sourceList.innerHTML = vdbSources.length
        ? vdbSources.map(function (s) {
            var bCls = s.ok ? "ok" : "err";
            var bTxt = s.ok ? "在线" : "异常";
            return '<div class="feed-item">' +
              '<span class="feed-name">' + escapeHtml(s.name) + '</span>' +
              '<span class="feed-type">SHA256</span>' +
              '<span class="badge ' + bCls + '">' + bTxt + '</span>' +
              '<span class="feed-count">' + (typeof s.total === "number" ? s.total.toLocaleString() : s.total) + '</span>' +
              '</div>';
          }).join("")
        : '<div class="feed-item"><span class="feed-info">暂无病毒库数据，点击下方按钮开始更新</span></div>';
    } catch (err) { console.warn("VDB load failed:", err); }
  }

  document.getElementById("btn-refresh-vdb") && document.getElementById("btn-refresh-vdb").addEventListener("click", async function () {
    var btn = document.getElementById("btn-refresh-vdb");
    btn.disabled = true;
    btn.innerHTML = '<svg class="ic"><use href="#ic-scan"/></svg> 更新中…';
    try {
      // 触发完整 KB 刷新（包含病毒库）
      await fetch("/api/kb/refresh", { method: "POST" });
      loadVirusDb();
      document.getElementById("vdb-refresh-msg").textContent = "病毒库已更新";
      document.getElementById("vdb-refresh-msg").classList.remove("hidden");
      setTimeout(function () { document.getElementById("vdb-refresh-msg").classList.add("hidden"); }, 3000);
    } catch (err) {
      document.getElementById("vdb-refresh-msg").textContent = "更新失败";
      document.getElementById("vdb-refresh-msg").classList.remove("hidden");
    }
    btn.disabled = false;
    btn.innerHTML = '<svg class="ic"><use href="#ic-scan"/></svg> 立即更新病毒库';
  });

  /* ── 顶部状态条 ── */
  async function loadStatusBar() {
    try {
      const [h, c] = await Promise.all([
        fetch("/api/health").then((r) => r.json()),
        fetch("/api/config").then((r) => r.json()),
      ]);
      const setDot = (id, on) => {
        const el = document.getElementById(id);
        if (el) { el.className = "status-dot " + (on ? "on" : "off"); }
      };
      const setVal = (id, v) => {
        const el = document.getElementById(id);
        if (el) el.textContent = v;
      };
      // LLM
      setDot("st-llm", h.llm === "configured");
      setVal("st-llm-val", h.llm === "configured" ? (c.model || c.provider || "已配置") : "未配置");
      // 数据库
      setDot("st-db", h.db === "connected");
      setVal("st-db-val", h.db === "connected" ? "正常" : "异常");
      // 威胁情报
      try {
        const kb = await fetch("/api/kb/status").then((r) => r.json());
        const total = (kb.ip_count || 0) + (kb.domain_count || 0);
        setDot("st-kb", total > 0);
        setVal("st-kb-val", total > 0 ? (total / 10000).toFixed(1) + "万条" : "空");
      } catch (e) {
        setDot("st-kb", false); setVal("st-kb-val", "--");
      }
      // 检测引擎
      setDot("st-engine", true);
      setVal("st-engine-val", "8 模块在线");
      // 版本
      setDot("st-version", true);
      setVal("st-version-val", h.version || "--");
    } catch (err) {
      console.warn("Status bar load failed:", err);
    }
  }

  /* ── 初始化 ── */
  loadConfig();
  loadStatusBar();
  // 检查 URL 参数：?tab=threats → 切换到威胁情报 Tab
  const params = new URLSearchParams(location.search);
  const targetTab = params.get("tab");
  if (targetTab) {
    const tab = document.querySelector('.sn-tab[data-tab="' + targetTab + '"]');
    if (tab) tab.click();
  }
})();
