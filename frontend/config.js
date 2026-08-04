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
  const providerSel = document.getElementById("provider-select");
  const modelSel = document.getElementById("model-select");
  const apiInput = document.getElementById("api-key");
  const customUrl = document.getElementById("custom-url");
  const customUrlGroup = document.getElementById("custom-url-group");
  const apiKeyGroup = document.getElementById("api-key-group");
  const keyHint = document.getElementById("key-hint");
  const providerDesc = document.getElementById("provider-desc");
  const btnSave = document.getElementById("btn-save-provider");
  const msgEl = document.getElementById("provider-msg");
  const toggleBtn = document.getElementById("toggle-key");

  let providers = [];
  let _loadedModel = "";

  toggleBtn?.addEventListener("click", () => {
    apiInput.type = apiInput.type === "password" ? "text" : "password";
  });

  function showMsg(text, ok) {
    msgEl.textContent = text;
    msgEl.className = "form-msg " + (ok ? "success" : "error");
    msgEl.classList.remove("hidden");
    setTimeout(() => msgEl.classList.add("hidden"), 4000);
  }

  async function loadConfig() {
    try {
      const r = await fetch("/api/config");
      const d = await r.json();
      providers = d.providers || [];

      providerSel.innerHTML = providers.map((p) =>
        '<option value="' + p.key + '" ' + (p.key === d.provider ? "selected" : "") + ">" + p.name + "</option>"
      ).join("");

      updateProviderUI(providers.find((p) => p.key === d.provider));

      if (d.configured) {
        apiInput.placeholder = "已配置（留空保持不变）";
        apiInput.value = "";
        btnSave.querySelector("span") && (btnSave.querySelector("span").textContent = "保存设置");
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

  function updateProviderUI(p) {
    if (!p) return;
    providerDesc.textContent = p.description || "";
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

  providerSel?.addEventListener("change", () => {
    updateProviderUI(providers.find((p) => p.key === providerSel.value));
    btnSave.disabled = false;
  });

  btnSave?.addEventListener("click", async () => {
    const provider = providerSel.value;
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
        return '<div class="feed-item">' +
          '<div class="feed-status ' + (ok ? "ok" : "err") + '"></div>' +
          '<span class="feed-name">' + escapeHtml(f.name) + '</span>' +
          '<span class="feed-type">' + escapeHtml(f.type || f.ioc_type || "") + '</span>' +
          '<span class="feed-info">' + escapeHtml(f.description || "") + '</span>' +
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
  async function loadWhitelist() {
    try {
      const r = await fetch("/api/whitelist");
      const d = await r.json();
      const list = document.getElementById("wl-list");
      const items = d.items || [];
      if (!items.length) {
        list.innerHTML = '<div class="wl-empty">白名单为空。添加进程名后，检测时将跳过这些进程。</div>';
        return;
      }
      list.innerHTML = items.map((name) =>
        '<div class="wl-item">' +
        '<span class="wl-name">' + escapeHtml(name) + '</span>' +
        '<button class="wl-del" data-name="' + escapeHtml(name) + '">✕</button>' +
        '</div>'
      ).join("");
    } catch (err) {
      console.warn("Whitelist load failed:", err);
    }
  }

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
            return '<div class="feed-item">' +
              '<div class="feed-status ' + (s.ok ? "ok" : "err") + '"></div>' +
              '<span class="feed-name">' + escapeHtml(s.name) + '</span>' +
              '<span class="feed-type">SHA256</span>' +
              '<span class="feed-info">' + escapeHtml(s.desc) + '</span>' +
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

  /* ── 初始化 ── */
  loadConfig();
  // 检查 URL 参数：?tab=threats → 切换到威胁情报 Tab
  const params = new URLSearchParams(location.search);
  const targetTab = params.get("tab");
  if (targetTab) {
    const tab = document.querySelector('.sn-tab[data-tab="' + targetTab + '"]');
    if (tab) tab.click();
  }
})();
