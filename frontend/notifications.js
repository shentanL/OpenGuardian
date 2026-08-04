/* OpenGuardian 企业级通知系统 */
(function () {
  "use strict";

  const container = document.createElement("div");
  container.id = "og-notifications";
  container.style.cssText = "position:fixed;top:16px;right:16px;z-index:9999;display:flex;flex-direction:column;gap:8px;max-width:380px;pointer-events:none;";
  document.body.appendChild(container);

  const ICONS = {
    critical: "ic-bolt",
    high: "ic-alert",
    medium: "ic-alert",
    low: "ic-check",
    info: "ic-book",
    success: "ic-check",
  };

  const COLORS = {
    critical: "#e52020",
    high: "#df6500",
    medium: "#bff230",
    low: "#76b900",
    info: "#4da6ff",
    success: "#76b900",
  };

  window.OGNotify = {
    /**
     * 弹出 Toast 通知。
     * @param {"critical"|"high"|"medium"|"low"|"info"|"success"} level
     * @param {string} title
     * @param {string} [message]
     * @param {Object} [opts] — {duration: ms, action: {label, callback}, sound: bool}
     */
    toast(level, title, message, opts = {}) {
      const duration = opts.duration || (level === "critical" ? 8000 : 5000);
      const color = COLORS[level] || COLORS.info;

      const el = document.createElement("div");
      el.style.cssText = `pointer-events:auto;background:rgba(13,13,13,0.96);border:1px solid ${color}40;border-left:3px solid ${color};border-radius:2px;padding:12px 16px;font-family:-apple-system,"Microsoft YaHei",sans-serif;font-size:12px;color:#e0e0e0;box-shadow:0 4px 24px rgba(0,0,0,0.6);animation:og-slide-in 0.25s ease-out;opacity:1;transition:opacity 0.3s,transform 0.3s;position:relative;overflow:hidden;`;

      // 进度条
      const bar = document.createElement("div");
      bar.style.cssText = `position:absolute;bottom:0;left:0;height:2px;background:${color};transition:width ${duration}ms linear;width:100%;`;
      el.appendChild(bar);

      // 标题行
      const titleRow = document.createElement("div");
      titleRow.style.cssText = "display:flex;align-items:center;gap:8px;margin-bottom:2px;";
      const dot = document.createElement("span");
      dot.style.cssText = `width:8px;height:8px;border-radius:50%;background:${color};flex-shrink:0;`;
      titleRow.appendChild(dot);
      const titleSpan = document.createElement("span");
      titleSpan.style.cssText = "font-weight:700;color:white;";
      titleSpan.textContent = title;
      titleRow.appendChild(titleSpan);
      el.appendChild(titleRow);

      // 消息体
      if (message) {
        const msgEl = document.createElement("div");
        msgEl.style.cssText = "margin-top:4px;color:#a7a7a7;line-height:1.5;";
        msgEl.textContent = message;
        el.appendChild(msgEl);
      }

      // 操作按钮
      if (opts.action) {
        const btn = document.createElement("button");
        btn.textContent = opts.action.label || "处理";
        btn.style.cssText = `margin-top:8px;padding:4px 12px;background:${color}20;border:1px solid ${color}50;border-radius:2px;color:${color};font-size:11px;cursor:pointer;font-weight:600;`;
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          if (opts.action.callback) opts.action.callback();
          dismiss();
        });
        el.appendChild(btn);
      }

      container.appendChild(el);

      // 自动消失
      let dismissed = false;
      const dismiss = () => {
        if (dismissed) return;
        dismissed = true;
        el.style.opacity = "0";
        el.style.transform = "translateX(40px)";
        setTimeout(() => el.remove(), 300);
      };

      el.addEventListener("click", () => {
        if (!opts.action) dismiss();
      });

      setTimeout(dismiss, duration);
      // 进度条动画
      requestAnimationFrame(() => { bar.style.width = "0%"; });

      return { dismiss };
    },

    /** 威胁告警快捷方法 */
    threat(level, title, message, pid) {
      return this.toast(level, title, message, {
        duration: level === "critical" ? 12000 : 8000,
        action: pid ? {
          label: `结束进程 (PID ${pid})`,
          callback: () => {
            fetch("/api/execute", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pid, action: "terminate" }),
            }).then(r => r.json()).then(d => {
              window.OGNotify.toast(d.success ? "success" : "info",
                d.success ? "进程已结束" : "操作结果", d.message);
            });
          },
        } : undefined,
      });
    },
  };

  // CSS 动画
  const style = document.createElement("style");
  style.textContent = `
    @keyframes og-slide-in {
      from { opacity: 0; transform: translateX(60px); }
      to { opacity: 1; transform: translateX(0); }
    }
  `;
  document.head.appendChild(style);
})();
