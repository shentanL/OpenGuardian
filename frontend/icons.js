/* OpenGuardian 自定义 SVG 图标库（安全主题线性图标）
 * 设计：2px stroke、圆头端点、24×24 viewBox
 * 用法：<svg class="ic"><use href="#ic-shield"/></svg>
 */
const ICONS = `
<svg xmlns="http://www.w3.org/2000/svg" style="display:none">
  <!-- 盾牌（品牌） -->
  <symbol id="ic-shield" viewBox="0 0 24 24">
    <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
    <path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </symbol>
  <!-- 雷达（检测） -->
  <symbol id="ic-radar" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="12" cy="12" r="5" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.5"/>
    <path d="M12 12L19 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    <circle cx="12" cy="12" r="1.6" fill="currentColor"/>
  </symbol>
  <!-- 锁（资产/密码） -->
  <symbol id="ic-lock" viewBox="0 0 24 24">
    <rect x="5" y="11" width="14" height="9" rx="1" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M8 11V8a4 4 0 018 0v3" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="12" cy="15.5" r="1.3" fill="currentColor"/>
  </symbol>
  <!-- 终端（执行/处置） -->
  <symbol id="ic-term" viewBox="0 0 24 24">
    <rect x="3" y="4" width="18" height="16" rx="1" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M7 9l3 3-3 3M13 15h4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </symbol>
  <!-- 书（教育） -->
  <symbol id="ic-book" viewBox="0 0 24 24">
    <path d="M4 5a2 2 0 012-2h14v16H6a2 2 0 00-2 2V5z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
    <path d="M4 19a2 2 0 012-2h14" fill="none" stroke="currentColor" stroke-width="2"/>
  </symbol>
  <!-- 对话（助手） -->
  <symbol id="ic-chat" viewBox="0 0 24 24">
    <path d="M4 6a2 2 0 012-2h12a2 2 0 012 2v8a2 2 0 01-2 2H9l-5 4V6z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
    <path d="M8 9h8M8 12h5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
  <!-- 仪表盘（监控） -->
  <symbol id="ic-gauge" viewBox="0 0 24 24">
    <path d="M4 18a8 8 0 1116 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    <path d="M12 14l3-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    <circle cx="12" cy="14.5" r="1.4" fill="currentColor"/>
  </symbol>
  <!-- 加号（新建） -->
  <symbol id="ic-plus" viewBox="0 0 24 24">
    <path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
  </symbol>
  <!-- 删除 -->
  <symbol id="ic-trash" viewBox="0 0 24 24">
    <path d="M4 7h16M10 7V5a1 1 0 011-1h2a1 1 0 011 1v2M7 7l1 13a1 1 0 001 1h6a1 1 0 001-1l1-13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </symbol>
  <!-- 警告三角（风险） -->
  <symbol id="ic-alert" viewBox="0 0 24 24">
    <path d="M12 4L2.5 20h19L12 4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
    <path d="M12 10v5M12 18v.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
  <!-- 复制 -->
  <symbol id="ic-copy" viewBox="0 0 24 24">
    <rect x="9" y="9" width="11" height="11" rx="1" fill="none" stroke="currentColor" stroke-width="1.7"/>
    <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" fill="none" stroke="currentColor" stroke-width="1.7"/>
  </symbol>
  <!-- 检查（安全/成功） -->
  <symbol id="ic-check" viewBox="0 0 24 24">
    <path d="M5 13l4 4 10-11" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </symbol>
  <!-- 危险（处置） -->
  <symbol id="ic-bolt" viewBox="0 0 24 24">
    <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  </symbol>
  <!-- 网络节点（外联检测） -->
  <symbol id="ic-net" viewBox="0 0 24 24">
    <circle cx="12" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="5" cy="19" r="2" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="19" cy="19" r="2" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M12 7v5M5 17l2-3 5 2M19 17l-2-3-5 2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </symbol>
  <!-- 扫描线（资源监控） -->
  <symbol id="ic-scan" viewBox="0 0 24 24">
    <path d="M3 8V5a2 2 0 012-2h3M16 3h3a2 2 0 012 2v3M21 16v3a2 2 0 01-2 2h-3M8 21H5a2 2 0 01-2-2v-3" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    <path d="M3 12h18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
  <!-- 发送 -->
  <symbol id="ic-send" viewBox="0 0 24 24">
    <path d="M3 11l18-8-8 18-2.5-7.5L3 11z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
  </symbol>
  <!-- CPU 芯片（进程） -->
  <symbol id="ic-cpu" viewBox="0 0 24 24">
    <rect x="7" y="7" width="10" height="10" rx="1" fill="none" stroke="currentColor" stroke-width="2"/>
    <rect x="10.5" y="10.5" width="3" height="3" fill="currentColor"/>
    <path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
  <!-- 历史时钟 -->
  <symbol id="ic-clock" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M12 7v5l3 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
  <!-- 齿轮（设置） -->
  <symbol id="ic-settings" viewBox="0 0 24 24">
    <circle cx="12" cy="12" r="2.5" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </symbol>
</svg>`;

function ic(name, cls) {
  return `<svg class="ic ${cls || ""}" aria-hidden="true"><use href="#${name}"/></svg>`;
}
