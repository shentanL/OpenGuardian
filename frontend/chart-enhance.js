/* OpenGuardian 增强图表渲染 — 覆盖默认 renderResChart */

(function () {
  "use strict";

  // 等待 app.js 加载完成后覆盖
  function patch() {
    if (typeof renderResChart === "undefined") {
      setTimeout(patch, 50);
      return;
    }

    // 新的增强版渲染（覆盖 app.js 中的默认实现）
    window.renderResChart = function (samples) {
      var svg = document.getElementById("res-chart");
      if (!svg) return;
      svg._samples = samples;

      var legendEl = document.querySelector(".legend");
      if (!samples || samples.length < 2) {
        svg.innerHTML = '<text x="200" y="80" text-anchor="middle" fill="#757575" font-size="12" font-family="monospace">采集数据中…</text>';
        if (legendEl) legendEl.innerHTML = '<span class="lg lg-cpu"><i class="sw sw-cpu"></i>CPU <b>--%</b></span><span class="lg lg-mem"><i class="sw sw-mem"></i>MEM <b>--%</b></span><span class="lg lg-disk"><i class="sw sw-disk"></i>DISK <b>--%</b></span>';
        return;
      }

      // 自适应宽度：取 SVG 元素实际宽度或 720px
      var rect = svg.getBoundingClientRect();
      var W = Math.max(rect.width || 720, 400);
      var H = 180, PAD = 16;
      var n = samples.length, last = samples[n - 1];
      var xn = function (i) { return PAD + (i * (W - 2 * PAD)) / Math.max(n - 1, 1); };
      var yn = function (v) { return H - PAD - (v / 100) * (H - 2 * PAD); };

      var smooth = function (key) {
        var pts = samples.map(function (s, i) { return { x: xn(i), y: yn(s[key]) }; });
        if (pts.length < 2) return "";
        var d = "M" + pts[0].x.toFixed(1) + "," + pts[0].y.toFixed(1);
        for (var i = 0; i < pts.length - 1; i++) {
          var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
          d += " C" + (p1.x + (p2.x - p0.x) / 6).toFixed(1) + "," + (p1.y + (p2.y - p0.y) / 6).toFixed(1) + " " + (p2.x - (p3.x - p1.x) / 6).toFixed(1) + "," + (p2.y - (p3.y - p1.y) / 6).toFixed(1) + " " + p2.x.toFixed(1) + "," + p2.y.toFixed(1);
        }
        return d;
      };

      var stats = function (key) {
        var vals = samples.map(function (s) { return s[key]; });
        return { avg: vals.reduce(function (a, b) { return a + b; }, 0) / vals.length, max: Math.max.apply(null, vals), min: Math.min.apply(null, vals) };
      };
      var stCpu = stats("cpu"), stMem = stats("mem"), stDisk = stats("disk");

      var s = '<defs>' +
        '<linearGradient id="grad-cpu" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#76b900" stop-opacity="0.35"/><stop offset="100%" stop-color="#76b900" stop-opacity="0.02"/></linearGradient>' +
        '<linearGradient id="grad-mem" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#bff230" stop-opacity="0.3"/><stop offset="100%" stop-color="#bff230" stop-opacity="0.02"/></linearGradient>' +
        '<linearGradient id="grad-disk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#a7a7a7" stop-opacity="0.22"/><stop offset="100%" stop-color="#a7a7a7" stop-opacity="0.02"/></linearGradient>' +
        '</defs>';

      // 85% 阈值带
      s += '<rect x="' + PAD + '" y="' + yn(100) + '" width="' + (W - 2 * PAD) + '" height="' + (yn(85) - yn(100)) + '" fill="rgba(223,101,0,0.06)"/>';
      s += '<line x1="' + PAD + '" y1="' + yn(85) + '" x2="' + (W - PAD) + '" y2="' + yn(85) + '" stroke="#df6500" stroke-width="1" stroke-dasharray="5,3" opacity="0.7"/>';
      s += '<text x="' + (PAD + 4) + '" y="' + (yn(85) - 3) + '" fill="#df6500" font-size="8" opacity="0.8">85%</text>';

      // 网格线 + Y 轴标签
      for (var vi = 0; vi <= 100; vi += 25) {
        s += '<line x1="' + PAD + '" y1="' + yn(vi) + '" x2="' + (W - PAD) + '" y2="' + yn(vi) + '" stroke="#1f1f1f" stroke-width="0.5"/>';
        s += '<text x="' + (W - PAD - 2) + '" y="' + (yn(vi) + 3) + '" fill="#555" font-size="8" text-anchor="end">' + vi + '%</text>';
      }

      // X 轴时间刻度
      var tStep = Math.max(Math.floor(n / 5), 1);
      for (var ti = 0; ti < n; ti += tStep) {
        s += '<text x="' + xn(ti) + '" y="' + (H - 2) + '" fill="#555" font-size="7" text-anchor="middle">' + ((samples[ti].time || "").slice(11, 19)) + '</text>';
      }

      // 折线 + 面积 + 圆点 + 值标签
      var series = [["cpu", "#76b900", "dot-cpu", false], ["mem", "#bff230", "dot-mem", false], ["disk", "#a7a7a7", "dot-disk", true]];
      for (var si = 0; si < series.length; si++) {
        var key = series[si][0], color = series[si][1], cls = series[si][2], dashed = series[si][3];
        var sp = smooth(key);
        s += '<polygon points="' + sp + ' L' + xn(n - 1).toFixed(1) + ',' + (H - PAD) + ' L' + xn(0).toFixed(1) + ',' + (H - PAD) + ' Z" fill="url(#grad-' + key + ')"/>';
        s += '<path d="' + sp + '" fill="none" stroke="' + color + '" stroke-width="' + (dashed ? 1.5 : 2) + '"' + (dashed ? ' stroke-dasharray="4,2"' : '') + ' stroke-linecap="round" stroke-linejoin="round"/>';
        s += '<circle cx="' + xn(n - 1).toFixed(1) + '" cy="' + yn(last[key]).toFixed(1) + '" r="4" fill="#000" stroke="' + color + '" stroke-width="2.5" class="' + cls + '"/>';
        s += '<text x="' + (xn(n - 1) + 10).toFixed(1) + '" y="' + (yn(last[key]) - 6).toFixed(1) + '" fill="' + color + '" font-size="10" font-weight="800" font-family="ui-monospace,monospace">' + last[key].toFixed(1) + '%</text>';
      }

      svg.innerHTML = s;

      // 图例
      if (legendEl) {
        legendEl.innerHTML =
          '<span class="lg lg-cpu"><i class="sw sw-cpu"></i>CPU <b>' + last.cpu.toFixed(1) + '%</b><em>avg ' + stCpu.avg.toFixed(1) + '%  max ' + stCpu.max.toFixed(1) + '%</em></span>' +
          '<span class="lg lg-mem"><i class="sw sw-mem"></i>MEM <b>' + last.mem.toFixed(1) + '%</b><em>avg ' + stMem.avg.toFixed(1) + '%  max ' + stMem.max.toFixed(1) + '%</em></span>' +
          '<span class="lg lg-disk"><i class="sw sw-disk"></i>DISK <b>' + last.disk.toFixed(1) + '%</b><em>avg ' + stDisk.avg.toFixed(1) + '%  max ' + stDisk.max.toFixed(1) + '%</em></span>';
      }
    };

    // 也覆盖全局 WebSocket 重绘函数
    window._renderResChart = function (samps) {
      if (samps && samps.length) window.renderResChart(samps);
    };

    // 监听窗口尺寸变化重新渲染
    window.addEventListener("resize", function () {
      var svg = document.getElementById("res-chart");
      if (svg && svg._samples && svg._samples.length > 1) {
        window.renderResChart(svg._samples);
      }
    });

    console.log("Chart enhancer patched");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { setTimeout(patch, 100); });
  } else {
    setTimeout(patch, 100);
  }
})();
