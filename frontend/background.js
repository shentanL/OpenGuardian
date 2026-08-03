/* OpenGuardian 粒子网络背景（自研，参考 particles.js ⭐30k 设计）
 * 效果：节点粒子缓慢漂移 + 近距连线 + 鼠标引力交互
 * 风格：NVIDIA 绿（#76b900 系），深底荧光网络
 * 性能：粒子数自适应屏幕，requestAnimationFrame，页面隐藏时暂停
 */
(function () {
  const canvas = document.getElementById("bg-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const COLOR = "118,185,0";       // NVIDIA 绿 RGB
  const LINK_DIST = 130;           // 连线距离
  const MOUSE_DIST = 160;          // 鼠标交互距离
  const MAX_PARTICLES = 70;

  let W = 0, H = 0, particles = [];
  let mouse = { x: -9999, y: -9999 };
  let rafId = null;
  let running = true;

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
    const count = Math.min(Math.max(Math.floor((W * H) / 22000), 24), MAX_PARTICLES);
    particles = [];
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.55,
        vy: (Math.random() - 0.5) * 0.55,
        r: Math.random() * 1.6 + 0.8,
      });
    }
  }

  function tick() {
    if (!running) return;
    ctx.clearRect(0, 0, W, H);

    // 移动粒子
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -20) p.x = W + 20; else if (p.x > W + 20) p.x = -20;
      if (p.y < -20) p.y = H + 20; else if (p.y > H + 20) p.y = -20;
    }

    // 连线（粒子间 + 粒子-鼠标）
    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist2 = dx * dx + dy * dy;
        if (dist2 < LINK_DIST * LINK_DIST) {
          const alpha = (1 - Math.sqrt(dist2) / LINK_DIST) * 0.35;
          ctx.strokeStyle = `rgba(${COLOR},${alpha.toFixed(3)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      // 粒子-鼠标连线
      const mdx = a.x - mouse.x, mdy = a.y - mouse.y;
      const mdist2 = mdx * mdx + mdy * mdy;
      if (mdist2 < MOUSE_DIST * MOUSE_DIST) {
        const alpha = (1 - Math.sqrt(mdist2) / MOUSE_DIST) * 0.5;
        ctx.strokeStyle = `rgba(${COLOR},${alpha.toFixed(3)})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }
    }

    // 粒子本体（光晕点）
    for (const p of particles) {
      ctx.fillStyle = `rgba(${COLOR},0.85)`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    }

    rafId = requestAnimationFrame(tick);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("mousemove", (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
  document.addEventListener("mouseleave", () => { mouse.x = -9999; mouse.y = -9999; });
  // 页面隐藏时暂停（省电）
  document.addEventListener("visibilitychange", () => {
    running = !document.hidden;
    if (running) {
      rafId = requestAnimationFrame(tick);
    } else if (rafId) {
      cancelAnimationFrame(rafId);
    }
  });

  resize();
  rafId = requestAnimationFrame(tick);
})();
