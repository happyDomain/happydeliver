<script>
let { pct, grade, size = 210 } = $props();
const r = (size - 16) / 2;
const c = 2 * Math.PI * r;
const dash = (pct / 100) * c;
const colors = { A: "#22d3a3", B: "#56c8a4", C: "#fbbf24", D: "#f87171", F: "#dc2626" };
</script>
<svg width={size} height={size} viewBox="0 0 {size} {size}" style="display:block">
<circle cx={size/2} cy={size/2} r={r} stroke="rgba(255,255,255,0.12)" stroke-width="10" fill="none"></circle>
<circle cx={size/2} cy={size/2} r={r} stroke={colors[grade]} stroke-width="10" fill="none" stroke-dasharray="{dash} {c}" stroke-linecap="round" transform="rotate(-90 {size/2} {size/2})"></circle>
<text x={size/2} y={size/2 - 4} text-anchor="middle" font-family="var(--hd-font-brand)" font-weight="700" font-size={size * 0.40} fill="var(--hd-brand-dark-fg)" dominant-baseline="middle" style="letter-spacing:-0.04em">{grade}</text>
<text x={size/2} y={size/2 + size*0.22} text-anchor="middle" font-family="var(--hd-font-mono)" font-size="13" fill="var(--hd-brand-dark-muted)">{pct} / 100</text>
</svg>
