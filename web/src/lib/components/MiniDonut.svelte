<script>
let { pct, grade, size = 48 } = $props();
const r = (size - 6) / 2;
const c = 2 * Math.PI * r;
const dash = (pct / 100) * c;
const colors = { A: "var(--hd-green-600)", B: "var(--hd-green-500)", C: "#f59e0b", D: "#e5484d", F: "#dc2626" };
</script>
<div class="wrap" style="width:{size}px;height:{size}px">
<svg width={size} height={size} viewBox="0 0 {size} {size}">
<circle cx={size/2} cy={size/2} r={r} stroke="var(--hd-bg-inset)" stroke-width="3" fill="none"></circle>
<circle cx={size/2} cy={size/2} r={r} stroke={colors[grade]} stroke-width="3" fill="none" stroke-dasharray="{dash} {c}" stroke-linecap="round" transform="rotate(-90 {size/2} {size/2})"></circle>
</svg>
<span class="g" style="color:{colors[grade]}">{grade}</span>
</div>
<style>
.wrap{position:relative}
.g{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--hd-font-brand);font-weight:700;font-size:18px;letter-spacing:-0.02em}
</style>
