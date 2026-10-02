import { createHash } from 'node:crypto';
import { escapeHtml as e } from './security.js';

// Shared UI: design tokens, layout shell, icons, and the one inline script. Everything is inline so the
// CSP stays `default-src 'none'`: styles via 'unsafe-inline', the script pinned by its SHA-256 hash.

const STYLE = `:root{color-scheme:light dark;--bg:#f6f6f8;--surface:#fff;--surface-2:#f4f4f6;--border:#e4e4e8;--border-strong:#d2d2d8;
--text:#16161a;--muted:#6b6b76;--accent:#4f46e5;--accent-hover:#4338ca;--accent-soft:#eef0ff;--accent-text:#3730a3;
--green:#15803d;--green-soft:#ecfdf3;--amber:#a15c07;--amber-soft:#fef6e7;--red:#c42b2b;--red-soft:#fdeeee;--blue:#1d5fc4;--blue-soft:#eaf2fe;
--gray-soft:#f0f0f3;--radius:12px;--shadow:0 1px 2px rgba(16,16,24,.04),0 1px 3px rgba(16,16,24,.06);
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f12;--surface:#18181c;--surface-2:#202026;--border:#2a2a31;--border-strong:#3a3a43;
--text:#ececf1;--muted:#9a9aa6;--accent:#7c74ff;--accent-hover:#958fff;--accent-soft:#25234a;--accent-text:#c4c1ff;
--green:#4ade80;--green-soft:#11291b;--amber:#fbbf24;--amber-soft:#2d2210;--red:#f87171;--red-soft:#321617;--blue:#7cb0ff;--blue-soft:#14223a;
--gray-soft:#24242b;--shadow:0 1px 2px rgba(0,0,0,.3)}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;color:var(--text);background:var(--bg);margin:0;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
svg.i{width:16px;height:16px;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
.topbar .wrap{display:flex;align-items:center;gap:24px;min-height:60px}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.01em;color:var(--text)}
.brand:hover{text-decoration:none}
.logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:grid;place-items:center;color:#fff;flex:none}
.logo svg{width:16px;height:16px;stroke:#fff;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.tabsnav{display:flex;gap:4px;flex:1;min-width:0}
.tabsnav a{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;color:var(--muted);font-weight:500;min-height:40px}
.tabsnav a:hover{background:var(--surface-2);color:var(--text);text-decoration:none}
.tabsnav a[aria-current=page]{color:var(--text);background:var(--surface-2)}
.user{display:flex;align-items:center;gap:10px;margin-left:auto}
.avatar{width:30px;height:30px;border-radius:50%;background:var(--accent-soft);color:var(--accent-text);display:grid;place-items:center;font-weight:700;font-size:13px;text-transform:uppercase;flex:none}
.user .email{color:var(--muted);font-size:13px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main.wrap{padding-top:28px;padding-bottom:64px}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px 24px;margin-bottom:20px}
h1{font-size:24px;line-height:1.25;letter-spacing:-.02em;margin:0}
.sub{color:var(--muted);margin:4px 0 0;max-width:62ch}
h2{font-size:15px;margin:0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.card-pad{padding:20px}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;border-bottom:1px solid var(--border)}
.card-head p{margin:2px 0 0;color:var(--muted);font-size:13px}
.stack>*+*{margin-top:16px}
.btn{font:inherit;font-weight:600;font-size:14px;display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:8px 16px;border-radius:8px;border:1px solid transparent;cursor:pointer;white-space:nowrap;text-decoration:none;background:var(--accent);color:#fff}
.btn:hover{background:var(--accent-hover);text-decoration:none}
.btn-secondary{background:var(--surface);color:var(--text);border-color:var(--border-strong)}
.btn-secondary:hover{background:var(--surface-2)}
.btn-ghost{background:transparent;color:var(--muted)}
.btn-ghost:hover{background:var(--surface-2);color:var(--text)}
.btn-danger{background:transparent;color:var(--red);border-color:var(--border)}
.btn-danger:hover{background:var(--red-soft);border-color:var(--red)}
.btn-sm{min-height:32px;padding:4px 10px;font-size:13px;border-radius:7px}
.btn-block{width:100%}
label.field{display:flex;flex-direction:column;gap:6px;font-size:13px;font-weight:600;min-width:0}
label.field .hint{font-weight:400;color:var(--muted)}
input,select{font:inherit;font-size:14px;font-weight:400;min-height:40px;padding:8px 12px;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface);color:var(--text);width:100%;max-width:100%}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.form-row{display:grid;grid-template-columns:minmax(0,1fr) 180px auto;gap:12px;align-items:end}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;line-height:20px;white-space:nowrap;background:var(--gray-soft);color:var(--muted)}
.pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.new,.pill.active{background:var(--blue-soft);color:var(--blue)}
.pill.active{background:var(--green-soft);color:var(--green)}
.pill.triaged{background:var(--amber-soft);color:var(--amber)}
.pill.actioned{background:var(--green-soft);color:var(--green)}
.pill.dismissed,.pill.expired{background:var(--gray-soft);color:var(--muted)}
.pill.revoked{background:var(--red-soft);color:var(--red)}
.pill.cat{background:var(--accent-soft);color:var(--accent-text)}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.seg{display:inline-flex;flex-wrap:wrap;gap:2px;padding:3px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px}
.seg a,.seg button{font:inherit;font-size:13px;font-weight:600;color:var(--muted);background:transparent;border:0;border-radius:7px;padding:5px 12px;min-height:32px;display:inline-flex;align-items:center;gap:6px;cursor:pointer}
.seg a:hover,.seg button:hover{color:var(--text);text-decoration:none}
.seg [aria-current=page],.seg [aria-pressed=true]{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.filters select,.filters input{width:auto;min-width:150px;min-height:36px;padding:6px 10px;font-size:13px}
.js .filters .apply{display:none}
.feed{display:flex;flex-direction:column;gap:14px}
.fb{padding:0;overflow:hidden}
.fb-top{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:14px 20px;border-bottom:1px solid var(--border)}
.fb-top .src{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;min-width:0;overflow-wrap:anywhere}
.fb-top time{margin-left:auto;color:var(--muted);font-size:13px;white-space:nowrap}
.fb-body{display:grid;grid-template-columns:1fr 1fr}
.fb-body section{padding:16px 20px;min-width:0}
.fb-body section+section{border-left:1px solid var(--border);background:color-mix(in srgb,var(--accent-soft) 35%,transparent)}
.label{display:flex;align-items:center;gap:6px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
.prose{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.ctx{display:flex;flex-wrap:wrap;gap:6px 20px;margin:0;padding:12px 20px;border-top:1px solid var(--border);font-size:13px}
.ctx>div{display:flex;gap:6px;min-width:0;max-width:100%}
.ctx dt{color:var(--muted)}
.ctx dd{margin:0;min-width:0;overflow-wrap:anywhere;font-weight:500}
.fb-foot{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;padding:12px 20px;border-top:1px solid var(--border);background:var(--surface-2)}
.reqid{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);min-width:0}
.reqid code{font-family:var(--mono);overflow-wrap:anywhere}
.copy{display:none}
.js .copy{display:inline-flex}
.copy.copied{color:var(--green);border-color:var(--green)}
.empty{text-align:center;padding:56px 24px}
.empty .ico{width:48px;height:48px;border-radius:12px;background:var(--accent-soft);color:var(--accent-text);display:inline-grid;place-items:center;margin-bottom:12px}
.empty .ico svg{width:22px;height:22px}
.empty h2{font-size:16px;margin-bottom:4px}
.empty p{color:var(--muted);margin:0 auto 16px;max-width:44ch}
.pager{display:flex;justify-content:center;gap:8px;margin-top:20px}
.alert{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;border-radius:var(--radius);border:1px solid;margin-bottom:16px}
.alert.ok{background:var(--green-soft);border-color:color-mix(in srgb,var(--green) 30%,transparent);color:var(--text)}
.alert.err{background:var(--red-soft);border-color:color-mix(in srgb,var(--red) 30%,transparent);color:var(--text)}
.alert .i{margin-top:3px}
.alert.ok .i{color:var(--green)}.alert.err .i{color:var(--red)}
.reveal{border:1px solid color-mix(in srgb,var(--green) 35%,var(--border));background:linear-gradient(0deg,var(--surface),var(--green-soft));border-radius:var(--radius);padding:20px;margin-bottom:20px}
.reveal h2{display:flex;align-items:center;gap:8px;font-size:16px}
.reveal h2 .i{color:var(--green)}
.reveal p{margin:4px 0 14px;color:var(--muted)}
.secret{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border-strong);border-radius:10px;padding:6px 6px 6px 14px}
.secret code{flex:1;min-width:0;font-family:var(--mono);font-size:14px;overflow-wrap:anywhere}
.reveal .next{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.keys{list-style:none;margin:0;padding:0}
.keys li{display:grid;grid-template-columns:minmax(0,2.2fr) 1fr 1fr 1fr 96px;gap:16px;align-items:center;padding:14px 20px;border-top:1px solid var(--border)}
.keys li:first-child{border-top:0}
.keys li.hd{padding-top:10px;padding-bottom:10px;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;background:var(--surface-2)}
.keys .name{display:flex;align-items:center;gap:10px;min-width:0}
.keys .name b{font-weight:600;overflow-wrap:anywhere;min-width:0}
.keys .cell{font-size:13px;color:var(--muted)}
.keys .cell .k{display:none}
.keys .act{text-align:right}
.keys li.off .name b{color:var(--muted)}
.keyico{width:32px;height:32px;border-radius:8px;background:var(--surface-2);border:1px solid var(--border);display:grid;place-items:center;color:var(--muted);flex:none}
.steps{counter-reset:s;list-style:none;margin:0;padding:0}
.steps>li{position:relative;padding:0 0 28px 44px}
.steps>li:last-child{padding-bottom:0}
.steps>li:before{counter-increment:s;content:counter(s);position:absolute;left:0;top:0;width:28px;height:28px;border-radius:50%;background:var(--accent-soft);color:var(--accent-text);font-weight:700;font-size:13px;display:grid;place-items:center}
.steps>li:after{content:"";position:absolute;left:13.5px;top:34px;bottom:6px;width:1px;background:var(--border)}
.steps>li:last-child:after{display:none}
.steps h3{font-size:15px;margin:3px 0 4px}
.steps p{margin:0 0 12px;color:var(--muted)}
.code{position:relative;background:#111117;color:#e6e6ef;border-radius:10px;border:1px solid #23232b}
.code pre{margin:0;padding:14px 16px;padding-right:96px;font-family:var(--mono);font-size:13px;line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere}
.code .copy{position:absolute;top:8px;right:8px;background:#23232b;color:#e6e6ef;border-color:#33333d}
.code .copy:hover{background:#2e2e38}
.code .copy.copied{color:#4ade80;border-color:#4ade80}
.tabs{display:flex;flex-direction:column}
.tabs>input{position:absolute;opacity:0;pointer-events:none}
.tabs .tl{display:flex;flex-wrap:wrap;gap:2px;padding:3px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;align-self:flex-start;margin-bottom:12px}
.tabs .tl label{font-size:13px;font-weight:600;color:var(--muted);border-radius:7px;padding:5px 12px;cursor:pointer}
.tabs .panel{display:none}
.tabs .panel p{font-size:13px;margin:8px 0 0}
#t1:checked~.tl [for=t1],#t2:checked~.tl [for=t2],#t3:checked~.tl [for=t3],#t4:checked~.tl [for=t4]{background:var(--surface);color:var(--text);box-shadow:var(--shadow)}
#t1:focus-visible~.tl [for=t1],#t2:focus-visible~.tl [for=t2],#t3:focus-visible~.tl [for=t3],#t4:focus-visible~.tl [for=t4]{outline:2px solid var(--accent)}
#t1:checked~.p1,#t2:checked~.p2,#t3:checked~.p3,#t4:checked~.p4{display:block}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:13px;margin:0}
.kv dt{color:var(--muted)}.kv dd{margin:0;font-family:var(--mono);overflow-wrap:anywhere}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:20px;align-items:start}
.muted{color:var(--muted)}
.small{font-size:13px}
body.solo{min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:radial-gradient(1200px 600px at 50% -10%,var(--accent-soft),transparent 70%),var(--bg)}
.solo-card{width:100%;max-width:400px;padding:36px 32px;text-align:center}
.solo-card .logo{width:44px;height:44px;border-radius:12px;margin:0 auto 18px}
.solo-card .logo svg{width:22px;height:22px}
.solo-card h1{font-size:22px}
.solo-card .sub{margin:6px auto 24px}
.solo-card .alert{text-align:left;margin-bottom:20px}
.solo-card .fine{display:flex;align-items:center;justify-content:center;gap:6px;font-size:12px;color:var(--muted);margin:20px 0 0}
.gbtn{font:inherit;font-size:15px;font-weight:600;width:100%;min-height:46px;display:flex;align-items:center;justify-content:center;gap:12px;border-radius:10px;border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer;box-shadow:var(--shadow)}
.gbtn:hover{background:var(--surface-2)}
.gbtn svg{width:20px;height:20px;flex:none}
.solo-actions{display:flex;flex-direction:column;gap:8px}
@media (max-width:820px){.grid2{grid-template-columns:1fr}.keys li.hd{display:none}
.keys li{grid-template-columns:1fr auto;gap:6px 12px}.keys .name{grid-column:1/-1}.keys .act{grid-column:2;grid-row:2/5;align-self:end}
.keys .cell{grid-column:1}.keys .cell .k{display:inline}}
@media (max-width:680px){.wrap{padding:0 16px}.topbar .wrap{gap:8px;flex-wrap:wrap;padding-top:8px}
.tabsnav{order:3;flex-basis:100%;overflow-x:auto;padding-bottom:6px}.user .email{display:none}
main.wrap{padding-top:20px}h1{font-size:21px}.fb-body{grid-template-columns:1fr}
.fb-body section+section{border-left:0;border-top:1px solid var(--border)}.form-row{grid-template-columns:1fr}
.fb-top,.fb-body section,.ctx,.fb-foot,.card-head,.card-pad,.keys li{padding-left:16px;padding-right:16px}
.filters{width:100%}.filters select,.filters input{flex:1;min-width:0}
.toolbar>.seg{flex-wrap:nowrap;overflow-x:auto;max-width:100%}.toolbar>.seg a{flex:none;padding:5px 10px}
.fb-foot form,.fb-foot .seg{width:100%}.fb-foot .seg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));flex-wrap:nowrap}.fb-foot .seg button{justify-content:center;padding:5px 4px}}`;

// Progressive enhancement only; every page works without it. Kept free of interpolation so its hash
// is a constant.
const SCRIPT = `(()=>{const d=document;d.documentElement.classList.add('js');
d.addEventListener('click',async(ev)=>{const b=ev.target.closest('[data-copy]');if(!b)return;
const src=d.getElementById(b.dataset.copy);if(!src)return;const text=src.textContent.trim();
try{await navigator.clipboard.writeText(text)}catch{const r=d.createRange();r.selectNodeContents(src);const s=getSelection();s.removeAllRanges();s.addRange(r);try{d.execCommand('copy')}catch{}}
const l=b.querySelector('.copy-label');if(l){l.dataset.label??=l.textContent;l.textContent='Copied'}
b.classList.add('copied');clearTimeout(b._t);b._t=setTimeout(()=>{b.classList.remove('copied');if(l)l.textContent=l.dataset.label},1600)});
d.addEventListener('submit',(ev)=>{const m=ev.target.dataset.confirm;if(m&&!confirm(m))ev.preventDefault()});
d.querySelectorAll('[data-autosubmit]').forEach((el)=>el.addEventListener('change',()=>el.form.requestSubmit()));})();`;

export const SCRIPT_HASH = `'sha256-${createHash('sha256').update(SCRIPT).digest('base64')}'`;

// Lucide-style stroke icons, inlined.
const PATHS = {
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
  plug: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  alert: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
  bolt: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  bulb: '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>',
  bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
  wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
  arrow: '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
};
export const icon = (name) => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${PATHS[name]}</svg>`;
// Eye-in-rearview mark for HindSight.
const LOGO = '<span class="logo" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg></span>';
export const GOOGLE_G = '<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>';

export const copyButton = (targetId, label = 'Copy', cls = 'btn btn-secondary btn-sm') =>
  `<button type="button" class="copy ${cls}" data-copy="${e(targetId)}" aria-label="Copy to clipboard">${icon('copy')}<span class="copy-label" aria-live="polite">${e(label)}</span></button>`;

const NAV = [['/review', 'Inbox', 'inbox'], ['/tokens', 'API keys', 'key'], ['/connect', 'Connect', 'plug']];

const doc = (title, bodyAttrs, inner) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)} · HindSight</title>
<style>${STYLE}</style>
</head><body${bodyAttrs}>${inner}<script>${SCRIPT}</script></body></html>`;

// Signed-in app shell. `current` is the nav path to highlight; `head` renders a page header.
export function shell(title, body, { user, current, sub = '', actions = '' } = {}) {
  const nav = NAV.map(([href, label, ico]) =>
    `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${icon(ico)}${label}</a>`).join('');
  const who = user ? `<div class="user"><span class="avatar" aria-hidden="true">${e(user.email[0] || '?')}</span>
<span class="email">${e(user.email)}</span><a class="btn btn-ghost btn-sm" href="/auth/signout">${icon('logout')}Sign out</a></div>` : '';
  return doc(title, '', `<header class="topbar"><div class="wrap"><a class="brand" href="/review">${LOGO}HindSight</a>
<nav class="tabsnav" aria-label="Main">${user ? nav : ''}</nav>${who}</div></header>
<main class="wrap"><div class="head"><div><h1>${e(title)}</h1>${sub ? `<p class="sub">${sub}</p>` : ''}</div>${actions}</div>${body}</main>`);
}

// Centered single-card screen: sign-in, sign-out, setup, and errors.
export function solo(title, body, { sub = '' } = {}) {
  return doc(title, ' class="solo"', `<main class="card solo-card">${LOGO}<h1>${e(title)}</h1>${sub ? `<p class="sub">${sub}</p>` : ''}${body}</main>`);
}

export const alertBox = (kind, html) => `<div class="alert ${kind}" role="${kind === 'err' ? 'alert' : 'status'}">${icon(kind === 'err' ? 'alert' : 'check')}<div>${html}</div></div>`;

export const emptyState = (ico, title, text, cta = '') =>
  `<div class="card empty"><span class="ico">${icon(ico)}</span><h2>${e(title)}</h2><p>${text}</p>${cta}</div>`;

// Exact UTC timestamp for machines and tooltips, short relative text for people.
export function when(value, now = Date.now()) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  const iso = d.toISOString();
  return `<time datetime="${e(iso)}" title="${e(iso.slice(0, 16).replace('T', ' '))} UTC">${e(relative(d.getTime() - now))}</time>`;
}

function relative(ms) {
  const future = ms > 0;
  const abs = Math.abs(ms);
  const units = [['year', 31536e6], ['month', 2592e6], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]];
  for (const [unit, size] of units) {
    if (abs >= size) {
      const n = Math.floor(abs / size);
      const text = `${n} ${unit}${n === 1 ? '' : 's'}`;
      return future ? `in ${text}` : `${text} ago`;
    }
  }
  return future ? 'in under a minute' : 'just now';
}
