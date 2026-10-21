import { createHash } from 'node:crypto';
import { escapeHtml as e } from './security.js';

// Shared UI: design tokens, layout shell, icons, and the one inline script. Everything is inline so the
// CSP stays `default-src 'none'`: styles via 'unsafe-inline', the script pinned by its SHA-256 hash, and only
// same-origin fetches (connect-src 'self', for the Inbox's "Show more").

const STYLE = `:root{color-scheme:light dark;--bg:#f7f7f8;--surface:#fff;--surface-2:#f2f2f4;--surface-3:#e9e9ec;--border:#e5e5e9;--border-strong:#cdcdd4;
--text:#17171c;--text-2:#4e4e58;--muted:#6f6f7b;--faint:#a9a9b3;--accent:#4f46e5;--accent-hover:#4338ca;--accent-soft:#eceefc;--accent-text:#3b34b5;--on-accent:#fff;
--ok:#15803d;--ok-soft:#e9f7ee;--planned:#1d5fc4;--planned-soft:#e8f0fd;--warn:#9a5b00;--warn-soft:#fff6e3;--warn-border:#f0cf86;--danger:#c42b2b;--danger-soft:#fdeeee;
--admin:#b45309;--admin-text:#8a3f04;--admin-soft:#fff3e2;--admin-border:#f1c48a;
--radius:10px;--radius-sm:6px;--radius-xs:4px;--shadow-1:0 1px 2px rgba(16,16,24,.05);--shadow-2:0 6px 20px rgba(16,16,24,.12),0 1px 3px rgba(16,16,24,.06);--ring:0 0 0 3px var(--accent-soft);
--font:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
--fs-xs:11px;--fs-sm:12.5px;--fs:14px;--fs-md:15px;--fs-lg:22px;--wrap:960px;--gutter:20px;--row-x:12px;--row-y:10px;--chk:18px;--hit:30px;
--code-bg:#121217;--code-text:#e6e6ef;--code-border:#26262e}
@media (prefers-color-scheme:dark){:root{--bg:#0e0e11;--surface:#16161a;--surface-2:#1d1d22;--surface-3:#26262c;--border:#27272e;--border-strong:#3a3a43;
--text:#ededf1;--text-2:#b9b9c3;--muted:#8f8f9b;--faint:#5d5d68;--accent:#7c74ff;--accent-hover:#958fff;--accent-soft:#25234a;--accent-text:#c4c1ff;--on-accent:#0e0e11;
--ok:#4ade80;--ok-soft:#12291b;--planned:#7cb0ff;--planned-soft:#14223a;--warn:#fbbf24;--warn-soft:#2b2110;--warn-border:#5c4512;--danger:#f87171;--danger-soft:#321617;
--admin:#f5a524;--admin-text:#ffd28a;--admin-soft:#2d1f0b;--admin-border:#5a3d10;
--shadow-1:0 1px 2px rgba(0,0,0,.35);--shadow-2:0 8px 24px rgba(0,0,0,.5),0 1px 3px rgba(0,0,0,.4);--code-bg:#0b0b0e;--code-border:#2a2a32}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font:var(--fs-md)/1.5 var(--font);color:var(--text);background:var(--bg);-webkit-font-smoothing:antialiased;font-feature-settings:"tnum"}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:var(--radius-sm)}
svg.i{width:16px;height:16px;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
code,kbd{font-family:var(--mono);font-size:.92em}
.wrap{max-width:var(--wrap);margin:0 auto;padding:0 var(--gutter)}
.muted{color:var(--muted)}
.small{font-size:var(--fs-sm)}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:5}
.topbar .wrap{display:flex;align-items:center;gap:20px;min-height:52px}
.brand{display:inline-flex;align-items:center;gap:9px;font-weight:650;font-size:15px;letter-spacing:-.01em;color:var(--text)}
.brand:hover{text-decoration:none}
.logo{width:24px;height:24px;border-radius:7px;background:var(--accent);color:var(--on-accent);display:grid;place-items:center;flex:none}
.logo svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.tabsnav{display:flex;gap:2px;flex:1;min-width:0}
.tabsnav a{display:inline-flex;align-items:center;gap:7px;padding:6px 10px;border-radius:var(--radius-sm);color:var(--muted);font-weight:500;font-size:var(--fs);min-height:34px;white-space:nowrap}
.tabsnav a:hover{background:var(--surface-2);color:var(--text);text-decoration:none}
.tabsnav a[aria-current=page]{color:var(--text);background:var(--surface-2)}
.user{display:flex;align-items:center;gap:10px;margin-left:auto}
.avatar{width:26px;height:26px;border-radius:50%;background:var(--accent-soft);color:var(--accent-text);display:grid;place-items:center;font-weight:650;font-size:12px;text-transform:uppercase;flex:none}
.user .email{color:var(--muted);font-size:var(--fs-sm);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main.wrap{padding-top:28px;padding-bottom:72px}
.head{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:8px 24px;margin-bottom:18px}
h1{font-size:var(--fs-lg);line-height:1.2;letter-spacing:-.02em;margin:0;font-weight:650}
.sub{color:var(--muted);margin:4px 0 0;max-width:60ch;font-size:var(--fs)}
h2{font-size:var(--fs-md);margin:0;font-weight:600}
.btn{font:inherit;font-weight:550;font-size:var(--fs);display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:36px;padding:6px 14px;border-radius:var(--radius-sm);border:1px solid transparent;cursor:pointer;white-space:nowrap;text-decoration:none;background:var(--accent);color:var(--on-accent)}
.btn:hover{background:var(--accent-hover);text-decoration:none}
.btn-secondary{background:var(--surface);color:var(--text);border-color:var(--border-strong)}
.btn-secondary:hover{background:var(--surface-2)}
.btn-ghost{background:transparent;color:var(--muted)}
.btn-ghost:hover{background:var(--surface-2);color:var(--text)}
.btn-danger{background:transparent;color:var(--danger);border-color:var(--border)}
.btn-danger:hover{background:var(--danger-soft);border-color:var(--danger)}
.btn-sm{min-height:30px;padding:3px 10px;font-size:var(--fs-sm)}
.btn-block{width:100%}
label.field{display:flex;flex-direction:column;gap:6px;font-size:var(--fs-sm);font-weight:600;min-width:0}
label.field .hint{font-weight:400;color:var(--muted)}
input[type=text],input:not([type]),select,textarea{font:inherit;font-size:var(--fs);font-weight:400;min-height:36px;padding:6px 10px;border:1px solid var(--border-strong);border-radius:var(--radius-sm);background:var(--surface);color:var(--text);width:100%;max-width:100%}
textarea{display:block;resize:vertical;line-height:1.45}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:var(--ring)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-1)}
.card-pad{padding:18px 20px}
.stack>*+*{margin-top:16px}
.toolbar{display:flex;align-items:center;gap:8px 16px;margin-bottom:10px;border-bottom:1px solid var(--border)}
.toolbar>.btn{margin-left:auto;margin-bottom:4px}
.views{display:flex;gap:2px;margin-bottom:-1px;overflow-x:auto;max-width:100%}
.views a{display:inline-flex;align-items:center;gap:6px;padding:8px 10px 10px;color:var(--muted);font-weight:500;font-size:var(--fs);border-bottom:2px solid transparent;white-space:nowrap}
.views a:hover{color:var(--text);text-decoration:none}
.views a[aria-current=page]{color:var(--text);border-bottom-color:var(--text)}
.views .n{font-size:var(--fs-xs);color:var(--muted);background:var(--surface-2);border-radius:999px;padding:0 6px;line-height:18px;min-width:18px;text-align:center}
.views a[aria-current=page] .n{color:var(--text);background:var(--surface-3)}
.filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 14px}
.filters select{width:auto;max-width:100%;min-height:30px;padding:3px 8px;font-size:var(--fs-sm);color:var(--text-2);border-color:var(--border);background-color:transparent}
.filters select:hover{border-color:var(--border-strong)}
.js .filters .apply{display:none}
.narrow{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:var(--fs-sm);color:var(--muted);margin:-6px 0 12px}
.group{display:flex;align-items:baseline;gap:8px;font-size:var(--fs-xs);font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:18px 0 6px;padding:0 var(--row-x)}
.group:first-child,.bulkbar+.group{margin-top:4px}
.group .n{font-weight:500;color:var(--faint);letter-spacing:0}
.tasks{list-style:none;margin:0;padding:0;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow-1)}
.task{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:start;gap:0 10px;padding:var(--row-y) var(--row-x);border-top:1px solid var(--border);position:relative;scroll-margin-top:68px}
.task:first-child{border-top:0;border-radius:var(--radius) var(--radius) 0 0}
.task:last-child{border-radius:0 0 var(--radius) var(--radius)}
.task:only-child{border-radius:var(--radius)}
.task:hover{background:color-mix(in srgb,var(--surface-2) 55%,var(--surface))}
.task:target,.task:has(:target){box-shadow:inset 3px 0 0 var(--accent)}
.chk-form{display:contents}
.chk,.sel{appearance:none;-webkit-appearance:none;width:var(--hit);height:var(--hit);margin:calc((20px - var(--hit))/2) calc((var(--chk) - var(--hit))/2);padding:0;border:0;background:none;display:grid;place-items:center;cursor:pointer;border-radius:var(--radius-sm);color:var(--on-accent);position:relative}
.box{width:var(--chk);height:var(--chk);border:1.5px solid var(--border-strong);border-radius:5px;background:var(--surface);display:grid;place-items:center;transition:border-color .12s,background .12s}
.box svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round;opacity:0}
.chk:hover .box,.sel:hover .box{border-color:var(--accent)}
.chk:hover svg{opacity:.45;color:var(--accent)}
.chk[aria-checked=true] .box,.sel input:checked+.box{background:var(--accent);border-color:var(--accent)}
.chk[aria-checked=true] svg,.chk[aria-checked=true]:hover svg,.sel input:checked+.box svg{opacity:1;color:var(--on-accent)}
.chk.planned .box{border-color:var(--planned)}
.chk.planned .box::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--planned)}
.chk.wontdo .box{background:var(--surface-2);color:var(--muted)}
.chk.wontdo .box::before{content:"";width:8px;height:1.5px;background:var(--muted)}
.chk.planned svg,.chk.wontdo svg{display:none}
.chk:focus-visible{outline:none}
.chk:focus-visible .box,.sel input:focus-visible+.box{outline:2px solid var(--accent);outline-offset:2px}
.sel input{position:absolute;inset:0;z-index:1;opacity:0;width:100%;height:100%;margin:0;cursor:pointer}
.task:has(.sel input:checked){background:color-mix(in srgb,var(--accent-soft) 70%,var(--surface))}
details.body{min-width:0}
details.body>summary{list-style:none;cursor:pointer;display:block;min-width:0;border-radius:var(--radius-xs)}
details.body>summary::-webkit-details-marker{display:none}
.title{font-size:var(--fs);line-height:20px;color:var(--text);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere;white-space:pre-line}
details.body[open] .title{display:block;-webkit-line-clamp:unset}
.meta{display:flex;flex-wrap:wrap;align-items:center;gap:4px 6px;margin-top:3px;font-size:var(--fs-sm);color:var(--muted);line-height:1.4}
.meta .sep{color:var(--faint)}
.meta .src{min-width:0;overflow-wrap:anywhere}
.meta time{white-space:nowrap}
.meta .i{width:12px;height:12px}
.cat{display:inline-flex;align-items:center;font-size:var(--fs-xs);font-weight:550;line-height:17px;padding:0 6px;border-radius:var(--radius-xs);border:1px solid var(--border);color:var(--text-2);background:var(--surface);letter-spacing:.01em}
.tag{display:inline-flex;align-items:center;gap:4px;font-size:var(--fs-xs);font-weight:600;line-height:17px}
.tag.planned{color:var(--planned)}
.tag.wontdo{color:var(--muted)}
.tag.hasnote{color:var(--text-2);font-weight:550}
.chev{margin-left:auto;display:inline-flex;align-items:center;gap:3px;color:var(--faint);font-size:var(--fs-xs);font-weight:500}
.chev svg.i{width:12px;height:12px;transition:transform .15s}
details.body[open] .chev svg{transform:rotate(180deg)}
details.body>summary:hover .chev{color:var(--muted)}
.task.is-done .title{color:var(--muted);text-decoration:line-through;text-decoration-color:var(--faint);text-decoration-thickness:1px}
.task.is-wontdo .title{color:var(--muted)}
.detail{margin:10px 0 2px;padding:12px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);font-size:var(--fs);cursor:auto}
.detail h3{font-size:var(--fs-xs);font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 4px}
.detail .prose{margin:0 0 12px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--text-2)}
.facts{display:flex;flex-wrap:wrap;gap:6px 22px;margin:0 0 12px;font-size:var(--fs-sm)}
.facts>div{display:flex;gap:6px;min-width:0;max-width:100%}
.facts dt{color:var(--muted);flex:none}
.facts dd{margin:0;min-width:0;color:var(--text);overflow-wrap:anywhere}
.note{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px 8px;align-items:end;margin:0 0 12px}
.note label{grid-column:1/-1;font-size:var(--fs-xs);font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.note label span{text-transform:none;letter-spacing:0;font-weight:400;color:var(--faint)}
.note textarea{min-height:36px;font-size:var(--fs-sm)}
.detail-foot{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px;padding-top:10px;border-top:1px solid var(--border)}
.reqid{display:inline-flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:var(--fs-xs);color:var(--muted);min-width:0}
.reqid code{font-family:var(--mono);overflow-wrap:anywhere;color:var(--text-2);min-width:0}
.copy{display:none}
.js .copy{display:inline-flex}
.copy.copied{color:var(--ok)}
.actions{display:flex;flex-wrap:wrap;gap:6px}
.actions .btn{font-weight:500}
.menu{position:relative;margin:-4px -4px 0 0}
.menu>summary{list-style:none;cursor:pointer;width:var(--hit);height:var(--hit);border-radius:var(--radius-sm);display:grid;place-items:center;color:var(--faint)}
.menu>summary::-webkit-details-marker{display:none}
.menu>summary:hover,.menu[open]>summary{background:var(--surface-3);color:var(--text)}
.menu-panel{position:absolute;right:0;top:calc(var(--hit) + 4px);z-index:4;min-width:190px;padding:4px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);box-shadow:var(--shadow-2)}
.menu-panel form{display:contents}
.menu-panel button,.menu-panel a{font:inherit;font-size:var(--fs-sm);font-weight:500;display:flex;width:100%;align-items:center;gap:8px;min-height:32px;padding:6px 9px;border:0;border-radius:var(--radius-xs);background:none;color:var(--text);cursor:pointer;text-align:left;text-decoration:none}
.menu-panel button:hover,.menu-panel a:hover{background:var(--surface-2);text-decoration:none}
.menu-panel hr{border:0;border-top:1px solid var(--border);margin:4px 0}
.menu-panel svg.i{width:14px;height:14px;color:var(--muted)}
.js .menu-panel .copy{display:flex}
.bulkbar{position:sticky;top:60px;z-index:3;display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 10px;margin:0 0 12px;background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius);box-shadow:var(--shadow-1)}
.bulkbar .count{font-weight:600;font-size:var(--fs);padding:0 6px;margin-right:4px}
.bulkbar .spacer{flex:1}
.empty{text-align:center;padding:48px 24px}
.empty .ico{width:40px;height:40px;border-radius:var(--radius);background:var(--surface-2);color:var(--muted);display:inline-grid;place-items:center;margin-bottom:10px}
.empty .ico svg{width:20px;height:20px}
.empty h2{font-size:var(--fs-md);margin-bottom:4px}
.empty p{color:var(--muted);margin:0 auto 14px;max-width:44ch;font-size:var(--fs)}
.pager{display:flex;justify-content:center;gap:8px;margin-top:20px}
.more{display:flex;flex-direction:column;align-items:center;gap:8px;margin:16px 0 0;font-size:var(--fs-sm);color:var(--muted);text-align:center}
.more [aria-busy=true]{opacity:.6;pointer-events:none}.task [id^="more-"]{scroll-margin-top:78px}
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:var(--radius);border:1px solid;margin-bottom:16px;font-size:var(--fs);color:var(--text)}
.alert.ok{background:var(--ok-soft);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.alert.err{background:var(--danger-soft);border-color:color-mix(in srgb,var(--danger) 30%,transparent)}
.alert .i{margin-top:3px}
.alert.ok .i{color:var(--ok)}
.alert.err .i{color:var(--danger)}
.reveal{border:1px solid color-mix(in srgb,var(--ok) 35%,var(--border));background:linear-gradient(0deg,var(--surface) 55%,var(--ok-soft));border-radius:var(--radius);padding:18px 20px;margin-bottom:20px;box-shadow:var(--shadow-1)}
.reveal.admin{border-color:var(--admin-border);background:linear-gradient(0deg,var(--surface) 55%,var(--admin-soft))}
.reveal h2{display:flex;align-items:center;gap:8px}
.reveal h2 .i{color:var(--ok)}
.reveal.admin h2 .i{color:var(--admin)}
.reveal p{margin:4px 0 12px;color:var(--muted);font-size:var(--fs)}
.reveal .warnline{display:flex;gap:8px;align-items:flex-start;margin:0 0 12px;padding:8px 10px;border-radius:var(--radius-sm);background:var(--admin-soft);border:1px solid var(--admin-border);color:var(--admin-text);font-size:var(--fs-sm)}
.reveal .warnline .i{margin-top:2px;color:var(--admin)}
.secret{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border-strong);border-radius:var(--radius-sm);padding:5px 5px 5px 12px}
.secret code{flex:1;min-width:0;font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.reveal .next{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.code{position:relative;background:var(--code-bg);color:var(--code-text);border-radius:var(--radius-sm);border:1px solid var(--code-border)}
.code pre{margin:0;padding:12px 14px;padding-right:88px;font-family:var(--mono);font-size:12.5px;line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere}
.code .copy{position:absolute;top:6px;right:6px;background:#23232b;color:#e6e6ef;border-color:#33333d}
.code .copy:hover{background:#2e2e38}
.code .copy.copied{color:#4ade80;border-color:#4ade80}
.kform{display:grid;gap:14px}
.kform .row2{display:grid;grid-template-columns:minmax(0,1fr) 160px auto;gap:12px;align-items:end}
fieldset.scopes{border:0;margin:0;padding:0;min-width:0}
fieldset.scopes legend{font-size:var(--fs-sm);font-weight:600;padding:0;margin-bottom:6px}
.scope-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.scope{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;align-items:start;padding:12px 14px;border:1px solid var(--border-strong);border-radius:var(--radius-sm);cursor:pointer;background:var(--surface)}
.scope:hover{background:var(--surface-2)}
.scope input{grid-row:1/3;margin:3px 0 0;accent-color:var(--accent);width:16px;height:16px}
.scope b{font-weight:600;font-size:var(--fs);display:flex;align-items:center;gap:8px}
.scope span{font-size:var(--fs-sm);color:var(--muted);line-height:1.45}
.scope:has(input:checked){border-color:var(--accent);box-shadow:var(--ring)}
.scope.admin b .i{color:var(--admin);width:15px;height:15px}
.scope.admin:has(input:checked){border-color:var(--admin);box-shadow:0 0 0 3px var(--admin-soft);background:var(--admin-soft)}
.scope.admin input{accent-color:var(--admin)}
.admin-warn{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;border:1px solid var(--admin-border);background:var(--admin-soft);border-radius:var(--radius-sm);color:var(--admin-text);font-size:var(--fs-sm);line-height:1.5;margin:0}
.admin-warn .i{color:var(--admin);margin-top:2px}
.kform:has(#sc-ingest:checked) .admin-warn{display:none}
.btn-create .lbl-a{display:none}
.kform:has(#sc-admin:checked) .btn-create{background:var(--admin);color:#fff}
.kform:has(#sc-admin:checked) .btn-create .lbl-a{display:inline}
.kform:has(#sc-admin:checked) .btn-create .lbl-i{display:none}
.keys{list-style:none;margin:0;padding:0}
.keys li{display:grid;grid-template-columns:minmax(0,2.3fr) .8fr 1fr 1fr 1.1fr 80px;gap:14px;align-items:center;padding:12px 16px;border-top:1px solid var(--border);font-size:var(--fs)}
.keys li:first-child{border-top:0}
.keys li.hd{padding-top:8px;padding-bottom:8px;font-size:var(--fs-xs);font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;background:var(--surface-2);border-radius:var(--radius) var(--radius) 0 0}
.keys li:last-child{border-radius:0 0 var(--radius) var(--radius)}
.keys .name{display:flex;align-items:center;gap:10px;min-width:0}
.keys .nm{display:flex;flex-wrap:wrap;align-items:center;gap:2px 10px;min-width:0}
.keys .name b{font-weight:600;min-width:0;overflow-wrap:anywhere}
.keys .cell{font-size:var(--fs-sm);color:var(--muted)}
.keys .cell .k{display:none}
.keys .act{text-align:right}
.keys li.off .name b{color:var(--muted)}
.keys li.off .keyico{opacity:.55}
.keyico{width:28px;height:28px;border-radius:var(--radius-sm);background:var(--surface-2);border:1px solid var(--border);display:grid;place-items:center;color:var(--muted);flex:none}
.keyico svg.i{width:14px;height:14px}
.keyico.admin{background:var(--admin-soft);border-color:var(--admin-border);color:var(--admin)}
.keys li.is-admin{background:color-mix(in srgb,var(--admin-soft) 45%,transparent)}
.scopelbl{display:inline-flex;align-items:center;gap:5px;font-size:var(--fs-xs);font-weight:600;line-height:18px;padding:0 7px;border-radius:999px;border:1px solid var(--border);color:var(--text-2);white-space:nowrap}
.scopelbl.admin{color:var(--admin-text);border-color:var(--admin-border);background:var(--admin-soft)}
.scopelbl svg.i{width:11px;height:11px}
.status{display:inline-flex;align-items:center;gap:5px;font-size:var(--fs-sm);color:var(--muted);white-space:nowrap}
.status::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.status.active{color:var(--ok)}
.status.revoked{color:var(--danger)}
.steps{counter-reset:s;list-style:none;margin:0;padding:0}
.steps>li{position:relative;padding:0 0 24px 40px;min-width:0}
.steps>li:last-child{padding-bottom:0}
.steps>li::before{counter-increment:s;content:counter(s);position:absolute;left:0;top:0;width:26px;height:26px;border-radius:50%;background:var(--accent-soft);color:var(--accent-text);font-weight:650;font-size:12px;display:grid;place-items:center}
.steps>li::after{content:"";position:absolute;left:12.5px;top:32px;bottom:6px;width:1px;background:var(--border)}
.steps>li:last-child::after{display:none}
.steps h3{font-size:var(--fs-md);margin:2px 0 4px;font-weight:600}
.steps p{margin:0 0 10px;color:var(--muted);font-size:var(--fs)}
.adminbox{border:1px solid var(--admin-border);border-radius:var(--radius);background:var(--surface);overflow:hidden;margin-top:20px;scroll-margin-top:68px}
.adminbox>header{display:flex;align-items:flex-start;gap:10px;padding:12px 18px;background:var(--admin-soft);border-bottom:1px solid var(--admin-border);color:var(--admin-text)}
.adminbox>header .i{color:var(--admin);margin-top:3px}
.adminbox>header h2{color:var(--text)}
.adminbox>header p{margin:0;font-size:var(--fs-sm);color:var(--admin-text)}
.adminbox .in{padding:16px 18px}
.adminbox .in>p{margin:0 0 10px}
.toolgrid{display:grid;grid-template-columns:auto minmax(0,1fr);gap:6px 14px;font-size:var(--fs-sm);margin:8px 0 0}
.toolgrid dt{font-family:var(--mono);color:var(--text);font-size:12px;padding-top:1px}
.toolgrid dd{margin:0;color:var(--muted);min-width:0}
.tabs{display:flex;flex-direction:column;min-width:0}
.tabs>input{position:absolute;opacity:0;pointer-events:none}
.tabs .tl{display:flex;flex-wrap:wrap;gap:2px;padding:3px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);align-self:flex-start;margin-bottom:10px}
.tabs .tl label{font-size:var(--fs-sm);font-weight:550;color:var(--muted);border-radius:4px;padding:4px 10px;min-height:28px;display:inline-flex;align-items:center;cursor:pointer}
.tabs .panel{display:none}
.tabs .panel>p{font-size:var(--fs-sm);margin:8px 0 0}
#t1:checked~.tl [for=t1],#t2:checked~.tl [for=t2],#t3:checked~.tl [for=t3],#t4:checked~.tl [for=t4],#a1:checked~.tl [for=a1],#a2:checked~.tl [for=a2]{background:var(--surface);color:var(--text);box-shadow:var(--shadow-1)}
#t1:focus-visible~.tl [for=t1],#t2:focus-visible~.tl [for=t2],#t3:focus-visible~.tl [for=t3],#t4:focus-visible~.tl [for=t4],#a1:focus-visible~.tl [for=a1],#a2:focus-visible~.tl [for=a2]{outline:2px solid var(--accent)}
#t1:checked~.p1,#t2:checked~.p2,#t3:checked~.p3,#t4:checked~.p4,#a1:checked~.p1,#a2:checked~.p2{display:block}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:var(--fs-sm);margin:0}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-family:var(--mono);overflow-wrap:anywhere}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:20px;align-items:start}
.problem{display:flex;gap:12px;align-items:flex-start}
.problem>.i{color:var(--danger);margin-top:3px}
.problem p{margin:0 0 14px}
body.solo{min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:radial-gradient(900px 500px at 50% -10%,var(--accent-soft),transparent 70%),var(--bg)}
.solo-card{width:100%;max-width:400px;padding:32px 28px;text-align:center}
.solo-card .logo{width:40px;height:40px;border-radius:10px;margin:0 auto 16px}
.solo-card .logo svg{width:20px;height:20px}
.solo-card h1{font-size:20px}
.solo-card .sub{margin:6px auto 22px}
.solo-card .alert{text-align:left;margin-bottom:18px}
.solo-card .prose-left{margin-top:16px;text-align:left;font-size:var(--fs);color:var(--text-2)}
.solo-card .prose-left p{margin:0 0 10px}
.solo-card .fine{display:flex;align-items:center;justify-content:center;gap:6px;font-size:var(--fs-sm);color:var(--muted);margin:18px 0 0}
.gbtn{font:inherit;font-size:var(--fs-md);font-weight:550;width:100%;min-height:44px;display:flex;align-items:center;justify-content:center;gap:12px;border-radius:var(--radius-sm);border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer;box-shadow:var(--shadow-1)}
.gbtn:hover{background:var(--surface-2)}
.gbtn svg{width:20px;height:20px;flex:none}
.solo-actions{display:flex;flex-direction:column;gap:8px}
@media (max-width:820px){.grid2{grid-template-columns:1fr}.keys li.hd{display:none}
.keys li{grid-template-columns:1fr auto;gap:4px 12px}.keys .name{grid-column:1/-1}.keys .act{grid-column:2;grid-row:2/6;align-self:end}
.keys .cell{grid-column:1}.keys .cell .k{display:inline}.keys li:first-child{border-radius:var(--radius) var(--radius) 0 0}
.kform .row2{grid-template-columns:1fr 1fr}.kform .row2 .btn-create{grid-column:1/-1}}
@media (max-width:640px){:root{--gutter:16px;--hit:36px}.topbar .wrap{gap:8px;flex-wrap:wrap;padding-top:6px;padding-bottom:6px}
.tabsnav{order:3;flex-basis:100%;overflow-x:auto}.tabsnav a{min-height:40px}.user .email{display:none}.user .btn{min-height:36px}
main.wrap{padding-top:18px}h1{font-size:20px}.btn-sm{min-height:36px}
.toolbar{gap:4px 8px}.views{flex:1;min-width:0}.views a{padding:10px 6px;gap:4px;min-height:40px}.toolbar>.btn{flex:none;padding:3px 6px}.toolbar>.btn .i{display:none}.views{gap:0}
.filters select{flex:1 1 38%;min-width:0;min-height:36px}.filters .apply{flex:1 1 100%}
.task{padding:10px 12px}.chev span{display:none}.menu{margin:-8px -8px 0 0}
.detail{padding:12px}.detail-foot{flex-direction:column;align-items:stretch}.actions .btn{flex:1}
.note{grid-template-columns:1fr}.note .btn{width:100%}
.scope-grid{grid-template-columns:1fr}.bulkbar{position:static}.bulkbar .btn{flex:1}.bulkbar .spacer{display:none}
.card-pad,.adminbox .in{padding:16px}.toolgrid{grid-template-columns:minmax(0,1fr);gap:2px}.toolgrid dd{margin-bottom:8px}.code pre{padding-right:14px;padding-top:44px}}`;

// Progressive enhancement only; every page works without it. Kept free of interpolation so its hash
// is a constant.
const SCRIPT = `(()=>{const d=document;d.documentElement.classList.add('js');
d.addEventListener('click',async(ev)=>{d.querySelectorAll('details.menu[open]').forEach((m)=>{if(!m.contains(ev.target))m.open=false});
const b=ev.target.closest('[data-copy]');if(!b)return;
const src=d.getElementById(b.dataset.copy);if(!src)return;const text=src.textContent.trim();
try{await navigator.clipboard.writeText(text)}catch{const r=d.createRange();r.selectNodeContents(src);const s=getSelection();s.removeAllRanges();s.addRange(r);try{d.execCommand('copy')}catch{}}
const l=b.querySelector('.copy-label');if(l){l.dataset.label??=l.textContent;l.textContent='Copied'}
b.classList.add('copied');clearTimeout(b._t);b._t=setTimeout(()=>{b.classList.remove('copied');if(l)l.textContent=l.dataset.label},1600)});
d.addEventListener('keydown',(ev)=>{if(ev.key==='Escape')d.querySelectorAll('details.menu[open]').forEach((m)=>{m.open=false;m.querySelector('summary').focus()})});
d.addEventListener('submit',(ev)=>{const m=ev.target.dataset.confirm;if(m&&!confirm(m))ev.preventDefault()});
d.addEventListener('change',(ev)=>{const f=ev.target.form;if(!f||f.id!=='bulk')return;const n=[...f.elements].filter((x)=>x.name==='ids'&&x.checked).length;
f.querySelector('[data-count]').textContent=n?n+' selected':'Select items'});
const t=location.hash.startsWith('#nt-')&&d.getElementById(location.hash.slice(1));if(t)t.closest('details').open=true;
d.querySelectorAll('[data-autosubmit]').forEach((el)=>el.addEventListener('change',()=>el.form.requestSubmit()));
d.addEventListener('click',async(ev)=>{const a=ev.target.closest('a[data-more]');if(!a||ev.button||ev.metaKey||ev.ctrlKey||ev.shiftKey||ev.altKey)return;
ev.preventDefault();if(a.hasAttribute('aria-busy'))return;a.setAttribute('aria-busy','true');const nav=a.closest('.more'),url=a.pathname+a.search;
try{const r=await fetch(url,{headers:{'X-HindSight-Batch':'1'}});if(!r.ok||r.headers.get('X-HindSight-Batch')!=='1')throw 0;
const t=d.createElement('template');t.innerHTML=await r.text();const lists=()=>[...d.querySelectorAll('main ul.tasks')];let first;
for(const u of t.content.querySelectorAll('ul.tasks')){for(const li of [...u.children])if(d.getElementById(li.id))li.remove();if(!u.children.length)continue;
first??=u.firstElementChild;const cur=lists().find((x)=>x.dataset.group===u.dataset.group);
if(cur){cur.append(...u.children);const n=cur.previousElementSibling?.querySelector('.n');if(n)n.textContent=cur.children.length;continue}
const h=u.previousElementSibling?.matches('h2.group')?u.previousElementSibling:null,next=lists().find((x)=>+x.dataset.order>+u.dataset.order);
const at=next?(next.previousElementSibling?.matches('h2.group')?next.previousElementSibling:next):nav;at.before(...(h?[h,u]:[u]))}
nav.replaceWith(t.content.querySelector('.more')??'');history.replaceState(history.state,'',url);
const shown=new URL(url,location.href).searchParams.get('shown');d.querySelectorAll('input[name=next]').forEach((i)=>{i.value=url});
d.querySelectorAll('a[data-here]').forEach((x)=>{const v=new URL(x.href);v.searchParams.set('shown',shown);x.href=v.pathname+v.search});
first?.querySelector('summary')?.focus()}catch{location.href=a.href}});})();`;

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
  chev: '<path d="m6 9 6 6 6-6"/>',
  dots: '<circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  undo: '<path d="M3 7v6h6"/><path d="M21 17a9 9 0 0 0-15-6.7L3 13"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/>',
  warn: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  note: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  list: '<path d="m3 17 2 2 4-4"/><path d="m3 7 2 2 4-4"/><path d="M13 6h8"/><path d="M13 12h8"/><path d="M13 18h8"/>',
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
  `<div class="card empty">${ico ? `<span class="ico">${icon(ico)}</span>` : ''}<h2>${e(title)}</h2><p>${text}</p>${cta}</div>`;

// Exact UTC timestamp for machines and tooltips, short relative text for people.
export function when(value, now = Date.now()) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  const iso = d.toISOString();
  return `<time datetime="${e(iso)}" title="${e(iso.slice(0, 16).replace('T', ' '))} UTC">${e(relative(d.getTime() - now))}</time>`;
}

// Short form for checklist rows ("14 min ago", "3 hr ago", "Yesterday", "4 days ago"), by UTC calendar day,
// matching the Today / Yesterday / Earlier group headers. The exact UTC time stays in the tooltip.
export const dayDiff = (value, now = Date.now()) => Math.floor(now / 864e5) - Math.floor(new Date(value).getTime() / 864e5);
export function ago(value, now = Date.now()) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  const iso = d.toISOString();
  const days = dayDiff(d, now);
  const mins = Math.floor((now - d.getTime()) / 6e4);
  const label = days <= 0 ? (mins < 1 ? 'just now' : mins < 60 ? `${mins} min ago` : `${Math.floor(mins / 60)} hr ago`)
    : days === 1 ? 'Yesterday' : days < 30 ? `${days} days ago` : relative(d.getTime() - now);
  return `<time datetime="${e(iso)}" title="${e(iso.slice(0, 16).replace('T', ' '))} UTC">${e(label)}</time>`;
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
