"""Interfaz web local (solo librería estándar). Se ejecuta en 127.0.0.1."""

from __future__ import annotations

import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .hashes import TOOLS, commands_for
from .scan import SECTIONS, result_to_dict, scan

PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CryptoHunter</title>
<style>
:root{--bg:#0f1117;--panel:#181b24;--border:#2a2f3c;--fg:#e6e8ee;--dim:#8b92a5;--acc:#4fd1c5;--ok:#7ee787;--warn:#f2cc60;--bad:#f27a7a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px;font-size:24px}h1 span{color:var(--acc)}p.sub{margin:0 0 20px;color:var(--dim)}
label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin:16px 0 6px}
textarea,pre,select{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--fg);
font:14px/1.5 ui-monospace,Consolas,monospace;padding:12px;margin:0}
textarea,pre{white-space:pre-wrap;word-break:break-all}
textarea{min-height:120px;resize:vertical}textarea:focus{outline:2px solid var(--acc);border-color:transparent}
pre{min-height:40px}
.tabs{display:flex;gap:4px;margin:20px 0 0;border-bottom:1px solid var(--border);flex-wrap:wrap}
.tab{padding:9px 16px;cursor:pointer;color:var(--dim);border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;position:relative}
.tab.active{color:var(--fg);background:var(--panel);border-color:var(--border)}
.tab .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--ok);margin-left:7px;vertical-align:middle}
.panel{background:var(--panel);border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;padding:16px}
.desc{color:var(--dim);margin:0 0 12px}
.can{margin:8px 0}.can b{color:var(--ok)}.cant b{color:var(--bad)}
.can ul{margin:4px 0 0;padding-left:20px}.can li{color:var(--dim);font-size:14px}
.chain{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:10px}
.chip{background:#1f3b3a;color:var(--acc);border-radius:999px;padding:3px 10px;font-size:13px}
.arrow{color:var(--dim)}.out{color:var(--ok)}
.cand{border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin-bottom:8px;cursor:pointer}
.cand:hover{border-color:var(--acc)}.cand small{color:var(--dim)}.cand code{display:block;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.htype{background:#2a2f3c;border-radius:6px;padding:2px 8px;margin:0 6px 6px 0;display:inline-block;font-size:13px}
.htype.sel{background:#1f3b3a;color:var(--acc)}
.cmd{background:#0f1117;border:1px solid var(--border);border-radius:6px;padding:8px 10px;margin:6px 0;position:relative}
.cmd .k{color:var(--warn);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.cmd code{display:block;color:var(--ok);margin-top:3px;white-space:pre-wrap;word-break:break-all}
.cmd button{position:absolute;top:8px;right:8px;background:var(--border);color:var(--fg);border:none;border-radius:5px;padding:3px 8px;cursor:pointer;font-size:12px}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:160px}
.muted{color:var(--dim);font-size:13px}a{color:var(--acc)}
.note{color:var(--warn);font-size:13px;margin-top:10px}
</style></head><body><main>
<h1>Crypto<span>Hunter</span></h1>
<p class="sub">Pega un texto: se detecta solo si es un cifrado (y se descifra), un hash o un formato conocido.</p>
<textarea id="in" placeholder="Ej: Krod pxqgr   |   5d41402abc4b2a76b9719d911017c592" autofocus></textarea>
<div class="tabs" id="tabs"></div>
<div class="panel" id="panel"></div>
</main>
<script id="meta" type="application/json">__META__</script>
<script>
const META=JSON.parse(document.getElementById('meta').textContent);
const SECTIONS=META.sections, TOOLS=META.tools;
const ORDER=['cifrado','hash','identificacion'];
let data=null, active='cifrado', timer, seq=0;
const el=(t,c,txt)=>{const e=document.createElement(t);if(c)e.className=c;if(txt!=null)e.textContent=txt;return e};

function renderTabs(){
  const tabs=document.getElementById('tabs');tabs.textContent='';
  ORDER.forEach(id=>{
    const t=el('div','tab'+(id===active?' active':''),SECTIONS[id].titulo);
    if(data&&data.sections_present.includes(id))t.appendChild(el('span','dot'));
    t.onclick=()=>{active=id;renderTabs();renderPanel()};
    tabs.appendChild(t);
  });
}
function sectionIntro(id){
  const m=SECTIONS[id],frag=document.createDocumentFragment();
  frag.appendChild(el('p','desc',m.descripcion));
  const can=el('div','can');can.appendChild(el('b',null,'Qué puede hacer:'));
  const ul=el('ul');m.puede.forEach(x=>ul.appendChild(el('li',null,x)));can.appendChild(ul);frag.appendChild(can);
  const no=el('div','can cant');no.appendChild(el('b',null,'Qué NO puede hacer:'));
  const ul2=el('ul');m.no_puede.forEach(x=>ul2.appendChild(el('li',null,x)));no.appendChild(ul2);frag.appendChild(no);
  return frag;
}
function renderCifrado(panel){
  const s=data&&data.sections.cifrado;
  if(!s){panel.appendChild(sectionIntro('cifrado'));return}
  const chain=el('div','chain');
  s.chain.forEach((c,i)=>{if(i)chain.appendChild(el('span','arrow','→'));chain.appendChild(el('span','chip',c))});
  panel.appendChild(el('label',null,'Cifrado detectado'));panel.appendChild(chain);
  panel.appendChild(el('label',null,'Texto descifrado'));
  const out=el('pre','out',s.result);panel.appendChild(out);
  if(s.candidates.length>1){
    panel.appendChild(el('label',null,'Otros candidatos'));
    s.candidates.slice(1).forEach(c=>{const d=el('div','cand');
      d.appendChild(el('small',null,'['+c.score.toFixed(2)+'] '+c.chain.join(' → ')));
      d.appendChild(el('code',null,c.result));d.onclick=()=>{out.textContent=c.result};panel.appendChild(d)});
  }
}
function copyBtn(text){const b=el('button',null,'copiar');b.onclick=()=>navigator.clipboard&&navigator.clipboard.writeText(text);return b}
async function renderHash(panel){
  const s=data&&data.sections.hash;
  panel.appendChild(sectionIntro('hash'));
  if(!s)return;
  panel.appendChild(el('label',null,'Tipos de hash probables'));
  const wrap=el('div');let sel=0;
  const draw=async()=>{
    wrap.textContent='';
    const types=el('div');
    s.candidates.forEach((c,i)=>{const h=el('span','htype'+(i===sel?' sel':''),c.name+(c.note?' ('+c.note+')':''));
      h.onclick=()=>{sel=i;draw()};types.appendChild(h)});
    wrap.appendChild(types);
    const row=el('div','row');
    const d1=el('div');d1.appendChild(el('label',null,'Herramienta'));
    const toolSel=el('select');TOOLS.forEach(t=>{const o=el('option',null,t);o.value=t;toolSel.appendChild(o)});
    toolSel.value=tool;toolSel.onchange=()=>{tool=toolSel.value;draw()};d1.appendChild(toolSel);row.appendChild(d1);
    const d2=el('div');d2.appendChild(el('label',null,'Diccionario (wordlist)'));
    const wl=el('input');wl.value=wordlist;wl.style.cssText='width:100%;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--fg);padding:11px;font:14px ui-monospace,monospace';
    wl.onchange=()=>{wordlist=wl.value;draw()};d2.appendChild(wl);row.appendChild(d2);
    wrap.appendChild(row);
    const my=++seq;
    const res=await fetch('/api/hashcmd',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text:data.input,tool,index:sel,wordlist})}).then(r=>r.json());
    if(my!==seq)return;
    wrap.appendChild(el('label',null,'Comando para '+res.tool));
    if(res.unsupported){wrap.appendChild(el('p','note',res.unsupported));}
    else{Object.entries(res.commands).forEach(([k,cmd])=>{
      const box=el('div','cmd');box.appendChild(el('div','k',k.replace('_',' ')));
      box.appendChild(el('code',null,cmd));box.appendChild(copyBtn(cmd));wrap.appendChild(box)})}
    wrap.appendChild(el('p','note','Guarda el hash en hash.txt y ejecútalo tú en tu equipo. Más info: '));
    const a=el('a',null,res.url);a.href=res.url;a.target='_blank';wrap.lastChild.appendChild(a);
  };
  await draw();panel.appendChild(wrap);
}
function renderIdent(panel){
  const s=data&&data.sections.identificacion;
  panel.appendChild(sectionIntro('identificacion'));
  if(!s)return;
  panel.appendChild(el('label',null,'Formato detectado'));
  const d=el('div');d.appendChild(el('span','chip',s.name));d.appendChild(el('p','muted',s.note));panel.appendChild(d);
}
let tool='hashcat',wordlist='/usr/share/wordlists/rockyou.txt';
function renderPanel(){
  const panel=document.getElementById('panel');panel.textContent='';
  if(active==='cifrado')renderCifrado(panel);
  else if(active==='hash')renderHash(panel);
  else renderIdent(panel);
}
document.getElementById('in').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(async()=>{
  const text=document.getElementById('in').value;
  if(!text.trim()){data=null;renderTabs();renderPanel();return}
  const my=++seq;
  const res=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
  if(my!==seq)return;data=await res.json();
  if(data.sections_present.length&&!data.sections_present.includes(active))active=data.sections_present[0];
  renderTabs();renderPanel();
},300)});
renderTabs();renderPanel();
</script></body></html>"""


def _render_page() -> bytes:
    meta = {
        "sections": SECTIONS,
        "tools": list(TOOLS),
    }
    return PAGE.replace("__META__", json.dumps(meta, ensure_ascii=False)).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        length = min(int(self.headers.get("Content-Length", 0)), 1_000_000)
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            return None

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, _render_page(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        payload = self._read_json()
        if payload is None or "text" not in payload:
            return self._send(400, b'{"error":"bad request"}', "application/json")
        text = str(payload["text"])

        if self.path == "/api/analyze":
            body = json.dumps(result_to_dict(scan(text)), ensure_ascii=False).encode()
        elif self.path == "/api/hashcmd":
            from .hashes import identify

            match = identify(text)
            if match is None:
                body = b'{"error":"no es un hash"}'
            else:
                tool = str(payload.get("tool", "hashcat"))
                index = int(payload.get("index", 0))
                index = max(0, min(index, len(match.candidates) - 1))
                wordlist = str(payload.get("wordlist") or "/usr/share/wordlists/rockyou.txt")
                body = json.dumps(
                    commands_for(match, tool=tool, candidate_index=index, wordlist=wordlist),
                    ensure_ascii=False,
                ).encode()
        else:
            return self._send(404, b"not found", "text/plain")
        self._send(200, body, "application/json; charset=utf-8")

    def log_message(self, *args):
        pass


def serve(port: int = 8000, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"CryptoHunter web en {url}  (Ctrl+C para salir)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
