/**
 * JBbyVTR: MARKETPLACE + REKBER + E-WALLET (web & API dalam satu file)
 *
 * Jalankan:
 *   1. npm init -y && npm i express pg bcryptjs jsonwebtoken express-rate-limit
 *   2. Buat database kosong:  createdb ewallet
 *   3. Set env:  DATABASE_URL, JWT_SECRET, WEBHOOK_SECRET, ADMIN_KEY, (opsional) PORT, FEE_PERCENT, FEE_EMAIL, OWNER_EMAIL
 *   4. node jbvtr.js          (tabel dibuat otomatis; buka http://localhost:3000)
 *
 * Rekber: GET/POST /listings, POST /orders, GET /orders, POST /orders/:id/{confirm,refund,dispute},
 *         admin: GET /admin/disputes, POST /admin/orders/:id/resolve {to:'seller'|'buyer'} (header x-admin-key)
 *
 * Endpoint:
 *   POST /auth/register          name, email, password (min 8), pin (6 digit)
 *   POST /auth/login             -> token JWT
 *   GET  /wallet/balance         Bearer
 *   POST /wallet/topup           Bearer + Idempotency-Key | amount (saldo masuk via webhook)
 *   POST /wallet/transfer        Bearer + Idempotency-Key | to_email, amount, pin
 *   POST /wallet/withdraw        Bearer + Idempotency-Key | amount, pin
 *   GET  /wallet/transactions    Bearer | ?limit=&offset=
 *   POST /webhooks/payment       x-signature = HMAC-SHA256(rawBody, WEBHOOK_SECRET) | reference, status (PAID/FAILED)
 *
 * Sebelum produksi: hubungkan payment gateway (lihat TODO), pakai HTTPS,
 * tambah KYC/limit/audit log, rekonsiliasi ledger, dan urus izin uang elektronik BI.
 */
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const { DATABASE_URL, JWT_SECRET, WEBHOOK_SECRET, ADMIN_KEY, PORT = 3000 } = process.env;
// Biaya rekber: dipotong dari penjual saat dana dicairkan, masuk ke akun FEE_EMAIL. Tanpa FEE_EMAIL = tidak ada biaya.
const FEE_PERCENT = Math.min(Math.max(parseFloat(process.env.FEE_PERCENT) || 0, 0), 50);
const FEE_EMAIL = (process.env.FEE_EMAIL || '').trim().toLowerCase();
// Pemilik web (satu-satunya yang boleh pin jualan). Jika kosong, memakai FEE_EMAIL.
const OWNER_EMAIL = (process.env.OWNER_EMAIL || process.env.FEE_EMAIL || '').trim().toLowerCase();
if (!DATABASE_URL || !JWT_SECRET || !WEBHOOK_SECRET) {
  console.error('Set DATABASE_URL, JWT_SECRET, WEBHOOK_SECRET'); process.exit(1);
}


// ---------- SKEMA DATABASE (dijalankan otomatis saat start) ----------
const SCHEMA = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  pin_hash      TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Saldo dalam satuan rupiah (integer), tidak boleh minus
CREATE TABLE IF NOT EXISTS wallets (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT NOT NULL UNIQUE REFERENCES users(id),
  balance    BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
  currency   TEXT NOT NULL DEFAULT 'IDR',
  status     TEXT NOT NULL DEFAULT 'ACTIVE',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          BIGINT NOT NULL REFERENCES users(id),
  type             TEXT NOT NULL CHECK (type IN ('TOPUP','TRANSFER','WITHDRAW')),
  status           TEXT NOT NULL CHECK (status IN ('PENDING','SUCCESS','FAILED')),
  amount           BIGINT NOT NULL CHECK (amount > 0),
  reference        TEXT NOT NULL UNIQUE,
  idempotency_key  TEXT,
  counterparty_id  BIGINT REFERENCES users(id),
  description      TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, idempotency_key)
);

-- Buku besar: append-only, jangan pernah di-UPDATE/DELETE
CREATE TABLE IF NOT EXISTS ledger_entries (
  id             BIGSERIAL PRIMARY KEY,
  transaction_id UUID NOT NULL REFERENCES transactions(id),
  wallet_id      BIGINT NOT NULL REFERENCES wallets(id),
  direction      TEXT NOT NULL CHECK (direction IN ('DEBIT','CREDIT')),
  amount         BIGINT NOT NULL CHECK (amount > 0),
  balance_after  BIGINT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ledger_wallet ON ledger_entries(wallet_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id, created_at DESC);

-- ===== Marketplace & rekber =====
ALTER TABLE transactions DROP CONSTRAINT IF EXISTS transactions_type_check;
ALTER TABLE transactions ADD CONSTRAINT transactions_type_check
  CHECK (type IN ('TOPUP','TRANSFER','WITHDRAW','ESCROW_HOLD','ESCROW_RELEASE','ESCROW_REFUND','ESCROW_FEE'));

CREATE TABLE IF NOT EXISTS listings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id   BIGINT NOT NULL REFERENCES users(id),
  title       TEXT NOT NULL,
  category    TEXT NOT NULL CHECK (category IN ('Akun','Barang')),
  price       BIGINT NOT NULL CHECK (price > 0),
  description TEXT,
  phone       TEXT NOT NULL,
  shots       JSONB NOT NULL DEFAULT '[]',
  status      TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RESERVED','SOLD','REMOVED')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dana rekber: sudah keluar dari saldo pembeli, belum masuk ke penjual
CREATE TABLE IF NOT EXISTS orders (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  listing_id UUID NOT NULL REFERENCES listings(id),
  buyer_id   BIGINT NOT NULL REFERENCES users(id),
  seller_id  BIGINT NOT NULL REFERENCES users(id),
  amount     BIGINT NOT NULL CHECK (amount > 0),
  status     TEXT NOT NULL DEFAULT 'HELD' CHECK (status IN ('HELD','COMPLETED','REFUNDED','DISPUTED')),
  hold_tx_id UUID NOT NULL REFERENCES transactions(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id);
CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);
ALTER TABLE listings ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT false;
`;

const PAGE = "<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><title>JBbyVTR</title><link rel=\"manifest\" href=\"/manifest.webmanifest\"><meta name=\"theme-color\" content=\"#4f46e5\"><link rel=\"icon\" href=\"/icon-192.png\"><link rel=\"apple-touch-icon\" href=\"/icon-192.png\">\n<style>\n:root{--bg:#f6f7fb;--c:#fff;--t:#16181d;--m:#667085;--l:#e4e7ec;--b:#4f46e5;--bt:#fff;--g:#16a34a;--r:#dc2626;color-scheme:light dark}\n@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--c:#181b22;--t:#eef0f4;--m:#98a2b3;--l:#2a2f3a;--b:#818cf8;--bt:#10121a}}\n*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:15px/1.45 system-ui,sans-serif;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}\n.w{max-width:960px;margin:0 auto;padding:16px}header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}h1{font-size:22px;margin:0}\nbutton{font:inherit;cursor:pointer;border:0;border-radius:10px;padding:9px 14px;background:var(--b);color:var(--bt);font-weight:600}button.g{background:none;color:var(--t);border:1px solid var(--l)}button.d{background:none;color:var(--r);border:1px solid var(--l)}button.ok{background:var(--g);color:#fff}\ninput,select,textarea{font:inherit;width:100%;padding:10px;border:1px solid var(--l);border-radius:10px;background:var(--c);color:var(--t)}label{display:block;font-size:13px;font-weight:600;margin:10px 0 4px}\nnav{display:flex;gap:6px;margin:14px 0;overflow-x:auto}nav button{white-space:nowrap}nav .on{background:var(--b);color:var(--bt)}\n.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}.card{background:var(--c);border:1px solid var(--l);border-radius:14px;padding:14px;margin-bottom:12px}.grid .card{margin:0;padding:0;overflow:hidden}.pad{padding:12px 14px}\n.sh{display:flex;overflow-x:auto;scroll-snap-type:x mandatory;background:var(--l)}.sh img{flex:0 0 100%;width:100%;height:190px;object-fit:cover;scroll-snap-align:start}\n.p{font-weight:700;font-size:18px}.m{color:var(--m);font-size:13px;white-space:pre-wrap;word-break:break-word}.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.row>*{flex:1}\n.badge{font-size:12px;padding:2px 9px;border-radius:99px;background:var(--l)}#msg{padding:0;margin:8px 0;font-size:14px}.bad{color:var(--r)}.ok2{color:var(--g)}\na.wa{text-decoration:none;text-align:center;background:var(--g);color:#fff;padding:9px;border-radius:10px;font-weight:600}\n</style></head><body><div class=\"w\"><header><h1>\ud83d\uded2 JBbyVTR</h1><div id=\"top\"></div></header><div id=\"msg\"></div><nav id=\"nav\"></nav><main id=\"main\"></main></div>\n<script>\n/* Kosongkan jika web & API satu server (node jbvtr.js). Isi jika web di hosting terpisah, mis. 'https://api.domainanda.com' */\nvar API='';\nvar $=function(s){return document.querySelector(s)},tok=localStorage.getItem('jb_tok'),tab='shop',bal=0,reg=false,shots=[],myId=null,isOwner=false;\nfunction h(t,a,k){var e=document.createElement(t);a=a||{};for(var x in a){if(x==='on')for(var v in a.on)e.addEventListener(v,a.on[v]);else if(x==='t')e.textContent=a[x];else e.setAttribute(x,a[x])}(k||[]).forEach(function(c){if(c)e.appendChild(c)});return e}\nfunction rp(n){return 'Rp '+Number(n).toLocaleString('id-ID')}\nfunction say(m,bad){var e=$('#msg');e.textContent=m||'';e.className=bad?'bad':'ok2'}\nfunction api(p,o){o=o||{};var hd={'Content-Type':'application/json'};if(tok)hd.Authorization='Bearer '+tok;if(o.idem)hd['Idempotency-Key']=crypto.randomUUID();\nreturn fetch(API+p,{method:o.m||'GET',headers:hd,body:o.b?JSON.stringify(o.b):undefined}).then(function(r){return r.json().catch(function(){return {}}).then(function(j){if(!r.ok)throw new Error(j.error||'Gagal');return j})})}\nfunction run(p,ok){say('');return p.then(function(r){if(ok)say(ok);return r}).catch(function(e){say(e.message,1)})}\nfunction wa(p){var d=String(p).replace(/\\D/g,'');if(d[0]==='0')d='62'+d.slice(1);return 'https://wa.me/'+d}\nfunction inp(id,l,t,ph){return [h('label',{t:l,for:id}),h('input',{id:id,type:t||'text',placeholder:ph||'',autocomplete:'off'})]}\nfunction go(t){tab=t;draw()}\nfunction logout(){tok=null;localStorage.removeItem('jb_tok');draw()}\nfunction draw(){var top=$('#top'),nav=$('#nav'),m=$('#main');top.textContent='';nav.textContent='';m.textContent='';\nif(!tok)return authView(m);\ntry{myId=JSON.parse(atob(tok.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).id}catch(e){logout();say('Sesi tidak valid, silakan masuk lagi.',1);return}\napi('/wallet/balance').then(function(r){bal=Number(r.balance);top.textContent='';top.appendChild(h('span',{t:'Saldo '+rp(bal)+'  ',style:'font-weight:700;margin-right:8px'}));top.appendChild(h('button',{class:'g',t:'Keluar',on:{click:logout}}))}).catch(function(e){if(/Unauthorized/.test(e.message)){logout();say('Sesi habis, silakan masuk lagi.',1)}else say('Gagal memuat saldo: '+e.message,1)});\n[['shop','Etalase'],['orders','Pesanan'],['sell','Jual'],['wallet','Dompet']].forEach(function(x){nav.appendChild(h('button',{class:tab===x[0]?'on':'g',t:x[1],on:{click:function(){go(x[0])}}}))});\nvar vw=({shop:shopView,orders:ordersView,sell:sellView,wallet:walletView})[tab];api('/me').then(function(r){isOwner=!!r.isOwner}).catch(function(){}).then(function(){vw(m)})}\nfunction authView(m){var b=h('div',{class:'card'},[h('h2',{t:reg?'Daftar':'Masuk'})]);\nvar f=reg?inp('n','Nama').concat(inp('e','Email','email'),inp('p','Password (min 8)','password'),inp('pin','PIN 6 digit','password','untuk transaksi')):inp('e','Email','email').concat(inp('p','Password','password'));\nf.forEach(function(x){b.appendChild(x)});\nb.appendChild(h('div',{class:'row'},[h('button',{t:reg?'Daftar':'Masuk',on:{click:function(){\nvar e=$('#e').value,p=$('#p').value;\nif(reg)run(api('/auth/register',{m:'POST',b:{name:$('#n').value,email:e,password:p,pin:$('#pin').value}}).then(function(){return api('/auth/login',{m:'POST',b:{email:e,password:p}})}).then(done));\nelse run(api('/auth/login',{m:'POST',b:{email:e,password:p}}).then(done))}}}),h('button',{class:'g',t:reg?'Sudah punya akun?':'Belum punya akun?',on:{click:function(){reg=!reg;draw()}}})]));m.appendChild(b)}\nfunction done(r){tok=r.token;localStorage.setItem('jb_tok',tok);say('');draw()}\nfunction shopView(m){var q=h('input',{placeholder:'Cari\u2026'});m.appendChild(q);var g=h('div',{class:'grid',style:'margin-top:12px'});m.appendChild(g);\nfunction load(){run(api('/listings?q='+encodeURIComponent(q.value))).then(function(ls){g.textContent='';if(!ls||!ls.length)g.appendChild(h('p',{class:'m',t:'Belum ada jualan.'}));(ls||[]).forEach(function(l){\nvar c=h('div',{class:'card'});if(l.shots.length)c.appendChild(h('div',{class:'sh'},l.shots.map(function(s){return h('img',{src:s,alt:l.title})})));\nvar b=h('div',{class:'pad'},[h('span',{class:'badge',t:(l.pinned?'\ud83d\udccc ':'')+l.category+(l.status==='RESERVED'?' \u00b7 Dipesan':'')}),h('div',{style:'font-weight:650',t:l.title}),h('div',{class:'p',t:rp(l.price)}),h('div',{class:'m',t:'Penjual: '+l.seller}),h('div',{class:'m',t:l.description||''})]);\nvar r=h('div',{class:'row'});\nif(l.seller_id===myId){if(l.status==='ACTIVE')r.appendChild(h('button',{class:'d',t:'Hapus',on:{click:function(){run(api('/listings/'+l.id,{m:'DELETE'}),'Dihapus').then(load)}}}))}\nelse{if(l.status==='ACTIVE')r.appendChild(h('button',{t:'Beli (Rekber)',on:{click:function(){var pin=prompt('PIN transaksi untuk bayar '+rp(l.price)+' (ditahan rekber):');if(!pin)return;run(api('/orders',{m:'POST',idem:1,b:{listing_id:l.id,pin:pin}}),'Dibayar & ditahan rekber. Lihat tab Pesanan.').then(function(){load();draw()})}}}));r.appendChild(h('a',{class:'wa',href:wa(l.phone),target:'_blank',rel:'noopener',t:'Tanya WA'}))}\nif(isOwner)r.appendChild(h('button',{class:'g',t:l.pinned?'Lepas pin':'\ud83d\udccc Pin',on:{click:function(){run(api('/listings/'+l.id+'/pin',{m:'POST',b:{pinned:!l.pinned}}),l.pinned?'Pin dilepas':'Dipin di atas').then(load)}}}));\nb.appendChild(r);c.appendChild(b);g.appendChild(c)})})}\nq.addEventListener('input',load);load()}\nfunction ordersView(m){run(api('/orders')).then(function(os){(os||[]).forEach(function(o){var buyer=o.buyer_id===myId;\nvar c=h('div',{class:'card'},[h('b',{t:o.title}),h('div',{class:'p',t:rp(o.amount)}),h('div',{class:'m',t:(buyer?'Anda pembeli':'Anda penjual')+' \u00b7 '+o.status})]);var r=h('div',{class:'row'});\nfunction act(path,ok,conf){return function(){if(conf&&!confirm(conf))return;run(api('/orders/'+o.id+'/'+path,{m:'POST'}),ok).then(function(){draw()})}}\nif(buyer&&(o.status==='HELD'||o.status==='DISPUTED'))r.appendChild(h('button',{class:'ok',t:'Barang diterima, cairkan',on:{click:act('confirm','Dana dicairkan ke penjual','Cairkan dana ke penjual? Tidak bisa dibatalkan.')}}));\nif(buyer&&o.status==='HELD')r.appendChild(h('button',{class:'d',t:'Komplain',on:{click:act('dispute','Komplain dikirim ke admin')}}));\nif(!buyer&&o.status==='HELD'){r.appendChild(h('button',{class:'d',t:'Batalkan & refund',on:{click:act('refund','Dana dikembalikan ke pembeli','Refund ke pembeli?')}}));}\nif(buyer)r.appendChild(h('a',{class:'wa',href:wa(o.phone),target:'_blank',rel:'noopener',t:'WA penjual'}));\nc.appendChild(r);m.appendChild(c)});if(!os||!os.length)m.appendChild(h('p',{class:'m',t:'Belum ada pesanan.'}))})}\nfunction shrink(f){return new Promise(function(ok,no){var r=new FileReader();r.onerror=no;r.onload=function(){var i=new Image();i.onerror=no;i.onload=function(){var k=Math.min(1,640/Math.max(i.width,i.height)),c=document.createElement('canvas');c.width=i.width*k;c.height=i.height*k;c.getContext('2d').drawImage(i,0,0,c.width,c.height);ok(c.toDataURL('image/jpeg',.6))};i.src=r.result};r.readAsDataURL(f)})}\nfunction sellView(m){shots=[];var b=h('div',{class:'card'},[h('h2',{t:'Pasang Jualan'})]);var fn=h('div',{class:'m'});b.appendChild(fn);api('/config').then(function(c){if(c.feePercent>0)fn.textContent='Biaya rekber '+c.feePercent+'% dipotong dari hasil penjualan.'}).catch(function(){});\ninp('t','Nama jualan').concat(inp('pr','Harga (Rp)','number'),inp('ph','No. WhatsApp','tel','08123456789'),inp('d','Deskripsi')).forEach(function(x){b.appendChild(x)});\nb.appendChild(h('label',{t:'Jenis'}));b.appendChild(h('select',{id:'c'},[h('option',{t:'Akun'}),h('option',{t:'Barang'})]));\nb.appendChild(h('label',{t:'Screenshot (maks 3)'}));var pv=h('div',{class:'row'});\nb.appendChild(h('input',{type:'file',accept:'image/*',multiple:'multiple',on:{change:function(e){Promise.all([].slice.call(e.target.files).slice(0,3-shots.length).map(shrink)).then(function(a){shots=shots.concat(a);pv.textContent='';shots.forEach(function(s){pv.appendChild(h('img',{src:s,style:'width:70px;height:70px;object-fit:cover;border-radius:8px;flex:none'}))})});e.target.value=''}}}));b.appendChild(pv);\nb.appendChild(h('div',{class:'row'},[h('button',{t:'Terbitkan',on:{click:function(){run(api('/listings',{m:'POST',b:{title:$('#t').value,category:$('#c').value,price:parseInt($('#pr').value,10),phone:$('#ph').value,description:$('#d').value,shots:shots}}),'Jualan terbit').then(function(r){if(r)go('shop')})}}})]));m.appendChild(b)}\nfunction walletView(m){var b=h('div',{class:'card'},[h('h2',{t:'Saldo '+rp(bal)})]);\ninp('ta','Top up (Rp)','number').forEach(function(x){b.appendChild(x)});\nb.appendChild(h('button',{t:'Buat tagihan top up',style:'margin-top:8px',on:{click:function(){run(api('/wallet/topup',{m:'POST',idem:1,b:{amount:parseInt($('#ta').value,10)}})).then(function(r){if(r)say('Tagihan '+r.reference+' dibuat. Saldo bertambah setelah pembayaran dikonfirmasi gateway.')})}}}));\ninp('wa','Tarik saldo (Rp)','number').concat(inp('wp','PIN','password')).forEach(function(x){b.appendChild(x)});\nb.appendChild(h('button',{class:'g',t:'Tarik',style:'margin-top:8px',on:{click:function(){run(api('/wallet/withdraw',{m:'POST',idem:1,b:{amount:parseInt($('#wa').value,10),pin:$('#wp').value}}),'Penarikan diproses').then(function(){draw()})}}}));m.appendChild(b);\nvar hi=h('div',{class:'card'},[h('b',{t:'Riwayat'})]);m.appendChild(hi);\nrun(api('/wallet/transactions')).then(function(r){(r||[]).forEach(function(x){hi.appendChild(h('div',{class:'m',t:new Date(x.created_at).toLocaleString('id-ID')+' \u00b7 '+x.type+' '+(x.direction==='CREDIT'?'+':'-')+rp(x.amount)+' \u00b7 '+x.status}))})})}\nif('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(function(){});\ndraw();\n</script></body></html>\n";

const useSsl = !/localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({ connectionString: DATABASE_URL, ssl: useSsl ? { rejectUnauthorized: false } : false });
const app = express();
app.set('trust proxy', 1); // di belakang proxy hosting: agar rate limit memakai IP pengguna asli

// CORS: isi CORS_ORIGIN (mis. https://webanda.com) hanya jika web dihosting terpisah dari API
if (process.env.CORS_ORIGIN) {
  app.use((req, res, next) => {
    res.set({
      'Access-Control-Allow-Origin': process.env.CORS_ORIGIN,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Idempotency-Key',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
}

// Simpan raw body untuk verifikasi signature webhook
app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(rateLimit({ windowMs: 60_000, limit: 100 }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 10 });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const isAmount = (n) => Number.isInteger(n) && n > 0 && n <= 100_000_000;
const ref = (p) => `${p}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;

async function withTx(fn) {
  const c = await
