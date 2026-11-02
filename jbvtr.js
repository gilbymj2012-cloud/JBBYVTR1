/**
 * JBbyVTR: MARKETPLACE + REKBER + E-WALLET (web & API dalam satu file)
 *
 * Jalankan:
 *   1. npm init -y && npm i express pg bcryptjs jsonwebtoken express-rate-limit
 *   2. Buat database kosong:  createdb ewallet
 *   3. Set env:  DATABASE_URL, JWT_SECRET, WEBHOOK_SECRET, ADMIN_KEY, (opsional) PORT
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
  CHECK (type IN ('TOPUP','TRANSFER','WITHDRAW','ESCROW_HOLD','ESCROW_RELEASE','ESCROW_REFUND'));

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
`;

const PAGE = "<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><title>JBbyVTR</title>\n<style>\n:root{--bg:#f6f7fb;--c:#fff;--t:#16181d;--m:#667085;--l:#e4e7ec;--b:#4f46e5;--bt:#fff;--g:#16a34a;--r:#dc2626;color-scheme:light dark}\n@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--c:#181b22;--t:#eef0f4;--m:#98a2b3;--l:#2a2f3a;--b:#818cf8;--bt:#10121a}}\n*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:15px/1.45 system-ui,sans-serif;padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}\n.w{max-width:960px;margin:0 auto;padding:16px}header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}h1{font-size:22px;margin:0}\nbutton{font:inherit;cursor:pointer;border:0;border-radius:10px;padding:9px 14px;background:var(--b);color:var(--bt);font-weight:600}button.g{background:none;color:var(--t);border:1px solid var(--l)}button.d{background:none;color:var(--r);border:1px solid var(--l)}button.ok{background:var(--g);color:#fff}\ninput,select,textarea{font:inherit;width:100%;padding:10px;border:1px solid var(--l);border-radius:10px;background:var(--c);color:var(--t)}label{display:block;font-size:13px;font-weight:600;margin:10px 0 4px}\nnav{display:flex;gap:6px;margin:14px 0;overflow-x:auto}nav button{white-space:nowrap}nav .on{background:var(--b);color:var(--bt)}\n.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}.card{background:var(--c);border:1px solid var(--l);border-radius:14px;padding:14px;margin-bottom:12px}.grid .card{margin:0;padding:0;overflow:hidden}.pad{padding:12px 14px}\n.sh{display:flex;overflow-x:auto;scroll-snap-type:x mandatory;background:var(--l)}.sh img{flex:0 0 100%;width:100%;height:190px;object-fit:cover;scroll-snap-align:start}\n.p{font-weight:700;font-size:18px}.m{color:var(--m);font-size:13px;white-space:pre-wrap;word-break:break-word}.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.row>*{flex:1}\n.badge{font-size:12px;padding:2px 9px;border-radius:99px;background:var(--l)}#msg{padding:0;margin:8px 0;font-size:14px}.bad{color:var(--r)}.ok2{color:var(--g)}\na.wa{text-decoration:none;text-align:center;background:var(--g);color:#fff;padding:9px;border-radius:10px;font-weight:600}\n</style></head><body><div class=\"w\"><header><h1>\ud83d\uded2 JBbyVTR</h1><div id=\"top\"></div></header><div id=\"msg\"></div><nav id=\"nav\"></nav><main id=\"main\"></main></div>\n<script>\nvar $=function(s){return document.querySelector(s)},tok=localStorage.getItem('jb_tok'),tab='shop',bal=0,reg=false,shots=[],myId=null;\nfunction h(t,a,k){var e=document.createElement(t);a=a||{};for(var x in a){if(x==='on')for(var v in a.on)e.addEventListener(v,a.on[v]);else if(x==='t')e.textContent=a[x];else e.setAttribute(x,a[x])}(k||[]).forEach(function(c){if(c)e.appendChild(c)});return e}\nfunction rp(n){return 'Rp '+Number(n).toLocaleString('id-ID')}\nfunction say(m,bad){var e=$('#msg');e.textContent=m||'';e.className=bad?'bad':'ok2'}\nfunction api(p,o){o=o||{};var hd={'Content-Type':'application/json'};if(tok)hd.Authorization='Bearer '+tok;if(o.idem)hd['Idempotency-Key']=crypto.randomUUID();\nreturn fetch(p,{method:o.m||'GET',headers:hd,body:o.b?JSON.stringify(o.b):undefined}).then(function(r){return r.json().catch(function(){return {}}).then(function(j){if(!r.ok)throw new Error(j.error||'Gagal');return j})})}\nfunction run(p,ok){say('');return p.then(function(r){if(ok)say(ok);return r}).catch(function(e){say(e.message,1)})}\nfunction wa(p){var d=String(p).replace(/\\D/g,'');if(d[0]==='0')d='62'+d.slice(1);return 'https://wa.me/'+d}\nfunction inp(id,l,t,ph){return [h('label',{t:l,for:id}),h('input',{id:id,type:t||'text',placeholder:ph||'',autocomplete:'off'})]}\nfunction go(t){tab=t;draw()}\nfunction logout(){tok=null;localStorage.removeItem('jb_tok');draw()}\nfunction draw(){var top=$('#top'),nav=$('#nav'),m=$('#main');top.textContent='';nav.textContent='';m.textContent='';\nif(!tok)return authView(m);\ntry{myId=JSON.parse(atob(tok.split('.')[1])).id}catch(e){return logout()}\napi('/wallet/balance').then(function(r){bal=Number(r.balance);top.textContent='';top.appendChild(h('span',{t:'Saldo '+rp(bal)+'  ',style:'font-weight:700;margin-right:8px'}));top.appendChild(h('button',{class:'g',t:'Keluar',on:{click:logout}}))}).catch(function(){logout()});\n[['shop','Etalase'],['orders','Pesanan'],['sell','Jual'],['wallet','Dompet']].forEach(function(x){nav.appendChild(h('button',{class:tab===x[0]?'on':'g',t:x[1],on:{click:function(){go(x[0])}}}))});\n({shop:shopView,orders:ordersView,sell:sellView,wallet:walletView})[tab](m)}\nfunction authView(m){var b=h('div',{class:'card'},[h('h2',{t:reg?'Daftar':'Masuk'})]);\nvar f=reg?inp('n','Nama').concat(inp('e','Email','email'),inp('p','Password (min 8)','password'),inp('pin','PIN 6 digit','password','untuk transaksi')):inp('e','Email','email').concat(inp('p','Password','password'));\nf.forEach(function(x){b.appendChild(x)});\nb.appendChild(h('div',{class:'row'},[h('button',{t:reg?'Daftar':'Masuk',on:{click:function(){\nvar e=$('#e').value,p=$('#p').value;\nif(reg)run(api('/auth/register',{m:'POST',b:{name:$('#n').value,email:e,password:p,pin:$('#pin').value}}).then(function(){return api('/auth/login',{m:'POST',b:{email:e,password:p}})}).then(done));\nelse run(api('/auth/login',{m:'POST',b:{email:e,password:p}}).then(done))}}}),h('button',{class:'g',t:reg?'Sudah punya akun?':'Belum punya akun?',on:{click:function(){reg=!reg;draw()}}})]));m.appendChild(b)}\nfunction done(r){tok=r.token;localStorage.setItem('jb_tok',tok);say('');draw()}\nfunction shopView(m){var q=h('input',{placeholder:'Cari\u2026'});m.appendChild(q);var g=h('div',{class:'grid',style:'margin-top:12px'});m.appendChild(g);\nfunction load(){run(api('/listings?q='+encodeURIComponent(q.value))).then(function(ls){g.textContent='';if(!ls||!ls.length)g.appendChild(h('p',{class:'m',t:'Belum ada jualan.'}));(ls||[]).forEach(function(l){\nvar c=h('div',{class:'card'});if(l.shots.length)c.appendChild(h('div',{class:'sh'},l.shots.map(function(s){return h('img',{src:s,alt:l.title})})));\nvar b=h('div',{class:'pad'},[h('span',{class:'badge',t:l.category+(l.status==='RESERVED'?' \u00b7 Dipesan':'')}),h('div',{style:'font-weight:650',t:l.title}),h('div',{class:'p',t:rp(l.price)}),h('div',{class:'m',t:'Penjual: '+l.seller}),h('div',{class:'m',t:l.description||''})]);\nvar r=h('div',{class:'row'});\nif(l.seller_id===myId){if(l.status==='ACTIVE')r.appendChild(h('button',{class:'d',t:'Hapus',on:{click:function(){run(api('/listings/'+l.id,{m:'DELETE'}),'Dihapus').then(load)}}}))}\nelse{if(l.status==='ACTIVE')r.appendChild(h('button',{t:'Beli (Rekber)',on:{click:function(){var pin=prompt('PIN transaksi untuk bayar '+rp(l.price)+' (ditahan rekber):');if(!pin)return;run(api('/orders',{m:'POST',idem:1,b:{listing_id:l.id,pin:pin}}),'Dibayar & ditahan rekber. Lihat tab Pesanan.').then(function(){load();draw()})}}}));r.appendChild(h('a',{class:'wa',href:wa(l.phone),target:'_blank',rel:'noopener',t:'Tanya WA'}))}\nb.appendChild(r);c.appendChild(b);g.appendChild(c)})})}\nq.addEventListener('input',load);load()}\nfunction ordersView(m){run(api('/orders')).then(function(os){(os||[]).forEach(function(o){var buyer=o.buyer_id===myId;\nvar c=h('div',{class:'card'},[h('b',{t:o.title}),h('div',{class:'p',t:rp(o.amount)}),h('div',{class:'m',t:(buyer?'Anda pembeli':'Anda penjual')+' \u00b7 '+o.status})]);var r=h('div',{class:'row'});\nfunction act(path,ok,conf){return function(){if(conf&&!confirm(conf))return;run(api('/orders/'+o.id+'/'+path,{m:'POST'}),ok).then(function(){draw()})}}\nif(buyer&&(o.status==='HELD'||o.status==='DISPUTED'))r.appendChild(h('button',{class:'ok',t:'Barang diterima, cairkan',on:{click:act('confirm','Dana dicairkan ke penjual','Cairkan dana ke penjual? Tidak bisa dibatalkan.')}}));\nif(buyer&&o.status==='HELD')r.appendChild(h('button',{class:'d',t:'Komplain',on:{click:act('dispute','Komplain dikirim ke admin')}}));\nif(!buyer&&o.status==='HELD'){r.appendChild(h('button',{class:'d',t:'Batalkan & refund',on:{click:act('refund','Dana dikembalikan ke pembeli','Refund ke pembeli?')}}));}\nif(buyer)r.appendChild(h('a',{class:'wa',href:wa(o.phone),target:'_blank',rel:'noopener',t:'WA penjual'}));\nc.appendChild(r);m.appendChild(c)});if(!os||!os.length)m.appendChild(h('p',{class:'m',t:'Belum ada pesanan.'}))})}\nfunction shrink(f){return new Promise(function(ok,no){var r=new FileReader();r.onerror=no;r.onload=function(){var i=new Image();i.onerror=no;i.onload=function(){var k=Math.min(1,640/Math.max(i.width,i.height)),c=document.createElement('canvas');c.width=i.width*k;c.height=i.height*k;c.getContext('2d').drawImage(i,0,0,c.width,c.height);ok(c.toDataURL('image/jpeg',.6))};i.src=r.result};r.readAsDataURL(f)})}\nfunction sellView(m){shots=[];var b=h('div',{class:'card'},[h('h2',{t:'Pasang Jualan'})]);\ninp('t','Nama jualan').concat(inp('pr','Harga (Rp)','number'),inp('ph','No. WhatsApp','tel','08123456789'),inp('d','Deskripsi')).forEach(function(x){b.appendChild(x)});\nb.appendChild(h('label',{t:'Jenis'}));b.appendChild(h('select',{id:'c'},[h('option',{t:'Akun'}),h('option',{t:'Barang'})]));\nb.appendChild(h('label',{t:'Screenshot (maks 3)'}));var pv=h('div',{class:'row'});\nb.appendChild(h('input',{type:'file',accept:'image/*',multiple:'multiple',on:{change:function(e){Promise.all([].slice.call(e.target.files).slice(0,3-shots.length).map(shrink)).then(function(a){shots=shots.concat(a);pv.textContent='';shots.forEach(function(s){pv.appendChild(h('img',{src:s,style:'width:70px;height:70px;object-fit:cover;border-radius:8px;flex:none'}))})});e.target.value=''}}}));b.appendChild(pv);\nb.appendChild(h('div',{class:'row'},[h('button',{t:'Terbitkan',on:{click:function(){run(api('/listings',{m:'POST',b:{title:$('#t').value,category:$('#c').value,price:parseInt($('#pr').value,10),phone:$('#ph').value,description:$('#d').value,shots:shots}}),'Jualan terbit').then(function(r){if(r)go('shop')})}}})]));m.appendChild(b)}\nfunction walletView(m){var b=h('div',{class:'card'},[h('h2',{t:'Saldo '+rp(bal)})]);\ninp('ta','Top up (Rp)','number').forEach(function(x){b.appendChild(x)});\nb.appendChild(h('button',{t:'Buat tagihan top up',style:'margin-top:8px',on:{click:function(){run(api('/wallet/topup',{m:'POST',idem:1,b:{amount:parseInt($('#ta').value,10)}})).then(function(r){if(r)say('Tagihan '+r.reference+' dibuat. Saldo bertambah setelah pembayaran dikonfirmasi gateway.')})}}}));\ninp('wa','Tarik saldo (Rp)','number').concat(inp('wp','PIN','password')).forEach(function(x){b.appendChild(x)});\nb.appendChild(h('button',{class:'g',t:'Tarik',style:'margin-top:8px',on:{click:function(){run(api('/wallet/withdraw',{m:'POST',idem:1,b:{amount:parseInt($('#wa').value,10),pin:$('#wp').value}}),'Penarikan diproses').then(function(){draw()})}}}));m.appendChild(b);\nvar hi=h('div',{class:'card'},[h('b',{t:'Riwayat'})]);m.appendChild(hi);\nrun(api('/wallet/transactions')).then(function(r){(r||[]).forEach(function(x){hi.appendChild(h('div',{class:'m',t:new Date(x.created_at).toLocaleString('id-ID')+' \u00b7 '+x.type+' '+(x.direction==='CREDIT'?'+':'-')+rp(x.amount)+' \u00b7 '+x.status}))})})}\ndraw();\n</script></body></html>\n";

const pool = new Pool({ connectionString: DATABASE_URL });
const app = express();

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
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK'); throw e;
  } finally { c.release(); }
}

function auth(req, _res, next) {
  const h = req.headers.authorization || '';
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch { next(new HttpError(401, 'Unauthorized')); }
}

async function checkPin(client, userId, pin) {
  const { rows } = await client.query('SELECT pin_hash FROM users WHERE id=$1', [userId]);
  if (!rows[0] || !(await bcrypt.compare(String(pin || ''), rows[0].pin_hash)))
    throw new HttpError(403, 'PIN salah');
}

function requireIdemKey(req) {
  const k = req.headers['idempotency-key'];
  if (!k || k.length > 100) throw new HttpError(400, 'Header Idempotency-Key wajib');
  return k;
}

// ---------- AUTH ----------
app.post('/auth/register', authLimiter, wrap(async (req, res) => {
  const { name, email, password, pin } = req.body;
  if (!name || !email || !password || password.length < 8 || !/^\d{6}$/.test(pin || ''))
    throw new HttpError(400, 'name, email, password (min 8), pin (6 digit) wajib');
  const [ph, pinh] = await Promise.all([bcrypt.hash(password, 12), bcrypt.hash(pin, 12)]);
  try {
    const user = await withTx(async (c) => {
      const u = await c.query(
        'INSERT INTO users(name,email,password_hash,pin_hash) VALUES($1,$2,$3,$4) RETURNING id,name,email',
        [name, email.toLowerCase(), ph, pinh]);
      await c.query('INSERT INTO wallets(user_id) VALUES($1)', [u.rows[0].id]);
      return u.rows[0];
    });
    res.status(201).json(user);
  } catch (e) {
    if (e.code === '23505') throw new HttpError(409, 'Email sudah terdaftar');
    throw e;
  }
}));

app.post('/auth/login', authLimiter, wrap(async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
  if (!rows[0] || !(await bcrypt.compare(String(password || ''), rows[0].password_hash)))
    throw new HttpError(401, 'Email atau password salah');
  const token = jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
}));

// ---------- WALLET ----------
app.get('/wallet/balance', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT balance, currency FROM wallets WHERE user_id=$1', [req.user.id]);
  res.json(rows[0]);
}));

// Top-up: buat tagihan PENDING. Saldo baru bertambah setelah webhook gateway masuk.
app.post('/wallet/topup', auth, wrap(async (req, res) => {
  const key = requireIdemKey(req);
  const { amount } = req.body;
  if (!isAmount(amount)) throw new HttpError(400, 'amount tidak valid');
  try {
    const { rows } = await pool.query(
      `INSERT INTO transactions(user_id,type,status,amount,reference,idempotency_key,description)
       VALUES($1,'TOPUP','PENDING',$2,$3,$4,'Top up saldo') RETURNING id,reference,status,amount`,
      [req.user.id, amount, ref('TOP'), key]);
    // TODO: panggil Midtrans/Xendit di sini (buat VA/QRIS) dengan reference sebagai order id
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code !== '23505') throw e;
    const { rows } = await pool.query(
      'SELECT id,reference,status,amount FROM transactions WHERE user_id=$1 AND idempotency_key=$2',
      [req.user.id, key]);
    res.json(rows[0]);
  }
}));

app.post('/wallet/transfer', auth, wrap(async (req, res) => {
  const key = requireIdemKey(req);
  const { to_email, amount, pin, description } = req.body;
  if (!isAmount(amount)) throw new HttpError(400, 'amount tidak valid');

  const run = () => withTx(async (c) => {
    await checkPin(c, req.user.id, pin);

    // Idempotency: kembalikan hasil lama jika request sudah pernah diproses
    const dup = await c.query(
      'SELECT id,reference,status,amount FROM transactions WHERE user_id=$1 AND idempotency_key=$2',
      [req.user.id, key]);
    if (dup.rows[0]) return { replay: true, tx: dup.rows[0] };

    const to = await c.query('SELECT id FROM users WHERE email=$1', [String(to_email || '').toLowerCase()]);
    if (!to.rows[0]) throw new HttpError(404, 'Penerima tidak ditemukan');
    if (to.rows[0].id === req.user.id) throw new HttpError(400, 'Tidak bisa transfer ke diri sendiri');

    // Lock kedua wallet dengan urutan id tetap agar tidak deadlock
    const locked = await c.query(
      'SELECT id,user_id,balance,status FROM wallets WHERE user_id = ANY($1) ORDER BY id FOR UPDATE',
      [[req.user.id, to.rows[0].id]]);
    const from = locked.rows.find((w) => w.user_id === req.user.id);
    const dest = locked.rows.find((w) => w.user_id === to.rows[0].id);
    if (from.status !== 'ACTIVE' || dest.status !== 'ACTIVE') throw new HttpError(403, 'Wallet tidak aktif');
    if (Number(from.balance) < amount) throw new HttpError(422, 'Saldo tidak cukup');

    const fromBal = Number(from.balance) - amount;
    const destBal = Number(dest.balance) + amount;
    await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [fromBal, from.id]);
    await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [destBal, dest.id]);

    const tx = await c.query(
      `INSERT INTO transactions(user_id,type,status,amount,reference,idempotency_key,counterparty_id,description)
       VALUES($1,'TRANSFER','SUCCESS',$2,$3,$4,$5,$6) RETURNING id,reference,status,amount`,
      [req.user.id, amount, ref('TRF'), key, to.rows[0].id, description || null]);
    await c.query(
      `INSERT INTO ledger_entries(transaction_id,wallet_id,direction,amount,balance_after)
       VALUES($1,$2,'DEBIT',$3,$4), ($1,$5,'CREDIT',$3,$6)`,
      [tx.rows[0].id, from.id, amount, fromBal, dest.id, destBal]);
    return { replay: false, tx: tx.rows[0] };
  });

  let result;
  try { result = await run(); }
  catch (e) { if (e.code === '23505') result = await run(); else throw e; } // race idempotency
  res.status(result.replay ? 200 : 201).json(result.tx);
}));

app.post('/wallet/withdraw', auth, wrap(async (req, res) => {
  const key = requireIdemKey(req);
  const { amount, pin } = req.body;
  if (!isAmount(amount)) throw new HttpError(400, 'amount tidak valid');

  const result = await withTx(async (c) => {
    await checkPin(c, req.user.id, pin);
    const dup = await c.query(
      'SELECT id,reference,status,amount FROM transactions WHERE user_id=$1 AND idempotency_key=$2',
      [req.user.id, key]);
    if (dup.rows[0]) return dup.rows[0];

    const w = (await c.query('SELECT id,balance FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.id])).rows[0];
    if (Number(w.balance) < amount) throw new HttpError(422, 'Saldo tidak cukup');
    const bal = Number(w.balance) - amount;
    await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [bal, w.id]);
    const tx = await c.query(
      `INSERT INTO transactions(user_id,type,status,amount,reference,idempotency_key,description)
       VALUES($1,'WITHDRAW','PENDING',$2,$3,$4,'Penarikan ke rekening') RETURNING id,reference,status,amount`,
      [req.user.id, amount, ref('WDR'), key]);
    await c.query(
      `INSERT INTO ledger_entries(transaction_id,wallet_id,direction,amount,balance_after)
       VALUES($1,$2,'DEBIT',$3,$4)`, [tx.rows[0].id, w.id, amount, bal]);
    // TODO: kirim disbursement ke bank/gateway; jika gagal, buat entri CREDIT pengembalian
    return tx.rows[0];
  });
  res.status(201).json(result);
}));

app.get('/wallet/transactions', auth, wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = parseInt(req.query.offset) || 0;
  const { rows } = await pool.query(
    `SELECT l.created_at, l.direction, l.amount, l.balance_after, t.type, t.status, t.reference, t.description
     FROM ledger_entries l
     JOIN wallets w ON w.id = l.wallet_id
     JOIN transactions t ON t.id = l.transaction_id
     WHERE w.user_id = $1
     ORDER BY l.created_at DESC, l.id DESC LIMIT $2 OFFSET $3`,
    [req.user.id, limit, offset]);
  res.json(rows);
}));

// ---------- WEBHOOK ----------
// Body: { reference, status: "PAID" | "FAILED" }. Header: x-signature = HMAC-SHA256(rawBody, WEBHOOK_SECRET)
// Sesuaikan format dengan dokumentasi gateway yang dipakai.
app.post('/webhooks/payment', wrap(async (req, res) => {
  const sig = Buffer.from(String(req.headers['x-signature'] || ''), 'hex');
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(req.rawBody || '').digest();
  if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected))
    throw new HttpError(401, 'Signature tidak valid');

  const { reference, status } = req.body;
  await withTx(async (c) => {
    const t = (await c.query('SELECT * FROM transactions WHERE reference=$1 FOR UPDATE', [reference])).rows[0];
    if (!t || t.type !== 'TOPUP') throw new HttpError(404, 'Transaksi tidak ditemukan');
    if (t.status !== 'PENDING') return; // sudah diproses: aman diulang
    if (status !== 'PAID') {
      await c.query("UPDATE transactions SET status='FAILED' WHERE id=$1", [t.id]);
      return;
    }
    const w = (await c.query('SELECT id,balance FROM wallets WHERE user_id=$1 FOR UPDATE', [t.user_id])).rows[0];
    const bal = Number(w.balance) + Number(t.amount);
    await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [bal, w.id]);
    await c.query("UPDATE transactions SET status='SUCCESS' WHERE id=$1", [t.id]);
    await c.query(
      `INSERT INTO ledger_entries(transaction_id,wallet_id,direction,amount,balance_after)
       VALUES($1,$2,'CREDIT',$3,$4)`, [t.id, w.id, t.amount, bal]);
  });
  res.json({ ok: true });
}));

// ---------- MARKETPLACE + REKBER ----------
const UUID = /^[0-9a-f-]{36}$/i;
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
function adminOnly(req, _res, next) {
  if (ADMIN_KEY && crypto.timingSafeEqual(sha(req.headers['x-admin-key'] || ''), sha(ADMIN_KEY))) return next();
  next(new HttpError(401, 'Unauthorized'));
}

app.get('/', (_req, res) => res.type('html').send(PAGE));

app.get('/listings', wrap(async (req, res) => {
  const q = `%${String(req.query.q || '').slice(0, 50).replace(/[%_]/g, '')}%`;
  const { rows } = await pool.query(
    `SELECT l.id, l.seller_id, u.name AS seller, l.title, l.category, l.price, l.description, l.phone, l.shots, l.status
     FROM listings l JOIN users u ON u.id = l.seller_id
     WHERE l.status IN ('ACTIVE','RESERVED') AND l.title ILIKE $1
     ORDER BY l.created_at DESC LIMIT 100`, [q]);
  res.json(rows);
}));

app.post('/listings', auth, wrap(async (req, res) => {
  const { title, category, price, phone, description, shots = [] } = req.body;
  const digits = String(phone || '').replace(/\D/g, '');
  if (!title || String(title).length > 80 || !['Akun', 'Barang'].includes(category) || !isAmount(price) ||
      digits.length < 9 || digits.length > 15) throw new HttpError(400, 'Data jualan tidak valid');
  if (!Array.isArray(shots) || shots.length > 3 ||
      shots.some((s) => typeof s !== 'string' || !s.startsWith('data:image/jpeg;base64,') || s.length > 200000))
    throw new HttpError(400, 'Screenshot tidak valid (maks 3 gambar JPEG)');
  const { rows } = await pool.query(
    `INSERT INTO listings(seller_id,title,category,price,phone,description,shots)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
    [req.user.id, String(title).trim(), category, price, digits, String(description || '').slice(0, 500), JSON.stringify(shots)]);
  res.status(201).json(rows[0]);
}));

app.delete('/listings/:id', auth, wrap(async (req, res) => {
  if (!UUID.test(req.params.id)) throw new HttpError(404, 'Tidak ditemukan');
  const { rowCount } = await pool.query(
    "UPDATE listings SET status='REMOVED' WHERE id=$1 AND seller_id=$2 AND status='ACTIVE'", [req.params.id, req.user.id]);
  if (!rowCount) throw new HttpError(404, 'Jualan tidak ditemukan atau sedang dipesan');
  res.json({ ok: true });
}));

// Beli: dana dipotong dari saldo pembeli dan DITAHAN (status HELD) sampai pembeli konfirmasi
app.post('/orders', auth, wrap(async (req, res) => {
  const key = requireIdemKey(req);
  const { listing_id, pin } = req.body;
  if (!UUID.test(String(listing_id))) throw new HttpError(400, 'listing_id tidak valid');
  const out = await withTx(async (c) => {
    await checkPin(c, req.user.id, pin);
    const dup = await c.query(
      `SELECT o.id,o.status,o.amount FROM orders o JOIN transactions t ON t.id=o.hold_tx_id
       WHERE t.user_id=$1 AND t.idempotency_key=$2`, [req.user.id, key]);
    if (dup.rows[0]) return dup.rows[0];

    const l = (await c.query('SELECT * FROM listings WHERE id=$1 FOR UPDATE', [listing_id])).rows[0];
    if (!l || l.status !== 'ACTIVE') throw new HttpError(409, 'Barang tidak tersedia');
    if (l.seller_id === req.user.id) throw new HttpError(400, 'Tidak bisa membeli jualan sendiri');
    const w = (await c.query('SELECT id,balance FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.id])).rows[0];
    const amount = Number(l.price);
    if (Number(w.balance) < amount) throw new HttpError(422, 'Saldo tidak cukup');
    const bal = Number(w.balance) - amount;
    await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [bal, w.id]);
    const tx = (await c.query(
      `INSERT INTO transactions(user_id,type,status,amount,reference,idempotency_key,counterparty_id,description)
       VALUES($1,'ESCROW_HOLD','SUCCESS',$2,$3,$4,$5,$6) RETURNING id`,
      [req.user.id, amount, ref('ESC'), key, l.seller_id, 'Rekber: ' + l.title])).rows[0];
    await c.query(
      `INSERT INTO ledger_entries(transaction_id,wallet_id,direction,amount,balance_after) VALUES($1,$2,'DEBIT',$3,$4)`,
      [tx.id, w.id, amount, bal]);
    const o = (await c.query(
      'INSERT INTO orders(listing_id,buyer_id,seller_id,amount,hold_tx_id) VALUES($1,$2,$3,$4,$5) RETURNING id,status,amount',
      [l.id, req.user.id, l.seller_id, amount, tx.id])).rows[0];
    await c.query("UPDATE listings SET status='RESERVED' WHERE id=$1", [l.id]);
    return o;
  });
  res.status(201).json(out);
}));

// Cairkan dana rekber ke penjual ('seller') atau kembalikan ke pembeli ('buyer')
async function settle(c, id, to, allowed, check) {
  if (!UUID.test(String(id))) throw new HttpError(404, 'Pesanan tidak ditemukan');
  const o = (await c.query(
    'SELECT o.*, l.title FROM orders o JOIN listings l ON l.id=o.listing_id WHERE o.id=$1 FOR UPDATE OF o', [id])).rows[0];
  if (!o) throw new HttpError(404, 'Pesanan tidak ditemukan');
  if (!check(o)) throw new HttpError(403, 'Tidak diizinkan');
  if (!allowed.includes(o.status)) throw new HttpError(409, 'Status pesanan: ' + o.status);
  const toSeller = to === 'seller';
  const rid = toSeller ? o.seller_id : o.buyer_id;
  const w = (await c.query('SELECT id,balance FROM wallets WHERE user_id=$1 FOR UPDATE', [rid])).rows[0];
  const bal = Number(w.balance) + Number(o.amount);
  await c.query('UPDATE wallets SET balance=$1, updated_at=now() WHERE id=$2', [bal, w.id]);
  const tx = (await c.query(
    `INSERT INTO transactions(user_id,type,status,amount,reference,counterparty_id,description)
     VALUES($1,$2,'SUCCESS',$3,$4,$5,$6) RETURNING id`,
    [rid, toSeller ? 'ESCROW_RELEASE' : 'ESCROW_REFUND', o.amount, ref('ESC'),
     toSeller ? o.buyer_id : o.seller_id, (toSeller ? 'Dana rekber cair: ' : 'Refund rekber: ') + o.title])).rows[0];
  await c.query(
    `INSERT INTO ledger_entries(transaction_id,wallet_id,direction,amount,balance_after) VALUES($1,$2,'CREDIT',$3,$4)`,
    [tx.id, w.id, o.amount, bal]);
  const status = toSeller ? 'COMPLETED' : 'REFUNDED';
  await c.query('UPDATE orders SET status=$2, updated_at=now() WHERE id=$1', [o.id, status]);
  await c.query('UPDATE listings SET status=$2 WHERE id=$1', [o.listing_id, toSeller ? 'SOLD' : 'ACTIVE']);
  return { id: o.id, status };
}

app.get('/orders', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT o.id,o.status,o.amount,o.buyer_id,o.seller_id,o.created_at,l.title,l.phone
     FROM orders o JOIN listings l ON l.id=o.listing_id
     WHERE o.buyer_id=$1 OR o.seller_id=$1 ORDER BY o.created_at DESC LIMIT 100`, [req.user.id]);
  res.json(rows);
}));

app.post('/orders/:id/confirm', auth, wrap(async (req, res) => {   // pembeli: barang diterima
  res.json(await withTx((c) => settle(c, req.params.id, 'seller', ['HELD', 'DISPUTED'], (o) => o.buyer_id === req.user.id)));
}));
app.post('/orders/:id/refund', auth, wrap(async (req, res) => {    // penjual: batalkan, uang kembali
  res.json(await withTx((c) => settle(c, req.params.id, 'buyer', ['HELD'], (o) => o.seller_id === req.user.id)));
}));
app.post('/orders/:id/dispute', auth, wrap(async (req, res) => {   // pembeli: komplain ke admin
  if (!UUID.test(req.params.id)) throw new HttpError(404, 'Pesanan tidak ditemukan');
  const { rows } = await pool.query(
    "UPDATE orders SET status='DISPUTED', updated_at=now() WHERE id=$1 AND buyer_id=$2 AND status='HELD' RETURNING id,status",
    [req.params.id, req.user.id]);
  if (!rows[0]) throw new HttpError(409, 'Pesanan tidak bisa dikomplain');
  res.json(rows[0]);
}));
// Admin: putuskan sengketa. Header x-admin-key, body { to: "seller" | "buyer" }
app.post('/admin/orders/:id/resolve', adminOnly, wrap(async (req, res) => {
  const to = req.body.to === 'buyer' ? 'buyer' : 'seller';
  res.json(await withTx((c) => settle(c, req.params.id, to, ['DISPUTED'], () => true)));
}));
app.get('/admin/disputes', adminOnly, wrap(async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT o.id,o.amount,o.buyer_id,o.seller_id,l.title,o.updated_at FROM orders o
     JOIN listings l ON l.id=o.listing_id WHERE o.status='DISPUTED' ORDER BY o.updated_at`);
  res.json(rows);
}));

// ---------- ERROR HANDLER ----------
app.use((err, _req, res, _next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Terjadi kesalahan server' });
});

pool.query(SCHEMA)
  .then(() => app.listen(PORT, () => console.log(`E-wallet API jalan di :${PORT}`)))
  .catch((e) => { console.error('Gagal inisialisasi database:', e.message); process.exit(1); });
