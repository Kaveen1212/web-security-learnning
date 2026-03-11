// ── phases.js — Part 1: Phase 0 (Mindset) + Phase 1 (Network) ──
const phases = [

// ════════════════════════════════════════════════════════════
// PHASE 0 — Security Mindset
// ════════════════════════════════════════════════════════════
{
  id:0, color:'#94a3b8', label:'PHASE 00', level:'ABSOLUTE BEGINNER',
  title:'Security Mindset', subtitle:'Think like an attacker to defend like a pro',
  navName:'Security Mindset', badge:'START',
  desc:'Before writing a single line of secure code, you need the right mindset. Security is not a feature you add at the end — it is a way of thinking. This phase has zero prerequisites.',
  concepts:[
    { icon:'🔒', name:'CIA Triad', desc:'Confidentiality (only right people see data), Integrity (data not tampered), Availability (systems stay up). Every security decision maps to one of these.' },
    { icon:'🧅', name:'Defence in Depth', desc:'Never rely on one layer. Layer multiple defences so one failure does not mean total compromise. Like an onion — peel one, there is another.' },
    { icon:'📋', name:'Least Privilege', desc:'Give users and services the minimum access they need. Nothing more. A compromised low-privilege account causes far less damage.' },
    { icon:'💥', name:'Threat Modelling', desc:'Ask: What am I protecting? From whom? What happens if it breaks? Do this for every feature, not just the whole system.' },
    { icon:'🎯', name:'Attack Surface', desc:'Every endpoint, input field, dependency and open port is a potential entry point. Reduce it. Disable what you do not need.' },
    { icon:'🚫', name:'Fail Securely', desc:'When something breaks, deny by default. A login failure should lock — not open. Errors must never reveal stack traces to users.' },
  ],
  examples:[
    {
      file:'first_secure_app.py', lang:'Python — Beginner',
      code:`<span class="c"># ── The #1 mistake beginners make: hardcoding secrets ──────</span>

<span class="i">import</span> os
<span class="i">from</span> <span class="cl">dotenv</span> <span class="i">import</span> load_dotenv   <span class="c"># pip install python-dotenv</span>

<span class="c"># ❌ WRONG — anyone who reads your code sees this</span>
DB_PASSWORD = <span class="s">"mypassword123"</span>
API_KEY     = <span class="s">"sk-live-abc123secret"</span>   <span class="c"># commit to Git → exposed!</span>
SECRET_KEY  = <span class="s">"supersecret"</span>

<span class="c"># ✅ RIGHT — load from environment, never hardcode</span>
load_dotenv()                           <span class="c"># reads .env file</span>
DB_PASSWORD = os.<span class="f">getenv</span>(<span class="s">"DB_PASSWORD"</span>)
API_KEY     = os.<span class="f">getenv</span>(<span class="s">"API_KEY"</span>)
SECRET_KEY  = os.<span class="f">getenv</span>(<span class="s">"SECRET_KEY"</span>)

<span class="c"># ── Your .env file (NEVER commit this — add to .gitignore) ──</span>
<span class="c"># DB_PASSWORD=mypassword123</span>
<span class="c"># API_KEY=sk-live-abc123secret</span>
<span class="c"># SECRET_KEY=supersecret</span>

<span class="c"># ── Guard: crash early if secrets are missing ───────────────</span>
<span class="k">def</span> <span class="f">require_env</span>(*keys):
    <span class="k">for</span> key <span class="k">in</span> keys:
        <span class="k">if not</span> os.<span class="f">getenv</span>(key):
            <span class="k">raise</span> <span class="cl">RuntimeError</span>(<span class="s">f"Missing required env var: {key}"</span>)

<span class="f">require_env</span>(<span class="s">"DB_PASSWORD"</span>, <span class="s">"SECRET_KEY"</span>)  <span class="c"># crash at startup, not at runtime</span>

<span class="c"># ── The 6 Golden Rules (memorise these) ─────────────────────</span>
GOLDEN_RULES = [
    <span class="s">"1. Never hardcode secrets — use environment variables"</span>,
    <span class="s">"2. Never trust user input — validate and sanitise everything"</span>,
    <span class="s">"3. Fail securely — deny by default, not allow by default"</span>,
    <span class="s">"4. Least privilege — minimum access needed, nothing more"</span>,
    <span class="s">"5. Defence in depth — multiple layers, not one magic fix"</span>,
    <span class="s">"6. Keep it simple — complexity is the enemy of security"</span>,
]`
    },
    {
      file:'cia_triad_demo.py', lang:'Python — CIA Triad in code',
      code:`<span class="i">import</span> hashlib, hmac, os
<span class="i">from</span> <span class="cl">cryptography.fernet</span> <span class="i">import</span> <span class="cl">Fernet</span>

<span class="c"># ── C: CONFIDENTIALITY — only authorised people see data ────</span>
<span class="c"># Encrypt sensitive data so even if stolen, it is unreadable</span>
key        = <span class="cl">Fernet</span>.<span class="f">generate_key</span>()    <span class="c"># AES-128 key</span>
cipher     = <span class="cl">Fernet</span>(key)
plaintext  = <span class="s">b"User SSN: 123-45-6789"</span>
ciphertext = cipher.<span class="f">encrypt</span>(plaintext)  <span class="c"># ✅ encrypted blob</span>
decrypted  = cipher.<span class="f">decrypt</span>(ciphertext) <span class="c"># only works with key</span>

<span class="c"># ── I: INTEGRITY — data has not been tampered with ──────────</span>
<span class="c"># HMAC: Hash-based Message Authentication Code</span>
<span class="c"># Proves data came from you AND was not modified</span>
secret   = os.<span class="f">urandom</span>(<span class="n">32</span>)                     <span class="c"># shared secret</span>
message  = <span class="s">b"Transfer $100 to Alice"</span>
mac      = hmac.<span class="f">new</span>(secret, message, hashlib.<span class="cl">sha256</span>).<span class="f">hexdigest</span>()

<span class="c"># Verify: receiver computes same HMAC and compares</span>
expected = hmac.<span class="f">new</span>(secret, message, hashlib.<span class="cl">sha256</span>).<span class="f">hexdigest</span>()
is_valid = hmac.<span class="f">compare_digest</span>(mac, expected)   <span class="c"># constant-time compare!</span>

<span class="c"># ── A: AVAILABILITY — system stays up under attack ──────────</span>
<span class="k">def</span> <span class="f">health_check</span>():
    <span class="s">"""Endpoint /health — load balancers use this to route traffic"""</span>
    checks = {
        <span class="s">"database"</span>: <span class="f">check_db_connection</span>(),
        <span class="s">"cache"</span>:    <span class="f">check_redis_connection</span>(),
    }
    healthy = <span class="f">all</span>(checks.<span class="f">values</span>())
    <span class="k">return</span> {<span class="s">"status"</span>: <span class="s">"ok"</span> <span class="k">if</span> healthy <span class="k">else</span> <span class="s">"degraded"</span>, <span class="s">"checks"</span>: checks}

<span class="c"># ── Fail securely: errors must NOT leak info to users ───────</span>
<span class="k">def</span> <span class="f">safe_login</span>(username, password):
    <span class="k">try</span>:
        <span class="k">return</span> <span class="f">do_login</span>(username, password)
    <span class="k">except</span> <span class="cl">Exception</span>:
        <span class="c"># ❌ WRONG: return {"error": str(e)}  ← leaks stack trace!</span>
        <span class="k">return</span> {<span class="s">"error"</span>: <span class="s">"Login failed"</span>}, <span class="n">401</span>  <span class="c"># ✅ generic message</span>`
    }
  ],
  steps:[
    { title:'Install python-dotenv', desc:'Create a .env file, add it to .gitignore immediately. Never commit it.', install:'pip install python-dotenv' },
    { title:'Read OWASP Top 10', desc:'The 10 most critical web vulnerabilities. Bookmark owasp.org/Top10 and read it today.', install:null },
    { title:'Run Bandit on your code', desc:'Static security analyser for Python. It flags hardcoded secrets, dangerous functions and more.', install:'pip install bandit && bandit -r .' },
    { title:'Run Safety on your dependencies', desc:'Checks every package in requirements.txt for known CVEs.', install:'pip install safety && safety check' },
    { title:'Create a .gitignore', desc:'Add: .env, *.key, *.pem, secrets/, __pycache__/, .DS_Store. Do this before your first commit.', install:null },
  ],
  libs:[
    { name:'python-dotenv', desc:'Load .env files into environment' },
    { name:'bandit', desc:'Static security analysis for Python' },
    { name:'safety', desc:'Check dependencies for known CVEs' },
    { name:'cryptography', desc:'Modern crypto primitives (used in all phases)' },
  ],
  callout:{ type:'info', label:'MINDSET SHIFT',
    text:'Security is not a checkbox. It is a <b>habit</b>. Ask yourself for every function you write: "How could an attacker abuse this input?" That one question will catch 80% of vulnerabilities before they are ever deployed.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 1 — Layer 1: Network Security
// ════════════════════════════════════════════════════════════
{
  id:1, color:'#38bdf8', label:'PHASE 01', level:'BEGINNER',
  title:'Layer 1 — Network Security',
  subtitle:'CORS · HTTPS · Security Headers · Firewall',
  navName:'Network Security', badge:'L1',
  layer:1, layerDesc:'CORS · HTTPS · Firewall',
  desc:'The outermost defence layer. Every HTTP request hits this layer first. Misconfigured CORS is one of the top causes of data theft. Without HTTPS, all traffic is readable by anyone on the network.',
  concepts:[
    { icon:'🌐', name:'CORS', desc:'Cross-Origin Resource Sharing. Controls which domains can call your API. A wildcard (*) origin lets ANY website read your API responses — dangerous for authenticated APIs.' },
    { icon:'🔐', name:'HTTPS / TLS', desc:'Encrypts all traffic between client and server. Without it, passwords, tokens, and data travel as plain text — readable by any network observer (coffee shop Wi-Fi attack).' },
    { icon:'🛡️', name:'Security Headers', desc:'HTTP response headers that instruct browsers to block attacks. HSTS, CSP, X-Frame-Options, X-Content-Type-Options — each prevents a specific class of attack.' },
    { icon:'🔥', name:'Firewall', desc:'Allows or denies traffic based on IP, port, and protocol. Block everything, then whitelist what you need. Block port 22 from the public internet if possible.' },
    { icon:'📋', name:'HSTS', desc:'HTTP Strict Transport Security. Tells browsers: always use HTTPS, never HTTP. Prevents SSL stripping attacks where an attacker downgrades your connection.' },
    { icon:'🧱', name:'CSP', desc:'Content Security Policy. Tells the browser which scripts, styles, and resources are allowed to load. The strongest defence against XSS attacks.' },
  ],
  examples:[
    {
      file:'cors_and_headers.py', lang:'Python / FastAPI',
      code:`<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">Request</span>, <span class="cl">Response</span>
<span class="i">from</span> <span class="cl">fastapi.middleware.cors</span> <span class="i">import</span> <span class="cl">CORSMiddleware</span>
<span class="i">from</span> <span class="cl">starlette.middleware.base</span> <span class="i">import</span> <span class="cl">BaseHTTPMiddleware</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── CORS Configuration ───────────────────────────────────────</span>
<span class="c"># CORS controls which websites can call your API from a browser</span>

<span class="c"># ❌ WRONG — wildcard allows ANY website to read responses</span>
<span class="c"># app.add_middleware(CORSMiddleware, allow_origins=["*"])</span>

<span class="c"># ✅ RIGHT — explicit list of trusted domains</span>
ALLOWED_ORIGINS = [
    <span class="s">"https://myapp.com"</span>,           <span class="c"># your production frontend</span>
    <span class="s">"https://www.myapp.com"</span>,
    <span class="s">"http://localhost:3000"</span>,        <span class="c"># dev only — remove in production!</span>
]

app.<span class="f">add_middleware</span>(
    <span class="cl">CORSMiddleware</span>,
    allow_origins=ALLOWED_ORIGINS,  <span class="c"># only these domains</span>
    allow_credentials=<span class="k">True</span>,         <span class="c"># allow cookies / auth headers</span>
    allow_methods=[<span class="s">"GET"</span>, <span class="s">"POST"</span>, <span class="s">"PUT"</span>, <span class="s">"DELETE"</span>],
    allow_headers=[<span class="s">"Authorization"</span>, <span class="s">"Content-Type"</span>],
    max_age=<span class="n">3600</span>,                   <span class="c"># cache preflight for 1 hour</span>
)

<span class="c"># ── Security Headers Middleware ──────────────────────────────</span>
<span class="c"># These headers tell the browser how to behave securely</span>
<span class="k">class</span> <span class="cl">SecurityHeadersMiddleware</span>(<span class="cl">BaseHTTPMiddleware</span>):
    <span class="k">async def</span> <span class="f">dispatch</span>(self, request: <span class="cl">Request</span>, call_next):
        response = <span class="k">await</span> <span class="f">call_next</span>(request)

        <span class="c"># Force HTTPS for 1 year — browsers will refuse plain HTTP</span>
        response.headers[<span class="s">"Strict-Transport-Security"</span>] = <span class="s">"max-age=31536000; includeSubDomains"</span>

        <span class="c"># Block clickjacking — no one can embed your site in an iframe</span>
        response.headers[<span class="s">"X-Frame-Options"</span>] = <span class="s">"DENY"</span>

        <span class="c"># Stop browser from guessing content types (MIME sniffing attack)</span>
        response.headers[<span class="s">"X-Content-Type-Options"</span>] = <span class="s">"nosniff"</span>

        <span class="c"># Don't send your URL to other sites when following links</span>
        response.headers[<span class="s">"Referrer-Policy"</span>] = <span class="s">"strict-origin-when-cross-origin"</span>

        <span class="c"># CSP: only load scripts/styles from your own domain</span>
        response.headers[<span class="s">"Content-Security-Policy"</span>] = (
            <span class="s">"default-src 'self'; "</span>
            <span class="s">"script-src 'self'; "</span>       <span class="c"># no inline scripts, no CDN</span>
            <span class="s">"style-src 'self'; "</span>
            <span class="s">"img-src 'self' data:; "</span>
            <span class="s">"frame-ancestors 'none'"</span>    <span class="c"># extra clickjacking protection</span>
        )

        <span class="c"># Hide what server software you are running</span>
        response.headers[<span class="s">"Server"</span>] = <span class="s">"unknown"</span>
        <span class="k">return</span> response

app.<span class="f">add_middleware</span>(<span class="cl">SecurityHeadersMiddleware</span>)

<span class="c"># ── HTTPS redirect — send all HTTP to HTTPS ─────────────────</span>
<span class="d">@app.middleware</span>(<span class="s">"http"</span>)
<span class="k">async def</span> <span class="f">force_https</span>(request: <span class="cl">Request</span>, call_next):
    <span class="k">if</span> request.url.scheme == <span class="s">"http"</span>:
        https_url = request.url.<span class="f">replace</span>(scheme=<span class="s">"https"</span>)
        <span class="k">return</span> <span class="cl">Response</span>(status_code=<span class="n">301</span>, headers={<span class="s">"Location"</span>: <span class="f">str</span>(https_url)})
    <span class="k">return</span> <span class="k">await</span> <span class="f">call_next</span>(request)`
    },
    {
      file:'ip_firewall_middleware.py', lang:'Python — IP Firewall',
      code:`<span class="i">import</span> os
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">Request</span>
<span class="i">from</span> <span class="cl">fastapi.responses</span> <span class="i">import</span> <span class="cl">JSONResponse</span>
<span class="i">from</span> <span class="cl">starlette.middleware.base</span> <span class="i">import</span> <span class="cl">BaseHTTPMiddleware</span>
<span class="i">import</span> ipaddress, logging

app = <span class="cl">FastAPI</span>()

<span class="c"># ── IP Firewall Middleware ───────────────────────────────────</span>
<span class="c"># Block known bad IPs and only allow trusted ones for admin routes</span>

<span class="c"># Blocklist: IPs you know are malicious</span>
IP_BLOCKLIST = {
    <span class="s">"203.0.113.5"</span>,    <span class="c"># known attacker</span>
    <span class="s">"198.51.100.2"</span>,   <span class="c"># banned IP</span>
}

<span class="c"># Allowlist for admin routes: ONLY these IPs can access /admin</span>
ADMIN_ALLOWLIST = {
    <span class="s">"127.0.0.1"</span>,       <span class="c"># localhost</span>
    <span class="s">"10.0.0.0/8"</span>,      <span class="c"># private network CIDR</span>
}

<span class="k">def</span> <span class="f">get_client_ip</span>(request: <span class="cl">Request</span>) -> str:
    <span class="c"># X-Forwarded-For is set by load balancers/proxies</span>
    forwarded = request.headers.<span class="f">get</span>(<span class="s">"X-Forwarded-For"</span>)
    <span class="k">if</span> forwarded:
        <span class="k">return</span> forwarded.<span class="f">split</span>(<span class="s">","</span>)[<span class="n">0</span>].<span class="f">strip</span>()  <span class="c"># first IP is the client</span>
    <span class="k">return</span> request.client.host

<span class="k">def</span> <span class="f">ip_in_cidr</span>(ip: str, cidr_set: set) -> bool:
    <span class="s">"""Check if IP is in any CIDR range in the set"""</span>
    client = ipaddress.<span class="f">ip_address</span>(ip)
    <span class="k">for</span> entry <span class="k">in</span> cidr_set:
        <span class="k">try</span>:
            <span class="k">if</span> client <span class="k">in</span> ipaddress.<span class="f">ip_network</span>(entry, strict=<span class="k">False</span>):
                <span class="k">return</span> <span class="k">True</span>
        <span class="k">except</span> <span class="cl">ValueError</span>:
            <span class="k">if</span> ip == entry:   <span class="c"># exact IP match</span>
                <span class="k">return</span> <span class="k">True</span>
    <span class="k">return</span> <span class="k">False</span>

<span class="k">class</span> <span class="cl">FirewallMiddleware</span>(<span class="cl">BaseHTTPMiddleware</span>):
    <span class="k">async def</span> <span class="f">dispatch</span>(self, request: <span class="cl">Request</span>, call_next):
        ip = <span class="f">get_client_ip</span>(request)

        <span class="c"># 1. Block known bad IPs immediately</span>
        <span class="k">if</span> ip <span class="k">in</span> IP_BLOCKLIST:
            logging.<span class="f">warning</span>(<span class="s">f"Blocked IP: {ip} → {request.url.path}"</span>)
            <span class="k">return</span> <span class="cl">JSONResponse</span>({<span class="s">"error"</span>: <span class="s">"Forbidden"</span>}, status_code=<span class="n">403</span>)

        <span class="c"># 2. Admin routes only accessible from trusted IPs</span>
        <span class="k">if</span> request.url.path.<span class="f">startswith</span>(<span class="s">"/admin"</span>):
            <span class="k">if not</span> <span class="f">ip_in_cidr</span>(ip, ADMIN_ALLOWLIST):
                logging.<span class="f">warning</span>(<span class="s">f"Admin access denied for IP: {ip}"</span>)
                <span class="k">return</span> <span class="cl">JSONResponse</span>({<span class="s">"error"</span>: <span class="s">"Forbidden"</span>}, status_code=<span class="n">403</span>)

        <span class="k">return</span> <span class="k">await</span> <span class="f">call_next</span>(request)

app.<span class="f">add_middleware</span>(<span class="cl">FirewallMiddleware</span>)`
    }
  ],
  steps:[
    { title:'Install FastAPI + uvicorn', desc:'FastAPI gives you CORS middleware and async request handling out of the box.', install:'pip install fastapi uvicorn python-multipart' },
    { title:'Get a free TLS certificate', desc:"Use Let's Encrypt (certbot) for free HTTPS. In production, your hosting provider (Nginx, Caddy, AWS ALB) handles TLS termination.", install:'sudo apt install certbot' },
    { title:'Test your headers', desc:'Run securityheaders.com on your domain. It grades your HTTP security headers A to F. Aim for A+.', install:null },
    { title:'Enable HSTS preloading', desc:'Once you add HSTS, submit your domain to hstspreload.org — browsers will always use HTTPS before even connecting.', install:null },
    { title:'Scan with nmap', desc:'Run nmap on your own server to see what ports are open. Close everything except 80 and 443.', install:'sudo apt install nmap && nmap -sV your-ip' },
  ],
  libs:[
    { name:'fastapi', desc:'CORS + security middleware built-in' },
    { name:'uvicorn', desc:'ASGI server with TLS support' },
    { name:'httpx', desc:'HTTP client for testing your endpoints' },
    { name:'certbot', desc:"Let's Encrypt TLS certificates" },
  ],
  callout:{ type:'warn', label:'COMMON MISTAKE',
    text:'<b>Never set CORS allow_origins=["*"] on an authenticated API.</b> This lets any website make requests to your API using the visitor\'s cookies. The correct setting is an explicit list of your own domains. Wildcard is only safe for fully public, read-only APIs with no authentication.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 2 — Layer 2: Authentication
// ════════════════════════════════════════════════════════════
{
  id:2, color:'#34d399', label:'PHASE 02', level:'BEGINNER',
  title:'Layer 2 — Authentication',
  subtitle:'JWT · Google OAuth · Sessions · 2FA',
  navName:'Authentication', badge:'L2',
  layer:2, layerDesc:'JWT · Google OAuth',
  desc:'Authentication answers the question: WHO are you? Before your app can decide what someone can do, it must know who they are. JWT and OAuth2 are the two most common modern approaches.',
  concepts:[
    { icon:'🎫', name:'JWT — JSON Web Token', desc:'A self-contained token with 3 parts: Header.Payload.Signature. The server signs it with a secret key. No database lookup needed to verify — just re-compute the signature.' },
    { icon:'🔄', name:'Access + Refresh Tokens', desc:'Access tokens are short-lived (15 min). Refresh tokens are long-lived (7 days) and stored securely. When access expires, use refresh to get a new one without re-login.' },
    { icon:'🌐', name:'OAuth2 / Google Login', desc:'Delegate authentication to Google/GitHub. You never touch the user\'s password. Flow: redirect → user logs in → Google gives you a code → exchange for token.' },
    { icon:'🔑', name:'State Parameter', desc:'A random secret you send to OAuth provider and get back. Verifying it prevents CSRF attacks on your OAuth callback — without it, attackers can hijack login.' },
    { icon:'🚫', name:'Token Blacklist', desc:'JWTs cannot be "un-issued" — a logout must invalidate the token. Store the token JTI (unique ID) in Redis with expiry equal to the token\'s remaining lifetime.' },
    { icon:'📱', name:'TOTP — 2FA', desc:'Time-based One-Time Password. Google Authenticator generates a 6-digit code every 30 seconds using a shared secret. Even if password is stolen, attacker needs your phone.' },
  ],
  examples:[
    {
      file:'jwt_auth.py', lang:'Python / FastAPI + PyJWT',
      code:`<span class="i">import</span> jwt, secrets, os
<span class="i">from</span> <span class="cl">datetime</span> <span class="i">import</span> datetime, timedelta, timezone
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">HTTPException</span>, <span class="cl">Depends</span>
<span class="i">from</span> <span class="cl">fastapi.security</span> <span class="i">import</span> <span class="cl">HTTPBearer</span>, <span class="cl">HTTPAuthorizationCredentials</span>

app    = <span class="cl">FastAPI</span>()
bearer = <span class="cl">HTTPBearer</span>()

<span class="c"># ── Config ───────────────────────────────────────────────────</span>
SECRET_KEY     = os.<span class="f">getenv</span>(<span class="s">"SECRET_KEY"</span>)   <span class="c"># min 32 random bytes</span>
ALGORITHM      = <span class="s">"HS256"</span>
ACCESS_EXPIRE  = timedelta(minutes=<span class="n">15</span>)      <span class="c"># short-lived</span>
REFRESH_EXPIRE = timedelta(days=<span class="n">7</span>)          <span class="c"># long-lived</span>

<span class="c"># In production: use Redis. Here: in-memory for simplicity</span>
token_blacklist: set = <span class="f">set</span>()

<span class="c"># ── Create tokens ────────────────────────────────────────────</span>
<span class="k">def</span> <span class="f">create_access_token</span>(user_id: str) -> str:
    now = datetime.<span class="f">now</span>(timezone.utc)
    payload = {
        <span class="s">"sub"</span>:  user_id,              <span class="c"># subject: who this token is for</span>
        <span class="s">"iat"</span>:  now,                  <span class="c"># issued at</span>
        <span class="s">"exp"</span>:  now + ACCESS_EXPIRE,  <span class="c"># expiry — verified automatically</span>
        <span class="s">"jti"</span>:  secrets.<span class="f">token_hex</span>(<span class="n">16</span>),<span class="c"># unique ID — used for blacklist</span>
        <span class="s">"type"</span>: <span class="s">"access"</span>,
    }
    <span class="k">return</span> jwt.<span class="f">encode</span>(payload, SECRET_KEY, algorithm=ALGORITHM)

<span class="k">def</span> <span class="f">create_refresh_token</span>(user_id: str) -> str:
    now = datetime.<span class="f">now</span>(timezone.utc)
    payload = {
        <span class="s">"sub"</span>:  user_id,
        <span class="s">"exp"</span>:  now + REFRESH_EXPIRE,
        <span class="s">"jti"</span>:  secrets.<span class="f">token_hex</span>(<span class="n">16</span>),
        <span class="s">"type"</span>: <span class="s">"refresh"</span>,
    }
    <span class="k">return</span> jwt.<span class="f">encode</span>(payload, SECRET_KEY, algorithm=ALGORITHM)

<span class="c"># ── Verify token ─────────────────────────────────────────────</span>
<span class="k">def</span> <span class="f">verify_token</span>(token: str, expected_type: str = <span class="s">"access"</span>) -> dict:
    <span class="k">try</span>:
        payload = jwt.<span class="f">decode</span>(token, SECRET_KEY, algorithms=[ALGORITHM])
    <span class="k">except</span> jwt.<span class="cl">ExpiredSignatureError</span>:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">401</span>, <span class="s">"Token expired"</span>)
    <span class="k">except</span> jwt.<span class="cl">InvalidTokenError</span>:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">401</span>, <span class="s">"Invalid token"</span>)

    <span class="k">if</span> payload[<span class="s">"type"</span>] != expected_type:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">401</span>, <span class="s">"Wrong token type"</span>)

    <span class="c"># Check blacklist — has this token been revoked?</span>
    <span class="k">if</span> payload[<span class="s">"jti"</span>] <span class="k">in</span> token_blacklist:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">401</span>, <span class="s">"Token has been revoked"</span>)

    <span class="k">return</span> payload

<span class="c"># ── Auth dependency — inject into any route ──────────────────</span>
<span class="k">def</span> <span class="f">get_current_user</span>(creds: <span class="cl">HTTPAuthorizationCredentials</span> = <span class="cl">Depends</span>(bearer)):
    <span class="k">return</span> <span class="f">verify_token</span>(creds.credentials)

<span class="c"># ── Routes ───────────────────────────────────────────────────</span>
<span class="d">@app.post</span>(<span class="s">"/login"</span>)
<span class="k">async def</span> <span class="f">login</span>(email: str, password: str):
    user = <span class="f">authenticate_user</span>(email, password)  <span class="c"># your DB lookup</span>
    <span class="k">return</span> {
        <span class="s">"access_token"</span>:  <span class="f">create_access_token</span>(user.id),
        <span class="s">"refresh_token"</span>: <span class="f">create_refresh_token</span>(user.id),
    }

<span class="d">@app.post</span>(<span class="s">"/logout"</span>)
<span class="k">async def</span> <span class="f">logout</span>(user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
    token_blacklist.<span class="f">add</span>(user[<span class="s">"jti"</span>])  <span class="c"># revoke this token</span>
    <span class="k">return</span> {<span class="s">"message"</span>: <span class="s">"Logged out"</span>}

<span class="d">@app.get</span>(<span class="s">"/me"</span>)
<span class="k">async def</span> <span class="f">me</span>(user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
    <span class="k">return</span> {<span class="s">"user_id"</span>: user[<span class="s">"sub"</span>]}`
    },
    {
      file:'google_oauth.py', lang:'Python — Google OAuth2 Flow',
      code:`<span class="i">import</span> secrets, os
<span class="i">import</span> httpx
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">Request</span>, <span class="cl">HTTPException</span>
<span class="i">from</span> <span class="cl">fastapi.responses</span> <span class="i">import</span> <span class="cl">RedirectResponse</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── Google OAuth2 credentials ────────────────────────────────</span>
GOOGLE_CLIENT_ID     = os.<span class="f">getenv</span>(<span class="s">"GOOGLE_CLIENT_ID"</span>)
GOOGLE_CLIENT_SECRET = os.<span class="f">getenv</span>(<span class="s">"GOOGLE_CLIENT_SECRET"</span>)
REDIRECT_URI         = <span class="s">"https://myapp.com/auth/callback"</span>

<span class="c"># Temporary store for state tokens (use Redis in production)</span>
oauth_states: dict = {}

<span class="c"># ── Step 1: Redirect user to Google ─────────────────────────</span>
<span class="d">@app.get</span>(<span class="s">"/auth/google"</span>)
<span class="k">async def</span> <span class="f">google_login</span>(request: <span class="cl">Request</span>):
    <span class="c"># State: random token to prevent CSRF on the callback</span>
    state = secrets.<span class="f">token_urlsafe</span>(<span class="n">32</span>)
    oauth_states[state] = <span class="k">True</span>           <span class="c"># remember it server-side</span>

    params = {
        <span class="s">"client_id"</span>:     GOOGLE_CLIENT_ID,
        <span class="s">"redirect_uri"</span>:  REDIRECT_URI,
        <span class="s">"response_type"</span>: <span class="s">"code"</span>,
        <span class="s">"scope"</span>:         <span class="s">"openid email profile"</span>,
        <span class="s">"state"</span>:         state,           <span class="c"># CSRF protection</span>
        <span class="s">"prompt"</span>:        <span class="s">"select_account"</span>,
    }
    url = <span class="s">"https://accounts.google.com/o/oauth2/v2/auth?"</span>
    url += <span class="s">"&"</span>.<span class="f">join</span>(<span class="s">f"{k}={v}"</span> <span class="k">for</span> k, v <span class="k">in</span> params.<span class="f">items</span>())
    <span class="k">return</span> <span class="cl">RedirectResponse</span>(url)

<span class="c"># ── Step 2: Google redirects back with a code ────────────────</span>
<span class="d">@app.get</span>(<span class="s">"/auth/callback"</span>)
<span class="k">async def</span> <span class="f">google_callback</span>(code: str, state: str):
    <span class="c"># CRITICAL: verify state matches what we sent — prevents CSRF</span>
    <span class="k">if</span> state <span class="k">not in</span> oauth_states:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">400</span>, <span class="s">"Invalid state — possible CSRF attack"</span>)
    <span class="k">del</span> oauth_states[state]              <span class="c"># one-time use</span>

    <span class="c"># Step 3: Exchange code for access token</span>
    <span class="k">async with</span> httpx.<span class="cl">AsyncClient</span>() <span class="k">as</span> client:
        token_resp = <span class="k">await</span> client.<span class="f">post</span>(
            <span class="s">"https://oauth2.googleapis.com/token"</span>,
            data={
                <span class="s">"code"</span>:          code,
                <span class="s">"client_id"</span>:     GOOGLE_CLIENT_ID,
                <span class="s">"client_secret"</span>: GOOGLE_CLIENT_SECRET,
                <span class="s">"redirect_uri"</span>:  REDIRECT_URI,
                <span class="s">"grant_type"</span>:    <span class="s">"authorization_code"</span>,
            }
        )
    token_data = token_resp.<span class="f">json</span>()

    <span class="c"># Step 4: Get user info from Google</span>
    <span class="k">async with</span> httpx.<span class="cl">AsyncClient</span>() <span class="k">as</span> client:
        user_resp = <span class="k">await</span> client.<span class="f">get</span>(
            <span class="s">"https://www.googleapis.com/oauth2/v3/userinfo"</span>,
            headers={<span class="s">"Authorization"</span>: <span class="s">f"Bearer {token_data['access_token']}"</span>}
        )
    user_info = user_resp.<span class="f">json</span>()
    <span class="c"># user_info = {"sub": "1234", "email": "user@gmail.com", "name": "..."}</span>

    <span class="c"># Step 5: Create your own JWT for this user</span>
    access_token = <span class="f">create_access_token</span>(user_info[<span class="s">"sub"</span>])
    <span class="k">return</span> {<span class="s">"access_token"</span>: access_token, <span class="s">"user"</span>: user_info}`
    }
  ],
  steps:[
    { title:'Install PyJWT', desc:'PyJWT is the standard JWT library for Python. Also install passlib for password hashing.', install:'pip install pyjwt[crypto] passlib[bcrypt]' },
    { title:'Create Google OAuth credentials', desc:'Go to console.cloud.google.com → Create project → Enable Google Identity API → Create OAuth 2.0 Client ID. Never expose the client secret.', install:null },
    { title:'Store refresh tokens securely', desc:'Refresh tokens must be stored in an httpOnly cookie (not localStorage) or server-side in Redis. httpOnly cookies cannot be read by JavaScript.', install:'pip install redis' },
    { title:'Add TOTP two-factor auth', desc:'Use pyotp to generate TOTP secrets. Users scan a QR code with Google Authenticator.', install:'pip install pyotp qrcode[pil]' },
    { title:'Test with jwt.io', desc:'Paste any JWT into jwt.io to decode and inspect the payload. Never put production secrets there.', install:null },
  ],
  libs:[
    { name:'pyjwt', desc:'Create and verify JSON Web Tokens' },
    { name:'httpx', desc:'Async HTTP client for OAuth flows' },
    { name:'pyotp', desc:'TOTP two-factor authentication' },
    { name:'passlib', desc:'Password hashing (bcrypt, argon2)' },
  ],
  callout:{ type:'danger', label:'NEVER DO THIS',
    text:'<b>Never store JWTs in localStorage.</b> JavaScript can read it — any XSS attack on your page will steal all your users\' tokens. Store access tokens in memory (JS variable) and refresh tokens in an <b>httpOnly cookie</b>. httpOnly cookies are invisible to JavaScript, even on an XSS-compromised page.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 3 — Layer 3: Authorization (RBAC)
// ════════════════════════════════════════════════════════════
{
  id:3, color:'#a78bfa', label:'PHASE 03', level:'INTERMEDIATE',
  title:'Layer 3 — Authorization',
  subtitle:'RBAC · Permissions · Ownership Checks',
  navName:'Authorization / RBAC', badge:'L3',
  layer:3, layerDesc:'RBAC · Role Checking',
  desc:'Authorization answers: WHAT can you do? Authentication says who you are. Authorization decides what you are allowed to access. Most data breaches happen not from broken auth but from missing authorisation checks.',
  concepts:[
    { icon:'👑', name:'RBAC', desc:'Role-Based Access Control. Users are assigned roles (admin, editor, viewer). Roles have permissions. Never give permissions directly to users — always through roles.' },
    { icon:'🗝️', name:'Permissions', desc:'Granular capabilities: read:users, write:posts, delete:comments. A role is just a named bundle of permissions. Always check the permission, not the role name, in code.' },
    { icon:'🏠', name:'Resource Ownership', desc:'Even with the right role, you must check: does this user OWN this resource? User 1 cannot edit User 2\'s post, even if both are "editors".' },
    { icon:'🚧', name:'IDOR — Insecure Direct Object Reference', desc:'The #1 access control bug: GET /invoices/99 where invoice 99 belongs to another user. Always filter DB queries by owner_id = current_user.id.' },
    { icon:'🔗', name:'Middleware vs Route-level', desc:'Middleware checks protect all routes at once (coarse-grained). Route-level checks are for fine-grained control. Use both: middleware for auth, route-level for ownership.' },
    { icon:'📊', name:'Deny by Default', desc:'Every route should require explicit permission. Never allow by default and deny specific routes. If you forget to add a deny, everything is open.' },
  ],
  examples:[
    {
      file:'rbac_system.py', lang:'Python / FastAPI — RBAC',
      code:`<span class="i">from</span> <span class="cl">enum</span> <span class="i">import</span> <span class="cl">Enum</span>
<span class="i">from</span> <span class="cl">functools</span> <span class="i">import</span> wraps
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">HTTPException</span>, <span class="cl">Depends</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── Define Roles ─────────────────────────────────────────────</span>
<span class="k">class</span> <span class="cl">Role</span>(<span class="cl">str</span>, <span class="cl">Enum</span>):
    ADMIN  = <span class="s">"admin"</span>
    EDITOR = <span class="s">"editor"</span>
    VIEWER = <span class="s">"viewer"</span>

<span class="c"># ── Define Permissions ───────────────────────────────────────</span>
<span class="c"># Format: "action:resource" — easy to read and extend</span>
<span class="k">class</span> <span class="cl">Permission</span>(<span class="cl">str</span>, <span class="cl">Enum</span>):
    READ_USERS    = <span class="s">"read:users"</span>
    WRITE_USERS   = <span class="s">"write:users"</span>
    DELETE_USERS  = <span class="s">"delete:users"</span>
    READ_POSTS    = <span class="s">"read:posts"</span>
    WRITE_POSTS   = <span class="s">"write:posts"</span>
    DELETE_POSTS  = <span class="s">"delete:posts"</span>
    MANAGE_SYSTEM = <span class="s">"manage:system"</span>

<span class="c"># ── Role → Permissions mapping ───────────────────────────────</span>
ROLE_PERMISSIONS: dict[<span class="cl">Role</span>, set] = {
    <span class="cl">Role</span>.ADMIN: {   <span class="c"># admin can do everything</span>
        <span class="cl">Permission</span>.READ_USERS, <span class="cl">Permission</span>.WRITE_USERS, <span class="cl">Permission</span>.DELETE_USERS,
        <span class="cl">Permission</span>.READ_POSTS, <span class="cl">Permission</span>.WRITE_POSTS, <span class="cl">Permission</span>.DELETE_POSTS,
        <span class="cl">Permission</span>.MANAGE_SYSTEM,
    },
    <span class="cl">Role</span>.EDITOR: {  <span class="c"># editor can read users and manage posts</span>
        <span class="cl">Permission</span>.READ_USERS,
        <span class="cl">Permission</span>.READ_POSTS, <span class="cl">Permission</span>.WRITE_POSTS, <span class="cl">Permission</span>.DELETE_POSTS,
    },
    <span class="cl">Role</span>.VIEWER: {  <span class="c"># viewer is read-only</span>
        <span class="cl">Permission</span>.READ_USERS,
        <span class="cl">Permission</span>.READ_POSTS,
    },
}

<span class="k">def</span> <span class="f">has_permission</span>(role: <span class="cl">Role</span>, permission: <span class="cl">Permission</span>) -> bool:
    <span class="k">return</span> permission <span class="k">in</span> ROLE_PERMISSIONS.<span class="f">get</span>(role, <span class="f">set</span>())

<span class="c"># ── Dependency: require a specific permission ────────────────</span>
<span class="k">def</span> <span class="f">require</span>(permission: <span class="cl">Permission</span>):
    <span class="k">async def</span> <span class="f">checker</span>(user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
        <span class="c"># get_current_user returns the JWT payload from Phase 2</span>
        user_role = <span class="cl">Role</span>(user[<span class="s">"role"</span>])
        <span class="k">if not</span> <span class="f">has_permission</span>(user_role, permission):
            <span class="k">raise</span> <span class="cl">HTTPException</span>(
                status_code=<span class="n">403</span>,
                detail=<span class="s">f"Permission denied: requires {permission}"</span>
            )
        <span class="k">return</span> user
    <span class="k">return</span> checker

<span class="c"># ── Protected Routes ─────────────────────────────────────────</span>
<span class="d">@app.get</span>(<span class="s">"/users"</span>)
<span class="k">async def</span> <span class="f">list_users</span>(user = <span class="cl">Depends</span>(<span class="f">require</span>(<span class="cl">Permission</span>.READ_USERS))):
    <span class="k">return</span> {<span class="s">"users"</span>: []}   <span class="c"># only admins + editors reach here</span>

<span class="d">@app.delete</span>(<span class="s">"/users/{user_id}"</span>)
<span class="k">async def</span> <span class="f">delete_user</span>(user_id: str, user = <span class="cl">Depends</span>(<span class="f">require</span>(<span class="cl">Permission</span>.DELETE_USERS))):
    <span class="k">return</span> {<span class="s">"deleted"</span>: user_id}  <span class="c"># only admins reach here</span>

<span class="d">@app.get</span>(<span class="s">"/admin/system"</span>)
<span class="k">async def</span> <span class="f">system_settings</span>(user = <span class="cl">Depends</span>(<span class="f">require</span>(<span class="cl">Permission</span>.MANAGE_SYSTEM))):
    <span class="k">return</span> {<span class="s">"settings"</span>: {}}   <span class="c"># only admins reach here</span>`
    },
    {
      file:'idor_prevention.py', lang:'Python — Ownership Checks',
      code:`<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">HTTPException</span>, <span class="cl">Depends</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── IDOR: Insecure Direct Object Reference ───────────────────</span>
<span class="c"># The attacker changes the ID in the URL to access other users' data</span>

<span class="c"># ❌ WRONG — no ownership check — User 1 can read User 99's invoice</span>
<span class="d">@app.get</span>(<span class="s">"/invoices/{invoice_id}"</span>)
<span class="k">async def</span> <span class="f">get_invoice_VULNERABLE</span>(invoice_id: int):
    invoice = <span class="k">await</span> db.<span class="f">get</span>(<span class="s">f"SELECT * FROM invoices WHERE id={invoice_id}"</span>)
    <span class="k">return</span> invoice  <span class="c"># returns ANY invoice — IDOR vulnerability!</span>

<span class="c"># ✅ RIGHT — always scope query to current user's ID</span>
<span class="d">@app.get</span>(<span class="s">"/invoices/{invoice_id}"</span>)
<span class="k">async def</span> <span class="f">get_invoice</span>(invoice_id: int, user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
    invoice = <span class="k">await</span> db.<span class="f">fetchone</span>(
        <span class="s">"SELECT * FROM invoices WHERE id = $1 AND owner_id = $2"</span>,
        invoice_id, user[<span class="s">"sub"</span>]         <span class="c"># MUST include owner_id filter!</span>
    )
    <span class="k">if not</span> invoice:
        <span class="c"># Return 404 — NOT 403 — never confirm that the resource exists!</span>
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">404</span>, <span class="s">"Invoice not found"</span>)
    <span class="k">return</span> invoice

<span class="c"># ── Ownership check helper (reusable) ────────────────────────</span>
<span class="k">async def</span> <span class="f">owned_by</span>(resource, user_id: str):
    <span class="s">"""Raise 404 if resource does not belong to this user.
    Use 404 not 403 — do not confirm the resource exists."""</span>
    <span class="k">if not</span> resource <span class="k">or</span> resource[<span class="s">"owner_id"</span>] != user_id:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">404</span>, <span class="s">"Not found"</span>)

<span class="c"># ── Admin override: admins can see anything ──────────────────</span>
<span class="k">async def</span> <span class="f">get_post_with_ownership</span>(post_id: int, user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
    post = <span class="k">await</span> db.<span class="f">fetchone</span>(<span class="s">"SELECT * FROM posts WHERE id = $1"</span>, post_id)
    user_role = <span class="cl">Role</span>(user[<span class="s">"role"</span>])

    <span class="c"># Admins bypass ownership check — everyone else must own it</span>
    <span class="k">if</span> user_role != <span class="cl">Role</span>.ADMIN:
        <span class="k">await</span> <span class="f">owned_by</span>(post, user[<span class="s">"sub"</span>])

    <span class="k">return</span> post

<span class="c"># ── Bulk queries: ALWAYS filter by owner ─────────────────────</span>
<span class="k">async def</span> <span class="f">list_my_orders</span>(user = <span class="cl">Depends</span>(<span class="f">get_current_user</span>)):
    <span class="c"># ❌ WRONG: SELECT * FROM orders</span>
    <span class="c"># ✅ RIGHT: filter by user ID at the database level</span>
    <span class="k">return</span> <span class="k">await</span> db.<span class="f">fetch</span>(
        <span class="s">"SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC"</span>,
        user[<span class="s">"sub"</span>]
    )`
    }
  ],
  steps:[
    { title:'Define your roles first', desc:'Before writing a single route, draw a table: roles vs resources vs actions. This becomes your ROLE_PERMISSIONS dict.', install:null },
    { title:'Always filter DB queries by owner', desc:'Every SELECT that returns user data must have a WHERE owner_id = ? clause. Make this a code-review rule.', install:null },
    { title:'Use Depends() for auth checking', desc:"FastAPI's Depends() system is perfect for RBAC — it composes cleanly and is tested in isolation.", install:'pip install fastapi' },
    { title:'Test with wrong user tokens', desc:'Create two test users. Log in as User A. Try to access User B\'s resources. Every attempt must return 404, never the data.', install:null },
    { title:'Consider Casbin for complex RBAC', desc:'For large systems with complex hierarchical roles and attribute-based access, Casbin is the industry standard Python RBAC library.', install:'pip install casbin' },
  ],
  libs:[
    { name:'fastapi', desc:'Depends() system for auth injection' },
    { name:'casbin', desc:'Complex RBAC / ABAC policies' },
    { name:'sqlalchemy', desc:'ORM with user-scoped query helpers' },
    { name:'pytest', desc:'Write tests for every permission combination' },
  ],
  callout:{ type:'danger', label:'MOST COMMON BUG',
    text:'<b>IDOR is the #1 authorisation vulnerability.</b> Returning 403 (Forbidden) instead of 404 (Not Found) when a user accesses another user\'s resource leaks information — it confirms the resource exists. Always return 404. An attacker iterating IDs 1–10000 can harvest a full user list just from 403 responses.' }
},


// ════════════════════════════════════════════════════════════
// PHASE 4 — Layer 4: Rate Limiting
// ════════════════════════════════════════════════════════════
{
  id:4, color:'#fb923c', label:'PHASE 04', level:'INTERMEDIATE',
  title:'Layer 4 — Rate Limiting',
  subtitle:'Brute-Force Protection · Token Bucket · Account Lockout',
  navName:'Rate Limiting', badge:'L4',
  layer:4, layerDesc:'Brute-Force Protection',
  desc:'Rate limiting is your defence against automated attacks. Without it, an attacker can try millions of passwords per minute, scrape your entire database, or overwhelm your server. Every public endpoint needs a limit.',
  concepts:[
    { icon:'🪣', name:'Token Bucket', desc:'A bucket holds N tokens. Each request costs one token. Tokens refill at a fixed rate. When empty, requests are rejected. Natural, burst-friendly algorithm.' },
    { icon:'🪟', name:'Sliding Window', desc:'Count requests in the last N seconds. More accurate than fixed windows which allow double the limit at window boundaries. Preferred for login endpoints.' },
    { icon:'🔐', name:'Brute-Force Protection', desc:'Limit login attempts per username AND per IP separately. An attacker with many IPs but targeting one account must be caught by the username limit.' },
    { icon:'🔒', name:'Account Lockout', desc:'After N failed attempts, lock the account for X minutes. Send an email alert to the real user. Progressive delays (1s, 2s, 4s) slow automated attacks without full lockout.' },
    { icon:'📦', name:'Redis-Based Limiting', desc:'In-memory counters reset when your server restarts. Use Redis for distributed, persistent rate limiting that survives deploys and works across multiple servers.' },
    { icon:'⚠️', name:'Denial-of-Service', desc:'Rate limiting is also a DoS defence. Without it, an attacker sends 10,000 requests/second to a slow endpoint, consuming all your server resources.' },
  ],
  examples:[
    {
      file:'rate_limiter.py', lang:'Python — Token Bucket + Sliding Window',
      code:`<span class="i">import</span> time, redis
<span class="i">from</span> <span class="cl">collections</span> <span class="i">import</span> defaultdict
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">Request</span>, <span class="cl">HTTPException</span>
<span class="i">from</span> <span class="cl">starlette.middleware.base</span> <span class="i">import</span> <span class="cl">BaseHTTPMiddleware</span>

app = <span class="cl">FastAPI</span>()
r   = redis.<span class="cl">Redis</span>(host=<span class="s">"localhost"</span>, port=<span class="n">6379</span>, decode_responses=<span class="k">True</span>)

<span class="c"># ── Algorithm 1: Token Bucket ────────────────────────────────</span>
<span class="c"># Each user has a bucket of tokens. Requests consume tokens.</span>
<span class="c"># Tokens refill over time. Natural burst support.</span>
<span class="k">class</span> <span class="cl">TokenBucket</span>:
    <span class="k">def</span> <span class="f">__init__</span>(self, capacity: int, refill_rate: float):
        self.capacity    = capacity      <span class="c"># max tokens (burst size)</span>
        self.refill_rate = refill_rate   <span class="c"># tokens added per second</span>
        self._buckets: dict = {}

    <span class="k">def</span> <span class="f">consume</span>(self, key: str, tokens: int = <span class="n">1</span>) -> bool:
        now    = time.<span class="f">time</span>()
        bucket = self._buckets.<span class="f">get</span>(key, {<span class="s">"tokens"</span>: self.capacity, <span class="s">"last"</span>: now})

        <span class="c"># Refill: add tokens based on time elapsed since last request</span>
        elapsed       = now - bucket[<span class="s">"last"</span>]
        bucket[<span class="s">"tokens"</span>] = <span class="f">min</span>(
            self.capacity,
            bucket[<span class="s">"tokens"</span>] + elapsed * self.refill_rate
        )
        bucket[<span class="s">"last"</span>] = now

        <span class="k">if</span> bucket[<span class="s">"tokens"</span>] >= tokens:
            bucket[<span class="s">"tokens"</span>] -= tokens   <span class="c"># consume token</span>
            self._buckets[key] = bucket
            <span class="k">return</span> <span class="k">True</span>                 <span class="c"># allowed</span>
        self._buckets[key] = bucket
        <span class="k">return</span> <span class="k">False</span>                    <span class="c"># rejected</span>

<span class="c"># ── Algorithm 2: Sliding Window (Redis-backed) ───────────────</span>
<span class="c"># More accurate for login endpoints — counts last N seconds</span>
<span class="k">def</span> <span class="f">sliding_window_check</span>(key: str, limit: int, window_secs: int) -> bool:
    now      = time.<span class="f">time</span>()
    pipe     = r.<span class="f">pipeline</span>()
    pipe.<span class="f">zremrangebyscore</span>(key, <span class="n">0</span>, now - window_secs) <span class="c"># remove old entries</span>
    pipe.<span class="f">zadd</span>(key, {<span class="s">f"{now}"</span>: now})                   <span class="c"># add this request</span>
    pipe.<span class="f">zcard</span>(key)                                    <span class="c"># count requests in window</span>
    pipe.<span class="f">expire</span>(key, window_secs)
    results = pipe.<span class="f">execute</span>()
    count   = results[<span class="n">2</span>]
    <span class="k">return</span> count <= limit  <span class="c"># True = allowed</span>

<span class="c"># ── Middleware: apply rate limiting to every request ─────────</span>
bucket = <span class="cl">TokenBucket</span>(capacity=<span class="n">100</span>, refill_rate=<span class="n">10</span>)  <span class="c"># 10 req/sec, burst 100</span>

<span class="k">class</span> <span class="cl">RateLimitMiddleware</span>(<span class="cl">BaseHTTPMiddleware</span>):
    <span class="k">async def</span> <span class="f">dispatch</span>(self, request: <span class="cl">Request</span>, call_next):
        ip = request.client.host

        <span class="c"># Stricter limit for auth endpoints (sliding window via Redis)</span>
        <span class="k">if</span> request.url.path <span class="k">in</span> (<span class="s">"/login"</span>, <span class="s">"/register"</span>):
            allowed = <span class="f">sliding_window_check</span>(<span class="s">f"login:{ip}"</span>, limit=<span class="n">5</span>, window_secs=<span class="n">60</span>)
        <span class="k">else</span>:
            allowed = bucket.<span class="f">consume</span>(ip)  <span class="c"># general limit</span>

        <span class="k">if not</span> allowed:
            <span class="k">raise</span> <span class="cl">HTTPException</span>(
                status_code=<span class="n">429</span>,
                detail=<span class="s">"Too many requests"</span>,
                headers={<span class="s">"Retry-After"</span>: <span class="s">"60"</span>}  <span class="c"># tell client when to retry</span>
            )
        <span class="k">return</span> <span class="k">await</span> <span class="f">call_next</span>(request)

app.<span class="f">add_middleware</span>(<span class="cl">RateLimitMiddleware</span>)`
    },
    {
      file:'brute_force_protection.py', lang:'Python — Account Lockout',
      code:`<span class="i">import</span> time, redis, secrets
<span class="i">from</span> <span class="cl">dataclasses</span> <span class="i">import</span> dataclass, field
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">HTTPException</span>

app = <span class="cl">FastAPI</span>()
r   = redis.<span class="cl">Redis</span>(host=<span class="s">"localhost"</span>, decode_responses=<span class="k">True</span>)

<span class="c"># ── Config ───────────────────────────────────────────────────</span>
MAX_ATTEMPTS  = <span class="n">5</span>       <span class="c"># lock after 5 failed logins</span>
LOCKOUT_SECS  = <span class="n">900</span>     <span class="c"># lock for 15 minutes</span>
ATTEMPT_WINDOW= <span class="n">300</span>     <span class="c"># count attempts in last 5 min</span>

<span class="k">def</span> <span class="f">record_failed_attempt</span>(username: str, ip: str):
    <span class="c"># Track per username (password spray from many IPs)</span>
    key_user = <span class="s">f"fails:user:{username}"</span>
    <span class="c"># Track per IP (credential stuffing from one IP)</span>
    key_ip   = <span class="s">f"fails:ip:{ip}"</span>

    <span class="k">for</span> key <span class="k">in</span> (key_user, key_ip):
        r.<span class="f">incr</span>(key)
        r.<span class="f">expire</span>(key, ATTEMPT_WINDOW)  <span class="c"># auto-expire after window</span>

<span class="k">def</span> <span class="f">is_locked_out</span>(username: str, ip: str) -> tuple[bool, int]:
    <span class="c"># Check account lockout</span>
    lock_key = <span class="s">f"lock:{username}"</span>
    ttl      = r.<span class="f">ttl</span>(lock_key)
    <span class="k">if</span> ttl > <span class="n">0</span>:
        <span class="k">return</span> <span class="k">True</span>, ttl         <span class="c"># locked — return seconds remaining</span>

    <span class="c"># Check attempt counts</span>
    user_fails = <span class="f">int</span>(r.<span class="f">get</span>(<span class="s">f"fails:user:{username}"</span>) <span class="k">or</span> <span class="n">0</span>)
    ip_fails   = <span class="f">int</span>(r.<span class="f">get</span>(<span class="s">f"fails:ip:{ip}"</span>) <span class="k">or</span> <span class="n">0</span>)

    <span class="k">if</span> user_fails >= MAX_ATTEMPTS <span class="k">or</span> ip_fails >= MAX_ATTEMPTS * <span class="n">3</span>:
        r.<span class="f">setex</span>(<span class="s">f"lock:{username}"</span>, LOCKOUT_SECS, <span class="s">"locked"</span>)
        <span class="k">return</span> <span class="k">True</span>, LOCKOUT_SECS

    <span class="k">return</span> <span class="k">False</span>, <span class="n">0</span>

<span class="k">def</span> <span class="f">clear_failed_attempts</span>(username: str, ip: str):
    <span class="c"># Successful login — reset counters</span>
    r.<span class="f">delete</span>(<span class="s">f"fails:user:{username}"</span>, <span class="s">f"fails:ip:{ip}"</span>, <span class="s">f"lock:{username}"</span>)

<span class="c"># ── Login endpoint with full brute-force protection ──────────</span>
<span class="d">@app.post</span>(<span class="s">"/login"</span>)
<span class="k">async def</span> <span class="f">login</span>(email: str, password: str, request=<span class="k">None</span>):
    ip = request.client.host

    <span class="c"># 1. Check lockout BEFORE doing any DB queries</span>
    locked, wait = <span class="f">is_locked_out</span>(email, ip)
    <span class="k">if</span> locked:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">429</span>,
            <span class="s">f"Account locked. Try again in {wait // 60} minutes."</span>)

    <span class="c"># 2. Attempt authentication</span>
    user = <span class="k">await</span> <span class="f">db_get_user</span>(email)

    <span class="c"># IMPORTANT: verify even if user not found (prevent user enumeration)</span>
    password_correct = user <span class="k">and</span> <span class="f">verify_password</span>(password, user.password_hash)

    <span class="k">if not</span> password_correct:
        <span class="f">record_failed_attempt</span>(email, ip)
        <span class="c"># Same error message whether user exists or not!</span>
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">401</span>, <span class="s">"Invalid email or password"</span>)

    <span class="c"># 3. Success — clear failed attempts</span>
    <span class="f">clear_failed_attempts</span>(email, ip)
    <span class="k">return</span> {<span class="s">"access_token"</span>: <span class="f">create_access_token</span>(user.id)}`
    }
  ],
  steps:[
    { title:'Install Redis', desc:'Redis is required for distributed rate limiting that persists across server restarts.', install:'pip install redis && docker run -d -p 6379:6379 redis' },
    { title:'Use slowapi for FastAPI', desc:'slowapi is a drop-in rate limiter for FastAPI built on limits library. One decorator = rate limited.', install:'pip install slowapi' },
    { title:'Test your limits', desc:"Use locust or k6 to simulate thousands of requests. Verify 429 responses kick in at the right threshold.", install:'pip install locust' },
    { title:'Add Retry-After header', desc:'HTTP 429 responses must include a Retry-After header. This tells clients and crawlers when to try again. Without it, they hammer you instantly on retry.', install:null },
    { title:'Set different limits per endpoint', desc:'Login: 5/min. API reads: 100/min. File uploads: 10/hour. Write-heavy endpoints need tighter limits than reads.', install:null },
  ],
  libs:[
    { name:'slowapi', desc:'FastAPI rate limiting decorator' },
    { name:'redis', desc:'Distributed counters and lockout storage' },
    { name:'limits', desc:'Rate limit algorithms (token bucket, sliding window)' },
    { name:'locust', desc:'Load test your rate limiting thresholds' },
  ],
  callout:{ type:'warn', label:'CRITICAL DETAIL',
    text:'<b>Always rate-limit per username AND per IP separately.</b> Per-IP only: attacker uses a botnet (thousands of IPs). Per-username only: attacker targets 10,000 different usernames from one IP. You need both. Also: use the same error message and response time whether the username exists or not — otherwise you leak a user enumeration vulnerability.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 5 — Layer 5: Input Validation & Sanitization
// ════════════════════════════════════════════════════════════
{
  id:5, color:'#f43f5e', label:'PHASE 05', level:'INTERMEDIATE',
  title:'Layer 5 — Input Security',
  subtitle:'Validation · SQL Injection · XSS · CSRF',
  navName:'Input Validation', badge:'L5',
  layer:5, layerDesc:'Validation · Sanitization',
  desc:'Never trust input from the outside world — users, APIs, files, even your own database. This layer prevents the most common and most damaging web vulnerabilities: SQL injection, XSS, and CSRF.',
  concepts:[
    { icon:'💉', name:'SQL Injection', desc:'User input goes directly into a SQL query: WHERE name=\'{input}\'. Attacker sends: \' OR 1=1 --  to bypass auth. Always use parameterized queries or an ORM.' },
    { icon:'📜', name:'XSS — Cross-Site Scripting', desc:'Attacker injects <script>steal_cookies()</script> into input that is later displayed to other users. The script runs in their browser with full access to their session.' },
    { icon:'🎭', name:'CSRF — Cross-Site Request Forgery', desc:'A malicious site tricks your logged-in user into making a request to your API. Since cookies are sent automatically, the request is authenticated. CSRF tokens prevent this.' },
    { icon:'✅', name:'Pydantic Validation', desc:'FastAPI uses Pydantic models to validate and parse all incoming data. Types, ranges, regex patterns, required fields — all enforced automatically before your code runs.' },
    { icon:'🧹', name:'Sanitization vs Escaping', desc:'Sanitization removes dangerous content (bleach strips script tags). Escaping converts < to &lt; so it renders as text not HTML. Use the right tool for the context.' },
    { icon:'📁', name:'File Upload Security', desc:'Never trust filenames or MIME types from clients. Validate file extensions, check magic bytes, scan with antivirus, store outside web root, serve via CDN not directly.' },
  ],
  examples:[
    {
      file:'input_validation.py', lang:'Python — Pydantic + Parameterized SQL',
      code:`<span class="i">import</span> re
<span class="i">from</span> <span class="cl">pydantic</span> <span class="i">import</span> <span class="cl">BaseModel</span>, <span class="cl">EmailStr</span>, validator, <span class="cl">Field</span>
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>
<span class="i">import</span> asyncpg  <span class="c"># async PostgreSQL driver</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── Pydantic model: validates ALL input automatically ────────</span>
<span class="k">class</span> <span class="cl">UserCreate</span>(<span class="cl">BaseModel</span>):
    <span class="c"># EmailStr validates email format (requires pip install pydantic[email])</span>
    email:    <span class="cl">EmailStr</span>
    <span class="c"># Field(...) adds constraints — min/max length, regex</span>
    username: str = <span class="cl">Field</span>(..., min_length=<span class="n">3</span>, max_length=<span class="n">30</span>, regex=<span class="s">r"^[a-zA-Z0-9_]+$"</span>)
    password: str = <span class="cl">Field</span>(..., min_length=<span class="n">12</span>, max_length=<span class="n">128</span>)
    age:      int = <span class="cl">Field</span>(..., ge=<span class="n">0</span>, le=<span class="n">150</span>)    <span class="c"># ge=greater-equal, le=less-equal</span>

    <span class="c"># Custom validator: check password strength</span>
    <span class="d">@validator</span>(<span class="s">"password"</span>)
    <span class="k">def</span> <span class="f">strong_password</span>(cls, v):
        <span class="k">if not</span> re.<span class="f">search</span>(<span class="s">r"[A-Z]"</span>, v): <span class="k">raise</span> <span class="cl">ValueError</span>(<span class="s">"Need uppercase letter"</span>)
        <span class="k">if not</span> re.<span class="f">search</span>(<span class="s">r"[0-9]"</span>, v): <span class="k">raise</span> <span class="cl">ValueError</span>(<span class="s">"Need a number"</span>)
        <span class="k">if not</span> re.<span class="f">search</span>(<span class="s">r"[!@#$%]"</span>, v): <span class="k">raise</span> <span class="cl">ValueError</span>(<span class="s">"Need special char"</span>)
        <span class="k">return</span> v

<span class="c"># ── SQL Injection Prevention ─────────────────────────────────</span>
<span class="k">async def</span> <span class="f">get_user_by_name</span>(username: str):
    <span class="c"># ❌ WRONG — direct string interpolation → SQL injection</span>
    <span class="c"># query = f"SELECT * FROM users WHERE username = '{username}'"</span>
    <span class="c"># attacker sends: ' OR '1'='1 → dumps entire table!</span>

    <span class="c"># ✅ RIGHT — parameterized query ($1 is a placeholder)</span>
    <span class="c"># The DB driver escapes the value — never interpolated into SQL</span>
    <span class="k">return</span> <span class="k">await</span> db.<span class="f">fetchrow</span>(
        <span class="s">"SELECT id, email, username FROM users WHERE username = $1"</span>,
        username    <span class="c"># passed separately — never part of the query string</span>
    )

<span class="c"># ── The ORM approach (SQLAlchemy) ────────────────────────────</span>
<span class="c"># ORM automatically parameterises — nearly impossible to inject</span>
<span class="k">async def</span> <span class="f">get_user_orm</span>(username: str):
    <span class="k">return</span> <span class="k">await</span> db.<span class="f">query</span>(<span class="cl">User</span>).<span class="f">filter</span>(<span class="cl">User</span>.username == username).<span class="f">first</span>()

<span class="c"># ── Route: FastAPI validates the body using Pydantic ─────────</span>
<span class="d">@app.post</span>(<span class="s">"/users"</span>)
<span class="k">async def</span> <span class="f">create_user</span>(body: <span class="cl">UserCreate</span>):
    <span class="c"># If we reach here, email/username/password are already validated</span>
    <span class="c"># Pydantic raises 422 automatically if any field is invalid</span>
    user = <span class="k">await</span> <span class="f">get_user_by_name</span>(body.username)
    <span class="k">if</span> user: <span class="k">return</span> {<span class="s">"error"</span>: <span class="s">"Username taken"</span>}, <span class="n">409</span>
    <span class="k">return</span> {<span class="s">"created"</span>: body.email}`
    },
    {
      file:'xss_csrf_protection.py', lang:'Python — XSS + CSRF',
      code:`<span class="i">import</span> bleach, html, secrets
<span class="i">from</span> <span class="cl">fastapi</span> <span class="i">import</span> <span class="cl">FastAPI</span>, <span class="cl">Request</span>, <span class="cl">HTTPException</span>

app = <span class="cl">FastAPI</span>()

<span class="c"># ── XSS Prevention ───────────────────────────────────────────</span>
<span class="c"># bleach strips ALL HTML except what you explicitly allow</span>

ALLOWED_TAGS  = [<span class="s">"b"</span>, <span class="s">"i"</span>, <span class="s">"em"</span>, <span class="s">"strong"</span>, <span class="s">"p"</span>, <span class="s">"ul"</span>, <span class="s">"li"</span>, <span class="s">"br"</span>]
ALLOWED_ATTRS = {}   <span class="c"># no attributes: no onclick, no onerror, no href</span>

<span class="k">def</span> <span class="f">sanitize_html</span>(user_input: str) -> str:
    <span class="c"># Strips: &lt;script&gt;alert(1)&lt;/script&gt;  ← XSS</span>
    <span class="c"># Strips: &lt;img src=x onerror="stealCookies()"&gt;</span>
    <span class="c"># Strips: &lt;a href="javascript:evil()"&gt;click me&lt;/a&gt;</span>
    <span class="c"># Allows: &lt;b&gt;bold&lt;/b&gt;, &lt;p&gt;paragraph&lt;/p&gt;</span>
    <span class="k">return</span> bleach.<span class="f">clean</span>(user_input,
        tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=<span class="k">True</span>)

<span class="k">def</span> <span class="f">escape_for_display</span>(user_input: str) -> str:
    <span class="c"># When you just display text (not rich HTML), escape everything</span>
    <span class="c"># &lt; → &amp;lt;   &gt; → &amp;gt;   " → &amp;quot;</span>
    <span class="k">return</span> html.<span class="f">escape</span>(user_input)  <span class="c"># built-in Python stdlib</span>

<span class="c"># ── CSRF Prevention ───────────────────────────────────────────</span>
<span class="c"># CSRF: attacker tricks your user's browser into sending a</span>
<span class="c"># request to your API using their existing session cookies.</span>
<span class="c"># Fix: require a secret token that only your frontend has.</span>

csrf_store: dict = {}   <span class="c"># use Redis in production</span>

<span class="k">def</span> <span class="f">generate_csrf_token</span>(session_id: str) -> str:
    token = secrets.<span class="f">token_hex</span>(<span class="n">32</span>)      <span class="c"># 256-bit random token</span>
    csrf_store[session_id] = token
    <span class="k">return</span> token

<span class="k">def</span> <span class="f">verify_csrf_token</span>(session_id: str, token: str):
    expected = csrf_store.<span class="f">get</span>(session_id)
    <span class="k">if not</span> expected:
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">403</span>, <span class="s">"No CSRF token found"</span>)
    <span class="c"># MUST use compare_digest — prevents timing attacks!</span>
    <span class="k">if not</span> secrets.<span class="f">compare_digest</span>(expected, token):
        <span class="k">raise</span> <span class="cl">HTTPException</span>(<span class="n">403</span>, <span class="s">"CSRF token mismatch"</span>)

<span class="c"># ── Routes ───────────────────────────────────────────────────</span>
<span class="d">@app.get</span>(<span class="s">"/csrf-token"</span>)
<span class="k">async def</span> <span class="f">get_csrf</span>(session_id: str):
    token = <span class="f">generate_csrf_token</span>(session_id)
    <span class="k">return</span> {<span class="s">"csrf_token"</span>: token}  <span class="c"># embed in every form/API call</span>

<span class="d">@app.post</span>(<span class="s">"/transfer"</span>)
<span class="k">async def</span> <span class="f">transfer</span>(session_id: str, csrf_token: str, amount: float):
    <span class="f">verify_csrf_token</span>(session_id, csrf_token)  <span class="c"># validate before anything!</span>
    <span class="k">return</span> {<span class="s">"transferred"</span>: amount}

<span class="d">@app.post</span>(<span class="s">"/posts"</span>)
<span class="k">async def</span> <span class="f">create_post</span>(title: str, body: str):
    safe_body = <span class="f">sanitize_html</span>(body)   <span class="c"># strip XSS before storing</span>
    safe_title = <span class="f">escape_for_display</span>(title)
    <span class="k">return</span> {<span class="s">"title"</span>: safe_title, <span class="s">"body"</span>: safe_body}`
    }
  ],
  steps:[
    { title:'Install Pydantic email validator', desc:'Pydantic is included with FastAPI but email validation needs an extra package.', install:'pip install pydantic[email]' },
    { title:'Install bleach for XSS sanitization', desc:'bleach is the standard Python HTML sanitizer. Always sanitize HTML input before storing or displaying it.', install:'pip install bleach' },
    { title:'Never use f-strings in SQL', desc:'Grep your codebase for f"SELECT and f"UPDATE. Replace every one with parameterized queries. Make this a CI lint rule.', install:null },
    { title:'Test with OWASP ZAP', desc:'OWASP ZAP is a free automated scanner that tests for XSS, SQLi, CSRF and more. Run it against your local dev server.', install:'docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:8000' },
    { title:'Add bandit to your CI pipeline', desc:'Bandit scans Python code for security issues including SQL injection patterns and hardcoded passwords.', install:'pip install bandit && bandit -r . -ll' },
  ],
  libs:[
    { name:'pydantic', desc:'Request body validation (built into FastAPI)' },
    { name:'bleach', desc:'HTML sanitization — strips XSS' },
    { name:'sqlalchemy', desc:'ORM that prevents SQL injection by design' },
    { name:'python-multipart', desc:'Safe file upload handling' },
  ],
  callout:{ type:'danger', label:'RULE #1',
    text:'<b>Never put user input directly into a SQL string.</b> This is the most exploited vulnerability of all time. One <code style="color:#f43f5e">f"SELECT * FROM users WHERE name=\'{input}\'"</code> can give an attacker full database access. Parameterized queries cost nothing and prevent this completely. There is no excuse for SQL injection in 2024.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 6 — Layer 6: Data Security
// ════════════════════════════════════════════════════════════
{
  id:6, color:'#facc15', label:'PHASE 06', level:'INTERMEDIATE',
  title:'Layer 6 — Data Security',
  subtitle:'Encryption · Hashing · Key Derivation · Secrets',
  navName:'Data Encryption', badge:'L6',
  layer:6, layerDesc:'Encryption · Hashing',
  desc:'Even if every other layer fails and an attacker steals your database, properly encrypted and hashed data is useless to them. This is your last line of defence for data at rest.',
  concepts:[
    { icon:'🔑', name:'Symmetric Encryption (AES)', desc:'One key encrypts and decrypts. AES-256-GCM is the standard — 256-bit key, authenticated encryption that also verifies data was not tampered with during transit.' },
    { icon:'🔐', name:'Asymmetric Encryption (RSA)', desc:'Two keys: public (encrypt) and private (decrypt). Used for key exchange and digital signatures. RSA-2048 for encryption, RSA-4096 for long-lived keys.' },
    { icon:'🧂', name:'Password Hashing (bcrypt/argon2)', desc:'Passwords must NEVER be encrypted — encrypt can be decrypted. Hash them with bcrypt or argon2. These are intentionally slow to make brute-force infeasible.' },
    { icon:'🔏', name:'Key Derivation (PBKDF2/Argon2)', desc:'Derive a strong encryption key from a weak password using PBKDF2 or Argon2. Adds salt and iterations to make brute-force of the password computationally expensive.' },
    { icon:'✍️', name:'HMAC — Data Integrity', desc:'Hash-Based Message Authentication Code. Proves a message was not tampered with and came from someone who knows the secret key. Used for webhook signatures, API authentication.' },
    { icon:'🎲', name:'Cryptographically Secure Random', desc:'Use secrets.token_hex() or os.urandom() for security tokens. Python\'s random module is NOT cryptographically secure — never use it for tokens or keys.' },
  ],
  examples:[
    {
      file:'aes_encryption.py', lang:'Python — AES-256-GCM',
      code:`<span class="i">import</span> os, base64
<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives.ciphers.aead</span> <span class="i">import</span> <span class="cl">AESGCM</span>
<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives.kdf.pbkdf2</span> <span class="i">import</span> <span class="cl">PBKDF2HMAC</span>
<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives</span> <span class="i">import</span> hashes

<span class="c"># ── Key Derivation from Password (PBKDF2) ────────────────────</span>
<span class="c"># Turns a weak human password into a strong 256-bit encryption key</span>
<span class="k">def</span> <span class="f">derive_key_from_password</span>(password: str, salt: bytes = <span class="k">None</span>) -> tuple:
    <span class="k">if</span> salt <span class="k">is</span> <span class="k">None</span>:
        salt = os.<span class="f">urandom</span>(<span class="n">16</span>)          <span class="c"># random salt — store alongside ciphertext</span>
    kdf = <span class="cl">PBKDF2HMAC</span>(
        algorithm=hashes.<span class="cl">SHA256</span>(),
        length=<span class="n">32</span>,                        <span class="c"># 256-bit key</span>
        salt=salt,
        iterations=<span class="n">480000</span>,               <span class="c"># NIST 2023 recommendation</span>
    )
    key = kdf.<span class="f">derive</span>(password.<span class="f">encode</span>())  <span class="c"># derived key</span>
    <span class="k">return</span> key, salt

<span class="c"># ── AES-256-GCM Encryption ───────────────────────────────────</span>
<span class="c"># GCM = Galois/Counter Mode — provides both encryption AND authentication</span>
<span class="c"># If anyone tampers with the ciphertext, decryption fails</span>
<span class="k">def</span> <span class="f">encrypt</span>(plaintext: str, key: bytes) -> dict:
    nonce = os.<span class="f">urandom</span>(<span class="n">12</span>)          <span class="c"># 96-bit nonce — NEVER reuse with same key!</span>
    aesgcm = <span class="cl">AESGCM</span>(key)
    ct = aesgcm.<span class="f">encrypt</span>(nonce, plaintext.<span class="f">encode</span>(), <span class="k">None</span>)
    <span class="k">return</span> {
        <span class="s">"ciphertext"</span>: base64.<span class="f">b64encode</span>(ct).<span class="f">decode</span>(),
        <span class="s">"nonce"</span>:      base64.<span class="f">b64encode</span>(nonce).<span class="f">decode</span>(),
    }

<span class="k">def</span> <span class="f">decrypt</span>(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    ct    = base64.<span class="f">b64decode</span>(ciphertext_b64)
    nonce = base64.<span class="f">b64decode</span>(nonce_b64)
    aesgcm = <span class="cl">AESGCM</span>(key)
    <span class="c"># Raises InvalidTag exception if ciphertext was tampered with</span>
    plain = aesgcm.<span class="f">decrypt</span>(nonce, ct, <span class="k">None</span>)
    <span class="k">return</span> plain.<span class="f">decode</span>()

<span class="c"># ── Usage ────────────────────────────────────────────────────</span>
password = <span class="s">"user-master-password"</span>
key, salt = <span class="f">derive_key_from_password</span>(password)

encrypted = <span class="f">encrypt</span>(<span class="s">"SSN: 123-45-6789"</span>, key)
decrypted = <span class="f">decrypt</span>(encrypted[<span class="s">"ciphertext"</span>], encrypted[<span class="s">"nonce"</span>], key)

<span class="c"># ── Field-level encryption in database ──────────────────────</span>
<span class="c"># Encrypt sensitive fields before inserting, decrypt after reading</span>
<span class="k">async def</span> <span class="f">save_user</span>(user_id: str, ssn: str, credit_card: str):
    enc_ssn = <span class="f">encrypt</span>(ssn, FIELD_KEY)
    enc_cc  = <span class="f">encrypt</span>(credit_card, FIELD_KEY)
    <span class="c"># Store encrypted blobs — useless without FIELD_KEY</span>
    <span class="k">await</span> db.<span class="f">execute</span>(
        <span class="s">"INSERT INTO users(id, ssn_enc, cc_enc) VALUES($1,$2,$3)"</span>,
        user_id, enc_ssn[<span class="s">"ciphertext"</span>], enc_cc[<span class="s">"ciphertext"</span>]
    )`
    },
    {
      file:'password_hashing.py', lang:'Python — bcrypt + argon2 + HMAC',
      code:`<span class="i">from</span> <span class="cl">passlib.context</span> <span class="i">import</span> <span class="cl">CryptContext</span>
<span class="i">from</span> <span class="cl">argon2</span> <span class="i">import</span> <span class="cl">PasswordHasher</span>
<span class="i">import</span> hmac, hashlib, secrets, os

<span class="c"># ── bcrypt: the standard password hash ──────────────────────</span>
<span class="c"># rounds=12 → 2^12 iterations — intentionally slow</span>
<span class="c"># Takes ~250ms per hash — makes brute-force take centuries</span>
pwd_ctx = <span class="cl">CryptContext</span>(schemes=[<span class="s">"bcrypt"</span>], deprecated=<span class="s">"auto"</span>)

<span class="k">def</span> <span class="f">hash_password</span>(password: str) -> str:
    <span class="k">return</span> pwd_ctx.<span class="f">hash</span>(password)
    <span class="c"># → "$2b$12$randomsalt.hashedvalue" — self-contained string</span>

<span class="k">def</span> <span class="f">verify_password</span>(plain: str, hashed: str) -> bool:
    <span class="k">return</span> pwd_ctx.<span class="f">verify</span>(plain, hashed)
    <span class="c"># Uses constant-time comparison internally — timing-safe!</span>

<span class="c"># ── argon2id: modern winner of Password Hashing Competition ─</span>
<span class="c"># Argon2id uses both CPU and MEMORY — harder to crack with GPUs</span>
ph = <span class="cl">PasswordHasher</span>(
    time_cost=<span class="n">2</span>,      <span class="c"># iterations</span>
    memory_cost=<span class="n">65536</span>, <span class="c"># 64MB RAM used per hash — defeats GPU attacks</span>
    parallelism=<span class="n">2</span>,
)

<span class="k">def</span> <span class="f">hash_argon2</span>(password: str) -> str:
    <span class="k">return</span> ph.<span class="f">hash</span>(password)

<span class="k">def</span> <span class="f">verify_argon2</span>(password: str, hashed: str) -> bool:
    <span class="k">try</span>:
        <span class="k">return</span> ph.<span class="f">verify</span>(hashed, password)
    <span class="k">except</span>:
        <span class="k">return</span> <span class="k">False</span>

<span class="c"># ── HMAC: prove data integrity and authenticity ──────────────</span>
<span class="c"># Used for: webhook signatures, API tokens, session cookies</span>
HMAC_SECRET = os.<span class="f">getenv</span>(<span class="s">"HMAC_SECRET"</span>).<span class="f">encode</span>()

<span class="k">def</span> <span class="f">sign_data</span>(data: str) -> str:
    mac = hmac.<span class="f">new</span>(HMAC_SECRET, data.<span class="f">encode</span>(), hashlib.<span class="cl">sha256</span>)
    <span class="k">return</span> mac.<span class="f">hexdigest</span>()

<span class="k">def</span> <span class="f">verify_signature</span>(data: str, signature: str) -> bool:
    expected = <span class="f">sign_data</span>(data)
    <span class="c"># compare_digest is CRITICAL — prevents timing attacks</span>
    <span class="k">return</span> hmac.<span class="f">compare_digest</span>(expected, signature)

<span class="c"># ── Verify GitHub/Stripe webhook signatures ──────────────────</span>
<span class="k">def</span> <span class="f">verify_github_webhook</span>(payload: bytes, sig_header: str) -> bool:
    secret = os.<span class="f">getenv</span>(<span class="s">"GITHUB_WEBHOOK_SECRET"</span>).<span class="f">encode</span>()
    expected = <span class="s">"sha256="</span> + hmac.<span class="f">new</span>(secret, payload, hashlib.<span class="cl">sha256</span>).<span class="f">hexdigest</span>()
    <span class="k">return</span> hmac.<span class="f">compare_digest</span>(expected, sig_header)

<span class="c"># ── Cryptographically secure random tokens ───────────────────</span>
api_key    = secrets.<span class="f">token_hex</span>(<span class="n">32</span>)       <span class="c"># 64-char hex string — for API keys</span>
reset_token= secrets.<span class="f">token_urlsafe</span>(<span class="n">32</span>)  <span class="c"># URL-safe base64 — for reset links</span>
session_id = secrets.<span class="f">token_bytes</span>(<span class="n">32</span>)    <span class="c"># raw bytes — for session storage</span>`
    }
  ],
  steps:[
    { title:'Install cryptography library', desc:'The Python cryptography library is the industry standard. It exposes both high-level recipes and low-level primitives.', install:'pip install cryptography argon2-cffi passlib[bcrypt]' },
    { title:'Never store plain-text passwords', desc:'Audit your database now. Run: SELECT email FROM users WHERE password NOT LIKE \'$2b%\' — any result means bcrypt is not being used.', install:null },
    { title:'Encrypt sensitive fields', desc:'PII (SSN, credit cards, DOB, phone numbers) should be encrypted at the field level. Even a DB admin should not be able to read them.', install:null },
    { title:'Use a Key Management Service (KMS)', desc:'In production, never store encryption keys in your code or .env. Use AWS KMS, Google Cloud KMS, or HashiCorp Vault to manage key rotation.', install:'pip install hvac  # HashiCorp Vault client' },
    { title:'Rotate keys periodically', desc:'Encryption keys should be rotated every year. Re-encrypt data with the new key. Store old keys only until re-encryption is complete.', install:null },
  ],
  libs:[
    { name:'cryptography', desc:'AES-GCM, RSA, PBKDF2, all primitives' },
    { name:'argon2-cffi', desc:'Argon2 — modern password hashing' },
    { name:'passlib', desc:'bcrypt and multi-algorithm context' },
    { name:'hvac', desc:'HashiCorp Vault — production key management' },
  ],
  callout:{ type:'danger', label:'CRITICAL DISTINCTION',
    text:'<b>Passwords must be HASHED, not encrypted.</b> Encryption can be reversed with the key. If an attacker steals both your database and your encryption key, they have all passwords. A proper bcrypt/argon2 hash cannot be reversed — only verified. Even the developer cannot know a user\'s password. That is the correct design.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 7 — Layer 7: Monitoring & Alerting
// ════════════════════════════════════════════════════════════
{
  id:7, color:'#c084fc', label:'PHASE 07', level:'INTERMEDIATE',
  title:'Layer 7 — Monitoring',
  subtitle:'Audit Logs · Anomaly Detection · Real-Time Alerts',
  navName:'Monitoring & Alerts', badge:'L7',
  layer:7, layerDesc:'Audit Logs · Alerts',
  desc:'You cannot defend what you cannot see. Security monitoring is how you detect breaches in progress, investigate incidents after the fact, and prove compliance to auditors. Every security event must be logged.',
  concepts:[
    { icon:'📋', name:'Audit Trail', desc:'An immutable record of who did what and when. Every login, permission change, data access, and deletion must be logged with user ID, IP, timestamp, and outcome.' },
    { icon:'🔗', name:'Tamper-Evident Logging', desc:'Each log entry is HMAC-chained to the previous one. If someone deletes or modifies a log entry, the chain breaks and you know. Critical for compliance and forensics.' },
    { icon:'📊', name:'Structured Logging', desc:'Log as JSON, not free-text strings. Free-text is unqueryable. JSON lets you filter, aggregate, and alert on specific fields using tools like Elasticsearch or Loki.' },
    { icon:'🚨', name:'Real-Time Alerting', desc:'Define thresholds: >5 login failures in 1 minute = alert. >100 API errors in 10 seconds = alert. Anomaly detection catches attacks before they complete.' },
    { icon:'🕵️', name:'SIEM Integration', desc:'Security Information and Event Management. Tools like Splunk, Elastic SIEM, or AWS Security Hub aggregate logs from all systems and correlate events into attack patterns.' },
    { icon:'🧾', name:'Compliance Logging', desc:'GDPR, SOC2, PCI-DSS, HIPAA all require specific log retention. Who accessed what data, when, and why. Logs must be stored securely for 1–7 years depending on regulation.' },
  ],
  examples:[
    {
      file:'audit_logging.py', lang:'Python — Tamper-Evident Audit Log',
      code:`<span class="i">import</span> json, hmac, hashlib, time, os, logging
<span class="i">from</span> <span class="cl">datetime</span> <span class="i">import</span> datetime, timezone
<span class="i">from</span> <span class="cl">dataclasses</span> <span class="i">import</span> dataclass, asdict

<span class="c"># ── Structured JSON logger setup ─────────────────────────────</span>
<span class="k">class</span> <span class="cl">JSONFormatter</span>(logging.<span class="cl">Formatter</span>):
    <span class="k">def</span> <span class="f">format</span>(self, record: logging.<span class="cl">LogRecord</span>) -> str:
        log_entry = {
            <span class="s">"timestamp"</span>: datetime.<span class="f">now</span>(timezone.utc).<span class="f">isoformat</span>(),
            <span class="s">"level"</span>:     record.levelname,
            <span class="s">"message"</span>:   record.<span class="f">getMessage</span>(),
            <span class="s">"logger"</span>:    record.name,
        }
        <span class="c"># Merge any extra fields (user_id, ip, action etc.)</span>
        <span class="k">if</span> <span class="f">hasattr</span>(record, <span class="s">"extra"</span>):
            log_entry.<span class="f">update</span>(record.extra)
        <span class="k">return</span> json.<span class="f">dumps</span>(log_entry)

logger = logging.<span class="f">getLogger</span>(<span class="s">"audit"</span>)
handler = logging.<span class="cl">StreamHandler</span>()
handler.<span class="f">setFormatter</span>(<span class="cl">JSONFormatter</span>())
logger.<span class="f">addHandler</span>(handler)

<span class="c"># ── Tamper-Evident HMAC Chain ────────────────────────────────</span>
<span class="c"># Each entry includes HMAC of (previous_hash + this_entry)</span>
<span class="c"># Deleting or editing any entry breaks the chain</span>
LOG_SECRET = os.<span class="f">getenv</span>(<span class="s">"LOG_HMAC_SECRET"</span>, <span class="s">"change-this-secret"</span>).<span class="f">encode</span>()

<span class="k">def</span> <span class="f">make_log_hmac</span>(prev_hash: str, entry: dict) -> str:
    data = prev_hash + json.<span class="f">dumps</span>(entry, sort_keys=<span class="k">True</span>)
    <span class="k">return</span> hmac.<span class="f">new</span>(LOG_SECRET, data.<span class="f">encode</span>(), hashlib.<span class="cl">sha256</span>).<span class="f">hexdigest</span>()

<span class="k">class</span> <span class="cl">AuditLogger</span>:
    last_hash = <span class="s">"GENESIS"</span>   <span class="c"># load from DB in production</span>

    <span class="k">def</span> <span class="f">log</span>(self, action: str, user_id: str, ip: str, **details):
        entry = {
            <span class="s">"timestamp"</span>: datetime.<span class="f">now</span>(timezone.utc).<span class="f">isoformat</span>(),
            <span class="s">"action"</span>:    action,    <span class="c"># e.g. "LOGIN_SUCCESS", "DELETE_USER"</span>
            <span class="s">"user_id"</span>:   user_id,
            <span class="s">"ip"</span>:        ip,
            <span class="s">"details"</span>:   details,
        }
        <span class="c"># Chain: HMAC(prev_hash + this_entry)</span>
        entry[<span class="s">"chain_hmac"</span>] = <span class="f">make_log_hmac</span>(self.last_hash, entry)
        self.last_hash = entry[<span class="s">"chain_hmac"</span>]

        <span class="c"># Write structured JSON — queryable by any log aggregator</span>
        logger.info(entry[<span class="s">"action"</span>], extra={<span class="s">"extra"</span>: entry})
        <span class="k">return</span> entry

audit = <span class="cl">AuditLogger</span>()

<span class="c"># ── Usage ────────────────────────────────────────────────────</span>
audit.<span class="f">log</span>(<span class="s">"LOGIN_SUCCESS"</span>,  user_id=<span class="s">"u123"</span>, ip=<span class="s">"1.2.3.4"</span>)
audit.<span class="f">log</span>(<span class="s">"LOGIN_FAILURE"</span>,  user_id=<span class="s">"u456"</span>, ip=<span class="s">"9.9.9.9"</span>, reason=<span class="s">"bad_password"</span>)
audit.<span class="f">log</span>(<span class="s">"DELETE_RECORD"</span>, user_id=<span class="s">"u123"</span>, ip=<span class="s">"1.2.3.4"</span>, table=<span class="s">"users"</span>, record_id=<span class="n">99</span>)
audit.<span class="f">log</span>(<span class="s">"PERMISSION_CHANGE"</span>, user_id=<span class="s">"admin1"</span>, ip=<span class="s">"10.0.0.1"</span>, target=<span class="s">"u789"</span>, new_role=<span class="s">"admin"</span>)`
    },
    {
      file:'security_alerts.py', lang:'Python — Anomaly Detection + Alerts',
      code:`<span class="i">import</span> redis, smtplib, os
<span class="i">from</span> <span class="cl">email.message</span> <span class="i">import</span> <span class="cl">EmailMessage</span>
<span class="i">from</span> <span class="cl">datetime</span> <span class="i">import</span> datetime, timezone
<span class="i">from</span> <span class="cl">collections</span> <span class="i">import</span> defaultdict

r = redis.<span class="cl">Redis</span>(host=<span class="s">"localhost"</span>, decode_responses=<span class="k">True</span>)

<span class="c"># ── Alert thresholds ─────────────────────────────────────────</span>
THRESHOLDS = {
    <span class="s">"login_failures"</span>: {<span class="s">"limit"</span>: <span class="n">5</span>,   <span class="s">"window"</span>: <span class="n">60</span>},    <span class="c"># 5 fails in 60s</span>
    <span class="s">"api_errors_500"</span>: {<span class="s">"limit"</span>: <span class="n">20</span>,  <span class="s">"window"</span>: <span class="n">30</span>},    <span class="c"># 20 errors in 30s</span>
    <span class="s">"new_admin_users"</span>:{<span class="s">"limit"</span>: <span class="n">1</span>,   <span class="s">"window"</span>: <span class="n">300</span>},   <span class="c"># any new admin = alert</span>
    <span class="s">"data_export"</span>:    {<span class="s">"limit"</span>: <span class="n">100</span>, <span class="s">"window"</span>: <span class="n">3600</span>},  <span class="c"># bulk export alert</span>
}

<span class="k">def</span> <span class="f">track_event</span>(event_type: str, key_suffix: str = <span class="s">""</span>) -> bool:
    <span class="s">"""Increment event counter. Returns True if threshold exceeded."""</span>
    cfg = THRESHOLDS.<span class="f">get</span>(event_type)
    <span class="k">if not</span> cfg: <span class="k">return</span> <span class="k">False</span>

    key   = <span class="s">f"alert:{event_type}:{key_suffix}"</span>
    count = r.<span class="f">incr</span>(key)
    r.<span class="f">expire</span>(key, cfg[<span class="s">"window"</span>])     <span class="c"># auto-expire counter</span>
    <span class="k">return</span> count >= cfg[<span class="s">"limit"</span>]    <span class="c"># True = threshold exceeded</span>

<span class="k">def</span> <span class="f">send_security_alert</span>(subject: str, body: str):
    <span class="s">"""Send email to security team via SMTP"""</span>
    msg = <span class="cl">EmailMessage</span>()
    msg[<span class="s">"Subject"</span>] = <span class="s">f"[SECURITY ALERT] {subject}"</span>
    msg[<span class="s">"From"</span>]    = os.<span class="f">getenv</span>(<span class="s">"ALERT_FROM_EMAIL"</span>)
    msg[<span class="s">"To"</span>]      = os.<span class="f">getenv</span>(<span class="s">"SECURITY_TEAM_EMAIL"</span>)
    msg.<span class="f">set_content</span>(body)

    <span class="k">with</span> smtplib.<span class="cl">SMTP_SSL</span>(<span class="s">"smtp.gmail.com"</span>, <span class="n">465</span>) <span class="k">as</span> smtp:
        smtp.<span class="f">login</span>(os.<span class="f">getenv</span>(<span class="s">"SMTP_USER"</span>), os.<span class="f">getenv</span>(<span class="s">"SMTP_PASS"</span>))
        smtp.<span class="f">send_message</span>(msg)

<span class="c"># ── On every failed login: check threshold and alert ────────</span>
<span class="k">def</span> <span class="f">on_login_failure</span>(username: str, ip: str):
    exceeded = <span class="f">track_event</span>(<span class="s">"login_failures"</span>, ip)
    <span class="k">if</span> exceeded:
        <span class="f">send_security_alert</span>(
            <span class="s">f"Brute force attempt from {ip}"</span>,
            <span class="s">f"IP {ip} exceeded login failure threshold.\n"</span>
            <span class="s">f"Target: {username}\n"</span>
            <span class="s">f"Time: {datetime.now(timezone.utc).isoformat()}"</span>
        )

<span class="c"># ── Anomaly: user exporting unusually large amount of data ───</span>
<span class="k">def</span> <span class="f">on_data_export</span>(user_id: str, record_count: int):
    <span class="k">if</span> record_count > <span class="n">1000</span>:                   <span class="c"># unusually large export</span>
        exceeded = <span class="f">track_event</span>(<span class="s">"data_export"</span>, user_id)
        <span class="k">if</span> exceeded:
            <span class="f">send_security_alert</span>(
                <span class="s">f"Large data export by user {user_id}"</span>,
                <span class="s">f"User {user_id} exported {record_count} records.\n"</span>
                <span class="s">f"Possible data exfiltration. Review immediately."</span>
            )`
    }
  ],
  steps:[
    { title:'Set up structured logging first', desc:'Replace all print() and logging.info(f"...") with JSON-formatted log entries. Every security event needs: timestamp, user_id, ip, action, outcome.', install:'pip install python-json-logger' },
    { title:'Use a log aggregator', desc:'Ship logs to Elasticsearch + Kibana (free), Datadog, or Papertrail. Never rely on reading server log files manually.', install:'pip install elasticsearch' },
    { title:'Define your alert rules', desc:'Start with 5 critical alerts: brute force, new admin created, bulk data export, 5xx spike, login from new country. Add more over time.', install:null },
    { title:'Test your alerts', desc:'Simulate attacks in staging: run 10 failed logins in a row, create an admin user, export 1000 records. Verify alerts fire within 60 seconds.', install:null },
    { title:'Set up uptime monitoring', desc:'Pingdom, UptimeRobot (free), or AWS CloudWatch alarms. Get paged when your API goes down.', install:null },
  ],
  libs:[
    { name:'python-json-logger', desc:'Structured JSON log formatter' },
    { name:'elasticsearch', desc:'Log aggregation and search' },
    { name:'sentry-sdk', desc:'Error tracking and performance monitoring' },
    { name:'redis', desc:'Fast counters for alert thresholds' },
  ],
  callout:{ type:'info', label:'KEY PRINCIPLE',
    text:'<b>Logs are your time machine.</b> When a breach happens (and eventually one will), logs are the only way to answer: When did it start? What data was accessed? How did they get in? Logs without integrity protection (HMAC chaining) are useless in court — an attacker who breaches your server will delete or modify the logs first.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 8 — Advanced Cryptography
// ════════════════════════════════════════════════════════════
{
  id:8, color:'#818cf8', label:'PHASE 08', level:'ADVANCED',
  title:'Advanced Cryptography',
  subtitle:'ECC · ECDSA · ECDH · Zero-Knowledge Proofs',
  navName:'Advanced Crypto', badge:'ADV',
  desc:'Elliptic Curve Cryptography powers Bitcoin, TLS 1.3, and Signal. Understanding it takes you from using security to understanding it at a mathematical level. This is where most developers stop — go further.',
  concepts:[
    { icon:'📐', name:'Elliptic Curve Crypto', desc:'Security comes from the Discrete Logarithm Problem on elliptic curves. Given point Q = k·P, finding k is computationally infeasible — even knowing P and Q. This is a mathematical trapdoor.' },
    { icon:'✍️', name:'ECDSA — Digital Signatures', desc:'Sign data with a private key. Anyone with the public key can verify the signature. Used in HTTPS certificates, Bitcoin transactions, code signing, and SSH.' },
    { icon:'🤝', name:'ECDH — Key Exchange', desc:'Alice and Bob each have key pairs. They compute the same shared secret without ever sending it over the network. This is how TLS establishes a session key securely.' },
    { icon:'🌲', name:'Merkle Trees', desc:'A tree of hashes where each node is the hash of its children. The root hash represents all data. Change one leaf → root changes. Used in Bitcoin, Git, and IPFS.' },
    { icon:'🔮', name:'Zero-Knowledge Proofs', desc:'Prove you know a secret without revealing it. "I know the password" without saying what it is. Foundation of privacy coins (Zcash) and zkEVM blockchains.' },
    { icon:'🔑', name:'secp256k1 vs P-256', desc:'secp256k1 is used by Bitcoin/Ethereum. P-256 (prime256v1) is used by TLS and US government. Both are 256-bit ECC — different curve parameters, same security level.' },
  ],
  examples:[
    {
      file:'ecc_cryptography.py', lang:'Python — ECDSA + ECDH',
      code:`<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives.asymmetric</span> <span class="i">import</span> ec
<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives</span> <span class="i">import</span> hashes, serialization
<span class="i">from</span> <span class="cl">cryptography.hazmat.primitives.kdf.hkdf</span> <span class="i">import</span> <span class="cl">HKDF</span>
<span class="i">from</span> <span class="cl">cryptography.hazmat.backends</span> <span class="i">import</span> default_backend
<span class="i">import</span> os

<span class="c"># ── Generate ECC key pair (secp256k1 = same curve as Bitcoin) ─</span>
private_key = ec.<span class="f">generate_private_key</span>(ec.<span class="cl">SECP256K1</span>(), default_backend())
public_key  = private_key.<span class="f">public_key</span>()

<span class="c"># ── ECDSA: Sign a message ────────────────────────────────────</span>
<span class="c"># Private key signs → public key verifies</span>
message   = <span class="s">b"Transfer 1 BTC to Alice"</span>
signature = private_key.<span class="f">sign</span>(message, ec.<span class="cl">ECDSA</span>(hashes.<span class="cl">SHA256</span>()))

<span class="c"># ── Verify signature ─────────────────────────────────────────</span>
<span class="k">try</span>:
    public_key.<span class="f">verify</span>(signature, message, ec.<span class="cl">ECDSA</span>(hashes.<span class="cl">SHA256</span>()))
    <span class="f">print</span>(<span class="s">"Valid — signed by key owner"</span>)
<span class="k">except</span> <span class="cl">Exception</span>:
    <span class="f">print</span>(<span class="s">"Invalid signature!"</span>)

<span class="c"># ── Serialize public key to share ────────────────────────────</span>
pub_pem = public_key.<span class="f">public_bytes</span>(
    serialization.<span class="cl">Encoding</span>.<span class="cl">PEM</span>,
    serialization.<span class="cl">PublicFormat</span>.<span class="cl">SubjectPublicKeyInfo</span>
)  <span class="c"># share this — anyone can verify signatures with it</span>

<span class="c"># ── ECDH: Secure key exchange ────────────────────────────────</span>
<span class="c"># Alice and Bob each have key pairs</span>
alice_private = ec.<span class="f">generate_private_key</span>(ec.<span class="cl">SECP256K1</span>(), default_backend())
bob_private   = ec.<span class="f">generate_private_key</span>(ec.<span class="cl">SECP256K1</span>(), default_backend())

<span class="c"># Alice computes: alice_priv * bob_pub</span>
alice_shared = alice_private.<span class="f">exchange</span>(ec.<span class="cl">ECDH</span>(), bob_private.<span class="f">public_key</span>())
<span class="c"># Bob computes:  bob_priv  * alice_pub</span>
bob_shared   = bob_private.<span class="f">exchange</span>(ec.<span class="cl">ECDH</span>(), alice_private.<span class="f">public_key</span>())

<span class="c"># Both arrive at the SAME shared secret — never sent over the wire!</span>
<span class="k">assert</span> alice_shared == bob_shared

<span class="c"># Derive an AES key from the shared secret (HKDF)</span>
aes_key = <span class="cl">HKDF</span>(
    algorithm=hashes.<span class="cl">SHA256</span>(), length=<span class="n">32</span>,
    salt=<span class="k">None</span>, info=<span class="s">b"handshake"</span>,
).<span class="f">derive</span>(alice_shared)
<span class="c"># Now use aes_key for AES-256-GCM encryption (Phase 6)</span>`
    },
    {
      file:'merkle_tree.py', lang:'Python — Merkle Tree',
      code:`<span class="i">import</span> hashlib
<span class="i">from</span> <span class="cl">typing</span> <span class="i">import</span> List, Optional

<span class="c"># ── Merkle Tree: efficient proof that data is in a set ───────</span>
<span class="c"># Used in: Bitcoin (transactions), Git (commits), IPFS (files)</span>

<span class="k">def</span> <span class="f">sha256</span>(data: str) -> str:
    <span class="k">return</span> hashlib.<span class="f">sha256</span>(data.<span class="f">encode</span>()).<span class="f">hexdigest</span>()

<span class="k">def</span> <span class="f">hash_pair</span>(left: str, right: str) -> str:
    <span class="k">return</span> hashlib.<span class="f">sha256</span>((left + right).<span class="f">encode</span>()).<span class="f">hexdigest</span>()

<span class="k">def</span> <span class="f">build_merkle_root</span>(data_items: <span class="cl">List</span>[str]) -> str:
    <span class="s">"""Build Merkle tree and return root hash."""</span>
    <span class="k">if not</span> data_items: <span class="k">return</span> <span class="f">sha256</span>(<span class="s">""</span>)
    nodes = [<span class="f">sha256</span>(item) <span class="k">for</span> item <span class="k">in</span> data_items]  <span class="c"># leaf hashes</span>

    <span class="k">while</span> <span class="f">len</span>(nodes) > <span class="n">1</span>:
        <span class="k">if</span> <span class="f">len</span>(nodes) % <span class="n">2</span> != <span class="n">0</span>:
            nodes.<span class="f">append</span>(nodes[-<span class="n">1</span>])  <span class="c"># duplicate last if odd count</span>
        nodes = [<span class="f">hash_pair</span>(nodes[i], nodes[i+<span class="n">1</span>])
                 <span class="k">for</span> i <span class="k">in</span> <span class="f">range</span>(<span class="n">0</span>, <span class="f">len</span>(nodes), <span class="n">2</span>)]
    <span class="k">return</span> nodes[<span class="n">0</span>]  <span class="c"># Merkle root</span>

<span class="c"># ── Example: Bitcoin-like transaction set ────────────────────</span>
transactions = [
    <span class="s">"Alice → Bob: 1 BTC"</span>,
    <span class="s">"Bob → Carol: 0.5 BTC"</span>,
    <span class="s">"Carol → Dave: 0.2 BTC"</span>,
    <span class="s">"Dave → Eve: 0.1 BTC"</span>,
]
root = <span class="f">build_merkle_root</span>(transactions)
<span class="f">print</span>(<span class="s">f"Merkle root: {root}"</span>)

<span class="c"># Tamper with ONE transaction → root COMPLETELY changes</span>
transactions[<span class="n">1</span>] = <span class="s">"Bob → Attacker: 0.5 BTC"</span>
tampered_root = <span class="f">build_merkle_root</span>(transactions)
<span class="f">print</span>(<span class="s">f"Tampered:    {tampered_root}"</span>)
<span class="f">print</span>(<span class="s">f"Tamper detected: {root != tampered_root}"</span>)  <span class="c"># True!</span>

<span class="c"># ── Simplified ZK proof concept ──────────────────────────────</span>
<span class="c"># Prove you know a secret without revealing it</span>
<span class="c"># (Schnorr identification protocol simplified)</span>
<span class="i">import</span> secrets <span class="k">as</span> sec, hashlib

<span class="k">def</span> <span class="f">zk_commit</span>(secret: int, generator: int = <span class="n">7</span>, modulus: int = <span class="n">1009</span>):
    <span class="c"># Prover: commit to a random nonce</span>
    r     = sec.<span class="f">randbelow</span>(modulus - <span class="n">1</span>) + <span class="n">1</span>
    R     = <span class="f">pow</span>(generator, r, modulus)      <span class="c"># R = g^r mod p (commitment)</span>
    x     = <span class="f">pow</span>(generator, secret, modulus) <span class="c"># x = g^secret (public key)</span>
    <span class="k">return</span> R, r, x

<span class="c"># In a real ZK proof: verifier sends a challenge, prover responds</span>
<span class="c"># without ever sending the secret. See ZKProof.org for full protocol.</span>`
    }
  ],
  steps:[
    { title:'Study elliptic curve math', desc:'Read "An Introduction to Mathematical Cryptography" (Hoffstein). Implement point addition on paper first. Understanding the math makes the code make sense.', install:null },
    { title:'Use the cryptography library', desc:'The Python cryptography library implements ECC correctly. Never roll your own crypto — use battle-tested libraries.', install:'pip install cryptography' },
    { title:'Implement a Merkle tree from scratch', desc:'Build one that works on a list of strings. Verify it detects tampering. Then look at pip install merkletools.', install:'pip install merkletools' },
    { title:'Read ZKProof.org standards', desc:'Zero-knowledge proofs are the future of privacy. Start with the Schnorr identification protocol, then study zk-SNARKs and STARKs.', install:null },
    { title:'Study TLS 1.3 handshake', desc:"TLS 1.3 uses ECDH for key exchange and ECDSA for certificates. Wireshark lets you see the handshake packets. It's ECC in action.", install:'pip install pyopenssl' },
  ],
  libs:[
    { name:'cryptography', desc:'ECC, ECDSA, ECDH, all primitives' },
    { name:'py_ecc', desc:'Ethereum BLS signatures and pairings' },
    { name:'merkletools', desc:'Merkle tree utilities' },
    { name:'sympy', desc:'Modular arithmetic for learning' },
  ],
  callout:{ type:'info', label:'KEY INSIGHT',
    text:'<b>The security of ECC comes from the Discrete Logarithm Problem:</b> Given points P and Q = k·P on an elliptic curve, it is computationally infeasible to find k even knowing both P and Q. This mathematical trapdoor is why 256-bit ECC gives the same security as 3072-bit RSA with a fraction of the key size and computation.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 9 — Blockchain Security
// ════════════════════════════════════════════════════════════
{
  id:9, color:'#ff6b35', label:'PHASE 09', level:'EXPERT',
  title:'Blockchain Security',
  subtitle:'HD Wallets · Smart Contract Auditing · DeFi Attacks',
  navName:'Blockchain Security', badge:'WEB3',
  desc:'Blockchain has unique security properties — immutability, transparency, decentralisation — and unique attack surfaces. A bug in a smart contract is permanent and irreversible. The DAO hack lost $60M in minutes.',
  concepts:[
    { icon:'👛', name:'HD Wallets (BIP39/BIP32)', desc:'One 24-word seed phrase deterministically generates unlimited key pairs. This is how MetaMask, Ledger, and every modern wallet works. Lose the phrase, lose everything.' },
    { icon:'⚠️', name:'Reentrancy Attack', desc:'Smart contract sends ETH to an external contract before updating its own state. The receiver calls back in, triggering another withdrawal. The DAO hack: $60M stolen this way.' },
    { icon:'⚡', name:'Flash Loan Attacks', desc:'Borrow $100M uncollateralized in one transaction, manipulate a price oracle, exploit a protocol, repay the loan — all in one atomic transaction. $3B+ stolen across DeFi.' },
    { icon:'🎲', name:'Oracle Manipulation', desc:'Smart contracts cannot access external data directly. Price oracles can be manipulated with large trades. TWAP (time-weighted average) oracles are much harder to manipulate.' },
    { icon:'🔮', name:'zk-SNARKs', desc:'Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge. Prove computation was done correctly without revealing inputs. Used in Zcash, zkRollups, zkEVM (zkSync, Polygon).' },
    { icon:'🔐', name:'Multi-Sig Wallets', desc:'N-of-M threshold: require 3 of 5 key holders to sign a transaction. Used for DAO treasuries. The Ronin bridge ($625M hack) had a 5-of-9 multi-sig compromised by 5 key thefts.' },
  ],
  examples:[
    {
      file:'hd_wallet.py', lang:'Python — BIP39 + BIP32 HD Wallet',
      code:`<span class="i">from</span> <span class="cl">mnemonic</span> <span class="i">import</span> <span class="cl">Mnemonic</span>
<span class="i">from</span> <span class="cl">eth_account</span> <span class="i">import</span> <span class="cl">Account</span>
<span class="i">import</span> hashlib, hmac, struct

<span class="c"># ── BIP39: Generate a 24-word seed phrase ────────────────────</span>
<span class="c"># 24 words = 256 bits of entropy</span>
<span class="c"># LOSING THIS PHRASE = LOSING ALL FUNDS. NEVER STORE DIGITALLY.</span>
mnemo = <span class="cl">Mnemonic</span>(<span class="s">"english"</span>)
words = mnemo.<span class="f">generate</span>(strength=<span class="n">256</span>)
<span class="f">print</span>(<span class="s">f"Seed phrase: {words}"</span>)
<span class="c"># → "abandon zoo ... " (24 words from BIP39 wordlist)</span>

<span class="c"># Convert mnemonic to 512-bit seed (PBKDF2 with 2048 iterations)</span>
seed = mnemo.<span class="f">to_seed</span>(words, passphrase=<span class="s">""</span>)

<span class="c"># ── BIP32: Derive Ethereum addresses ─────────────────────────</span>
<span class="c"># Enable HD wallet features in eth_account</span>
<span class="cl">Account</span>.<span class="f">enable_unaudited_hdwallet_features</span>()

<span class="c"># Derivation path: m/44'/60'/0'/0/0</span>
<span class="c"># 44' = BIP44 purpose</span>
<span class="c"># 60' = Ethereum coin type</span>
<span class="c"># 0'  = account index</span>
<span class="c"># 0   = external chain</span>
<span class="c"># 0   = address index (increment for multiple addresses)</span>
account = <span class="cl">Account</span>.<span class="f">from_mnemonic</span>(words, account_path=<span class="s">"m/44'/60'/0'/0/0"</span>)
<span class="f">print</span>(<span class="s">f"Address:     {account.address}"</span>)
<span class="f">print</span>(<span class="s">f"Private key: {account.key.hex()}"</span>)

<span class="c"># ── Sign a transaction ───────────────────────────────────────</span>
<span class="c"># The private key NEVER leaves your device</span>
<span class="c"># Only the signed transaction is broadcast to the network</span>
signed = account.<span class="f">sign_transaction</span>({
    <span class="s">"to"</span>:       <span class="s">"0xRecipientAddress"</span>,
    <span class="s">"value"</span>:    <span class="n">1000000000000000000</span>,  <span class="c"># 1 ETH in wei</span>
    <span class="s">"gas"</span>:      <span class="n">21000</span>,
    <span class="s">"gasPrice"</span>: <span class="n">20000000000</span>,           <span class="c"># 20 gwei</span>
    <span class="s">"nonce"</span>:    <span class="n">0</span>,
    <span class="s">"chainId"</span>:  <span class="n">1</span>                      <span class="c"># 1=mainnet, 11155111=sepolia</span>
})

<span class="c"># ── Verify a message signature ───────────────────────────────</span>
message   = <span class="s">"I am the owner of this address"</span>
signature = account.<span class="f">sign_message</span>(<span class="f">encode_defunct</span>(text=message))
recovered = <span class="cl">Account</span>.<span class="f">recover_message</span>(<span class="f">encode_defunct</span>(text=message),
                                    signature=signature.signature)
<span class="f">print</span>(<span class="s">f"Verified: {recovered.lower() == account.address.lower()}"</span>)`
    },
    {
      file:'smart_contract_audit.py', lang:'Python — Reentrancy + CEI Pattern',
      code:`<span class="c"># ── Reentrancy Attack (The DAO hack — $60M lost) ────────────</span>
<span class="c"># The most famous smart contract vulnerability.</span>
<span class="c"># Shown in Python to illustrate the logic (actual code is Solidity)</span>

<span class="k">class</span> <span class="cl">VulnerableVault</span>:
    <span class="s">"""❌ VULNERABLE: state updated AFTER external call"""</span>
    <span class="k">def</span> <span class="f">__init__</span>(self): self.balances = {}

    <span class="k">def</span> <span class="f">withdraw</span>(self, user, amount):
        <span class="k">if</span> self.balances.<span class="f">get</span>(user, <span class="n">0</span>) >= amount:
            self.<span class="f">_send_eth</span>(user, amount)      <span class="c"># external call first!</span>
            self.balances[user] -= amount    <span class="c"># state update too late!</span>
            <span class="c"># Attacker re-enters _send_eth before state is updated</span>
            <span class="c"># balance still shows original amount → drains entire vault</span>

<span class="k">class</span> <span class="cl">SecureVault</span>:
    <span class="s">"""✅ SECURE: Checks-Effects-Interactions (CEI) pattern"""</span>
    <span class="k">def</span> <span class="f">__init__</span>(self): self.balances = {}

    <span class="k">def</span> <span class="f">withdraw</span>(self, user, amount):
        <span class="c"># 1. CHECKS: validate conditions</span>
        <span class="k">if</span> self.balances.<span class="f">get</span>(user, <span class="n">0</span>) < amount:
            <span class="k">raise</span> <span class="cl">ValueError</span>(<span class="s">"Insufficient balance"</span>)
        <span class="c"># 2. EFFECTS: update state BEFORE external call</span>
        self.balances[user] -= amount        <span class="c"># state updated first!</span>
        <span class="c"># 3. INTERACTIONS: now make the external call</span>
        self.<span class="f">_send_eth</span>(user, amount)         <span class="c"># re-entry now has no effect</span>

<span class="c"># ── Flash Loan Attack (no code required) ─────────────────────</span>
<span class="c"># All steps happen in a SINGLE Ethereum transaction:</span>
<span class="c"># Step 1: Borrow $100M USDC uncollateralized (Aave flash loan)</span>
<span class="c"># Step 2: Buy huge amount on a DEX → price spikes artificially</span>
<span class="c"># Step 3: Exploit a protocol that uses this price as collateral</span>
<span class="c"># Step 4: Repay $100M + 0.09% fee to Aave</span>
<span class="c"># Step 5: Keep the profits</span>
<span class="c"># Total capital required: ~$30 for gas. Profit: millions.</span>
<span class="c"># Defence: use TWAP oracle (time-weighted average — needs many blocks)</span>

<span class="c"># ── Smart Contract Auditing Tools ────────────────────────────</span>
<span class="c"># Slither (static analyser):</span>
<span class="c"># pip install slither-analyzer</span>
<span class="c"># slither contract.sol → detects reentrancy, unchecked returns, overflow</span>
<span class="c">#</span>
<span class="c"># Mythril (symbolic execution):</span>
<span class="c"># pip install mythril</span>
<span class="c"># myth analyze contract.sol → deep vulnerability analysis</span>
<span class="c">#</span>
<span class="c"># Echidna (fuzzer): generates random inputs to find edge cases</span>
<span class="c"># Certora Prover: formal verification — mathematical proof of correctness</span>`
    }
  ],
  steps:[
    { title:'Understand BIP39 and BIP32', desc:'Read Bitcoin Improvement Proposals 39 and 32. Implement the derivation path manually from scratch — you will never forget it.', install:'pip install mnemonic eth-account web3' },
    { title:'Read the SWC Registry', desc:'Smart Contract Weakness Classification (swcregistry.io) — the OWASP Top 10 equivalent for Solidity. Study every entry.', install:null },
    { title:'Run Slither on Solidity code', desc:'Slither statically analyses Solidity. It finds reentrancy, unchecked math, access control bugs, and more in seconds.', install:'pip install slither-analyzer' },
    { title:'Study DeFi post-mortems on rekt.news', desc:'Every major DeFi hack is dissected on rekt.news. Reading 20 of these gives you a masterclass in blockchain attack vectors.', install:null },
    { title:'Learn Solidity on CryptoZombies', desc:'Free, gamified Solidity tutorial. Build zombie game contracts while learning the language. Then audit them for vulnerabilities.', install:null },
  ],
  libs:[
    { name:'web3', desc:'Ethereum Python client' },
    { name:'eth-account', desc:'HD wallets and transaction signing' },
    { name:'mnemonic', desc:'BIP39 seed phrase generation' },
    { name:'slither-analyzer', desc:'Smart contract static analysis' },
    { name:'py_ecc', desc:'BLS signatures for Ethereum 2.0' },
  ],
  callout:{ type:'danger', label:'IMMUTABLE RISK',
    text:'<b>Smart contract bugs are permanent and irreversible.</b> Unlike a web app where you patch and redeploy, a deployed smart contract cannot be changed. The Ronin bridge lost $625M, the Wormhole bridge $320M, BadgerDAO $120M. Every contract must have: multiple independent audits, formal verification, a bug bounty, and a time-lock before launch.' }
},

// ════════════════════════════════════════════════════════════
// PHASE 10 — Penetration Testing
// ════════════════════════════════════════════════════════════
{
  id:10, color:'#e879f9', label:'PHASE 10', level:'ELITE',
  title:'Penetration Testing',
  subtitle:'OSINT · Scanning · STRIDE · Bug Bounty',
  navName:'Penetration Testing', badge:'ELITE',
  desc:'The elite level. Security engineers who can both build and break systems are rare and valuable. Penetration testing means legally attacking systems to find vulnerabilities before real attackers do.',
  concepts:[
    { icon:'🗺️', name:'OSINT & Reconnaissance', desc:'Information gathering before touching the target. Shodan, Censys, theHarvester, LinkedIn, GitHub. Know your target before the first packet is sent.' },
    { icon:'🔭', name:'Vulnerability Scanning', desc:'Automated discovery: nmap for ports, Nessus or OpenVAS for CVEs, OWASP ZAP for web apps. Scanning without permission is illegal — only on systems you own or have written authorisation for.' },
    { icon:'💻', name:'Exploitation', desc:'Metasploit, custom exploits, buffer overflows, RCE. Understanding exploitation makes you a better defender — you understand exactly what you are protecting against.' },
    { icon:'📝', name:'STRIDE Threat Model', desc:'Systematic framework: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. Apply to every component of your system.' },
    { icon:'🏆', name:'Bug Bounty', desc:'Legal, paid hacking. HackerOne, Bugcrowd, Intigriti. Reports can earn $500 to $1M+ for critical vulnerabilities. Google, Microsoft, Apple all run programs.' },
    { icon:'📋', name:'Pentest Reporting', desc:'CVSS severity scoring, executive summary, technical details, proof-of-concept, reproduction steps, remediation guidance. A finding without a report is worthless.' },
  ],
  examples:[
    {
      file:'network_recon.py', lang:'Python — Ethical Recon (own systems only)',
      code:`<span class="c"># ⚠️  Only run on systems you OWN or have written permission for!</span>
<span class="c"># Unauthorised scanning is illegal in most jurisdictions.</span>

<span class="i">import</span> nmap, socket, os
<span class="i">from</span> <span class="cl">shodan</span> <span class="i">import</span> <span class="cl">Shodan</span>

<span class="c"># ── Port Scanning with python-nmap ───────────────────────────</span>
nm = nmap.<span class="cl">PortScanner</span>()

<span class="c"># -sV: detect service version | -O: OS detection | -A: aggressive</span>
nm.<span class="f">scan</span>(<span class="s">"192.168.1.1"</span>, <span class="s">"22,80,443,3306,5432,6379,27017"</span>, arguments=<span class="s">"-sV"</span>)

<span class="k">for</span> host <span class="k">in</span> nm.<span class="f">all_hosts</span>():
    <span class="k">for</span> proto <span class="k">in</span> nm[host].<span class="f">all_protocols</span>():
        <span class="k">for</span> port, info <span class="k">in</span> nm[host][proto].<span class="f">items</span>():
            state   = info[<span class="s">"state"</span>]
            service = info[<span class="s">"name"</span>]
            version = info[<span class="s">"version"</span>]
            <span class="k">if</span> state == <span class="s">"open"</span>:
                <span class="f">print</span>(<span class="s">f"OPEN  {port:5d}/tcp  {service:10} {version}"</span>)

<span class="c"># ── Shodan: search for exposed services globally ────────────</span>
<span class="c"># Shodan is a search engine for internet-connected devices</span>
<span class="c"># Use it on your own infrastructure to see what is exposed!</span>
api     = <span class="cl">Shodan</span>(os.<span class="f">getenv</span>(<span class="s">"SHODAN_API_KEY"</span>))
results = api.<span class="f">search</span>(<span class="s">"hostname:mycompany.com"</span>)  <span class="c"># search YOUR company</span>
<span class="k">for</span> r <span class="k">in</span> results[<span class="s">"matches"</span>][:<span class="n">10</span>]:
    <span class="f">print</span>(<span class="s">f"IP: {r['ip_str']}:{r['port']}  {r.get('product', '')}"</span>)

<span class="c"># ── Subdomain enumeration ────────────────────────────────────</span>
<span class="k">def</span> <span class="f">enum_subdomains</span>(domain: str, wordlist: list) -> list:
    found = []
    <span class="k">for</span> sub <span class="k">in</span> wordlist:
        fqdn = <span class="s">f"{sub}.{domain}"</span>
        <span class="k">try</span>:
            ip = socket.<span class="f">gethostbyname</span>(fqdn)
            found.<span class="f">append</span>({<span class="s">"host"</span>: fqdn, <span class="s">"ip"</span>: ip})
            <span class="f">print</span>(<span class="s">f"Found: {fqdn} → {ip}"</span>)
        <span class="k">except</span> socket.<span class="cl">gaierror</span>:
            <span class="k">pass</span>   <span class="c"># does not resolve — skip</span>
    <span class="k">return</span> found

wordlist = [<span class="s">"www"</span>, <span class="s">"api"</span>, <span class="s">"admin"</span>, <span class="s">"dev"</span>, <span class="s">"staging"</span>, <span class="s">"mail"</span>, <span class="s">"vpn"</span>]
<span class="f">enum_subdomains</span>(<span class="s">"mycompany.com"</span>, wordlist)  <span class="c"># only run on YOUR domain</span>`
    },
    {
      file:'stride_model.py', lang:'Python — STRIDE Threat Modelling',
      code:`<span class="c"># ── STRIDE Threat Model ──────────────────────────────────────</span>
<span class="c"># For each component in your system, ask all 6 STRIDE questions</span>
<span class="c"># This is the most systematic way to find security gaps</span>

STRIDE = {
    <span class="s">"S"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Spoofing"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can an attacker pretend to be someone/something else?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"MFA"</span>, <span class="s">"Strong authentication"</span>, <span class="s">"Certificate pinning"</span>],
    },
    <span class="s">"T"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Tampering"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can data be modified in transit or at rest?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"HMAC"</span>, <span class="s">"Digital signatures"</span>, <span class="s">"TLS"</span>, <span class="s">"DB constraints"</span>],
    },
    <span class="s">"R"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Repudiation"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can a user deny performing an action?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"Audit logs"</span>, <span class="s">"Non-repudiation signatures"</span>, <span class="s">"Timestamps"</span>],
    },
    <span class="s">"I"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Information Disclosure"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can sensitive data leak to unauthorised parties?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"Encryption"</span>, <span class="s">"Minimal data collection"</span>, <span class="s">"Access controls"</span>],
    },
    <span class="s">"D"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Denial of Service"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can the system be made unavailable?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"Rate limiting"</span>, <span class="s">"CDN"</span>, <span class="s">"Auto-scaling"</span>, <span class="s">"Circuit breakers"</span>],
    },
    <span class="s">"E"</span>: {
        <span class="s">"threat"</span>:     <span class="s">"Elevation of Privilege"</span>,
        <span class="s">"question"</span>:   <span class="s">"Can a low-privilege user gain higher permissions?"</span>,
        <span class="s">"mitigations"</span>:[<span class="s">"RBAC"</span>, <span class="s">"Least privilege"</span>, <span class="s">"Input validation"</span>, <span class="s">"Sandboxing"</span>],
    },
}

<span class="k">def</span> <span class="f">threat_model</span>(component: str):
    <span class="f">print</span>(<span class="s">f"\\n{'='*60}"</span>)
    <span class="f">print</span>(<span class="s">f"Threat Model: {component}"</span>)
    <span class="f">print</span>(<span class="s">f"{'='*60}"</span>)
    <span class="k">for</span> letter, t <span class="k">in</span> STRIDE.<span class="f">items</span>():
        <span class="f">print</span>(<span class="s">f"\\n[{letter}] {t['threat']}"</span>)
        <span class="f">print</span>(<span class="s">f"    Q: {t['question']}"</span>)
        <span class="f">print</span>(<span class="s">f"    Mitigations: {', '.join(t['mitigations'])}"</span>)

<span class="c"># Run STRIDE against every major component in your system</span>
<span class="f">threat_model</span>(<span class="s">"Login Endpoint"</span>)
<span class="f">threat_model</span>(<span class="s">"User Database"</span>)
<span class="f">threat_model</span>(<span class="s">"Payment API"</span>)
<span class="f">threat_model</span>(<span class="s">"Admin Dashboard"</span>)
<span class="f">threat_model</span>(<span class="s">"File Upload Service"</span>)`
    }
  ],
  steps:[
    { title:'Set up a legal lab environment', desc:'Hack The Box, TryHackMe, or VulnHub provide legal vulnerable VMs to practice on. Never practice on real systems without authorisation.', install:null },
    { title:'Get certified', desc:'eJPT (beginner, $200), CEH (intermediate), OSCP (gold standard, 24-hour hands-on exam). OSCP is what hiring managers look for.', install:null },
    { title:'Learn Metasploit', desc:'The industry-standard exploitation framework. Learn the basics: search, use, set RHOSTS, exploit. Use only in legal lab environments.', install:'sudo apt install metasploit-framework' },
    { title:'Run STRIDE on your own system', desc:'Take your current project. For each component (API, DB, frontend, file storage), run through all 6 STRIDE categories. Document every threat you find.', install:null },
    { title:'Start a bug bounty program', desc:'HackerOne, Bugcrowd, Intigriti. Even a small program attracts researchers. A $500 bounty for a critical bug is cheaper than a breach worth millions.', install:null },
  ],
  libs:[
    { name:'python-nmap', desc:'Port scanning wrapper' },
    { name:'shodan', desc:'Internet search engine API' },
    { name:'scapy', desc:'Packet crafting and analysis' },
    { name:'pwntools', desc:'CTF and exploit development' },
    { name:'impacket', desc:'Windows network protocol implementation' },
  ],
  callout:{ type:'danger', label:'LEGAL WARNING',
    text:'<b>Only test systems you own or have explicit, written permission to test.</b> Unauthorised penetration testing is a criminal offence under the Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK), and equivalent laws in almost every country. Always get a signed scope agreement and rules of engagement before touching anything that is not yours.' }
},

]; // ── end of phases ──────────────────────────────────────────

