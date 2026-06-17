import re
import json
import http.cookiejar
import urllib.request

BASE = 'http://127.0.0.1:5000'

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get(url):
    req = urllib.request.Request(url)
    with opener.open(req) as resp:
        return resp.read().decode(), resp.status

def post(url, data=None, json_body=None, headers=None):
    hdrs = headers or {}
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs['Content-Type'] = 'application/json'
    else:
        body = data.encode() if data else None
    req = urllib.request.Request(url, data=body, headers=hdrs, method='POST')
    try:
        with opener.open(req) as resp:
            return resp.read().decode(), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode(), e.code

# Login flow
html, _ = get(f'{BASE}/login')
csrf1 = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
print('CSRF from login page:', csrf1[:20], '...')
print('Cookies after login page:', list(cj))

body, status = post(
    f'{BASE}/api/login',
    data=f'email=admin%40securevault.local&password=VaultAdmin2026%21&csrf_token={csrf1}',
    headers={'X-CSRFToken': csrf1, 'Content-Type': 'application/x-www-form-urlencoded'},
)
print('Login:', status)
print('Cookies after login:', list(cj))

# Get fresh CSRF from profile after login
html2, _ = get(f'{BASE}/profile')
csrf2 = re.search(r'name="csrf-token" content="([^"]+)"', html2)
csrf2 = csrf2.group(1) if csrf2 else None
print('CSRF from profile meta:', (csrf2 or '')[:20], '...')

# Encrypt first to get valid cipher
body_e, status_e = post(
    f'{BASE}/api/encrypt',
    json_body={'plain_text': 'test secret'},
    headers={'X-CSRFToken': csrf2 or csrf1},
)
print('Encrypt:', status_e, body_e[:120])

if status_e == 200:
    cipher = json.loads(body_e).get('encrypted', '')
    body_d, status_d = post(
        f'{BASE}/api/decrypt',
        json_body={'cipher_text': cipher},
        headers={'X-CSRFToken': csrf2 or csrf1},
    )
    print('Decrypt:', status_d, body_d[:200])

# User-reported ciphertext from screenshot
cipher_user = 'FnEEgcJW0Y0GVCHK18vWP72LmiTafwx090uizq1Ck59d'
body_u, status_u = post(
    f'{BASE}/api/decrypt',
    json_body={'cipher_text': cipher_user},
    headers={'X-CSRFToken': csrf2 or csrf1},
)
print('User cipher decrypt:', status_u, body_u[:200])
