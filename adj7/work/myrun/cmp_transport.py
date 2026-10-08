import socket, threading, time
from curl_cffi.requests import Session

CAPTURED = {}
def server(name, port):
    try:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', port)); srv.listen(1)
        srv.settimeout(15)
        c, _ = srv.accept()
        data = b''
        while b'\r\n\r\n' not in data:
            ch = c.recv(65536)
            if not ch: break
            data += ch
        head, _, rest = data.partition(b'\r\n\r\n')
        cl = 0
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                cl = int(line.split(b':')[1].strip())
        while len(rest) < cl:
            rest += c.recv(65536)
        CAPTURED[name] = head + b'\r\n\r\n' + rest[:cl]
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        c.close(); srv.close()
    except Exception as e:
        CAPTURED[name] = ('SERVER-ERR ' + repr(e)).encode()

AUTH = 'Signature signature="' + 'AB' * 304 + '",adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"'
HEADERS = [("Client-SDK", "flutter5.5.0@android5.5.0"), ("Authorization", AUTH),
           ("Content-Type", "application/x-www-form-urlencoded"),
           ("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"),
           ("Host", "127.0.0.1:18911"), ("Connection", "Keep-Alive"),
           ("Accept-Encoding", "gzip")]
BODY = "app_token=vf3lochhmgw0&gps_adid=x"
HEADERS = [("Client-SDK", "flutter5.5.0@android5.5.0"), ("Authorization", AUTH),
           ("Content-Type", "application/x-www-form-urlencoded"),
           ("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"),
           ("Host", "127.0.0.1:18911"), ("Connection", "Keep-Alive"),
           ("Accept-Encoding", "gzip"),
           ("Content-Length", "33")]

t = threading.Thread(target=server, args=('curl', 18911)); t.start()
time.sleep(0.3)
s = Session(impersonate='chrome131_android')
try:
    r = s.post('http://127.0.0.1:18911/session', headers=dict(HEADERS), data=BODY, verify=False, timeout=10)
    print('curl status', r.status_code)
except Exception as e:
    print('curl ERR', type(e).__name__, str(e)[:200])
t.join(5)

import http.client
t2 = threading.Thread(target=server, args=('py', 18912)); t2.start()
time.sleep(0.3)
c = http.client.HTTPConnection('127.0.0.1', 18912, timeout=10)
c.putrequest('POST', '/session', skip_host=1, skip_accept_encoding=1)
for k, v in HEADERS:
    if k == 'Host': v = '127.0.0.1:18912'
    c.putheader(k, v)
c.endheaders(BODY.encode())
print('py status', c.getresponse().status)
t2.join(5)

a = CAPTURED.get('curl', b'').replace(b'127.0.0.1:18911', b'HOST')
b = CAPTURED.get('py', b'').replace(b'127.0.0.1:18912', b'HOST')
print('--- curl sent:'); print(a.decode('latin1')[:900])
print('--- identical:', a == b)
if a != b:
    la, lb = a.split(b'\r\n'), b.split(b'\r\n')
    for i, (x, y) in enumerate(zip(la, lb)):
        if x != y: print(' line%d curl=%r py=%r' % (i, x[:100], y[:100]))
    if len(la) != len(lb): print(' linecount', len(la), len(lb))
