import io
p = "appcap_reg_src.js"
t = io.open(p, encoding="utf-8").read()
anchor = "  send({ type: 'log', note: 'guards disarmed' });"
extra = (
    "  var abortPtr = findExp('libc.so', 'abort');\n"
    "  if (abortPtr) Interceptor.replace(abortPtr, new NativeCallback(function () { send({ type: 'block', note: 'abort()' }); }, 'void', []));\n"
    "  var _exitPtr2 = findExp('libc.so', '_exit');\n"
    "  if (_exitPtr2) Interceptor.replace(_exitPtr2, new NativeCallback(function (c) { send({ type: 'block', note: '_exit' }); }, 'void', ['int']));\n"
)
if "abortPtr" not in t:
    t = t.replace(anchor, extra + anchor)
io.open(p, "w", encoding="utf-8").write(t)
print("abort disarmed:", t.count("abortPtr"), "_exit:", t.count("_exitPtr2"))
