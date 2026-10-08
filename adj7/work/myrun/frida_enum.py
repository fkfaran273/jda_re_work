import frida, json
m = frida.get_device_manager()
m.add_remote_device('127.0.0.1:27042')
dev = None
for d in m.enumerate_devices():
    if d.id == 'socket@127.0.0.1:27042':
        dev = d
sess = dev.attach('Hunch')
src = """
Java.perform(function () {
  var out = [];
  ['com.adjust.sdk.sig.NativeLibHelper','com.adjust.sdk.sig.n','com.adjust.sdk.sig.SignUtil'].forEach(function (cn) {
    try {
      var c = Java.use(cn);
      var ms = c.class.getDeclaredMethods();
      for (var i = 0; i < ms.length; i++) out.push(cn + ' :: ' + ms[i].toString());
    } catch (e) { out.push(cn + ' MISSING ' + e); }
  });
  send({methods: out});
});
"""
msgs = []
def on_msg(msg, data):
    if msg['type'] == 'send':
        print(json.dumps(msg['payload'], indent=1)[:4000])
    elif msg['type'] == 'error':
        print('ERR', (msg.get('stack') or '')[:1500])
script = sess.create_script(src)
script.on('message', on_msg)
script.load()
import time; time.sleep(8)
sess.detach()
