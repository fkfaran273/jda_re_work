import frida, json, time
m = frida.get_device_manager()
m.add_remote_device('127.0.0.1:27042')
dev = None
for d in m.enumerate_devices():
    if d.id == 'socket@127.0.0.1:27042':
        dev = d
pid = dev.spawn(['social.hunch.app'])
print('spawned', pid, flush=True)
sess = dev.attach(pid)
src = """
send({java_available: (typeof Java !== 'undefined') && Java.available});
"""
def on_msg(msg, data):
    print(msg['type'], json.dumps(msg.get('payload', msg.get('stack', '')))[:300], flush=True)
script = sess.create_script(src)
script.on('message', on_msg)
script.load()
time.sleep(4)
dev.resume(pid)
time.sleep(10)
sess.detach()
print('done', flush=True)
