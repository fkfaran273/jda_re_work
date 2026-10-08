import frida, json, time
m = frida.get_device_manager()
m.add_remote_device('127.0.0.1:27042')
dev = None
for d in m.enumerate_devices():
    if d.id == 'socket@127.0.0.1:27042':
        dev = d
for p in dev.enumerate_processes():
    if 'hunch' in p.name.lower():
        print('pid', p.pid, 'name', p.name)
sess = dev.attach(31966 if False else [p.pid for p in dev.enumerate_processes() if 'hunch' in p.name.lower()][0])
src = """
send({java_available: (typeof Java !== 'undefined') && Java.available});
"""
def on_msg(msg, data):
    print(msg['type'], json.dumps(msg.get('payload', msg.get('stack', '')))[:500])
script = sess.create_script(src)
script.on('message', on_msg)
script.load()
time.sleep(5)
sess.detach()
