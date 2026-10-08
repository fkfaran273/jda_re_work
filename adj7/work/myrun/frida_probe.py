import frida
m = frida.get_device_manager()
m.add_remote_device('127.0.0.1:27042')
for d in m.enumerate_devices():
    print(repr(d.id), repr(d.name), d.type)
    if d.type == 'remote' and '127.0.0.1' in (d.id or ''):
        try:
            print(' procs:', len(d.enumerate_processes()))
            names = [p.name for p in d.enumerate_processes()]
            print(' hunch/hanaf:', [n for n in names if 'hunch' in n.lower() or 'hanaf' in n.lower()])
        except Exception as e:
            print(' ERR', type(e).__name__, str(e)[:200])
