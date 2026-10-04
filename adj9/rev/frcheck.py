import frida
d = frida.get_device_manager().add_remote_device("127.0.0.1:4777")
try:
    print("procs:", len(d.enumerate_processes()))
except Exception as e:
    print("ERR:", type(e).__name__, str(e)[:150])