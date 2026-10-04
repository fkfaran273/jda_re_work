# mi_chain_wait.py - sleep out the 20-min session interval (imposed by run 1's
# booked session at 07:45:42Z), then run the user's exact scenario:
#   GAID 274418fe (their device's real click, reftag cA1DXYdvcrG5k) ->
#   python /session -> /sdk_click(their reftag) -> /attribution
import runpy
import time

# last booked session 2026-09-17T07:45:42Z = epoch 1789631142 (+20m min-interval)
TARGET = 1789631142 + 1200 + 60   # +60s buffer
while time.time() < TARGET:
    time.sleep(5)
print("[wait] interval cleared; firing user's reftag chain", flush=True)
runpy.run_path(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\mi_chain.py",
               run_name="__main__")
