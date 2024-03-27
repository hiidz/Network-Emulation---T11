import platform
from subprocess import Popen, PIPE

def run_script(script_name):
    if platform.system() == 'Windows':
        return Popen(["start", "cmd.exe", "/k", "python", script_name], shell=True)
    elif platform.system() == 'Darwin':
        return Popen(['osascript', '-e', f'tell app "Terminal" to do script "python {script_name}"'])

node1 = run_script("app/node-1.py")
router1 = run_script("app/router-interface-1.py")

node2 = run_script("app/node-2.py")
router2 = run_script("app/router-interface-2.py")

node3 = run_script("app/node-3.py")
router3 = run_script("app/router-interface-3.py")

node4 = run_script("app/node-4.py")
router4 = run_script("app/router-interface-4.py")

router5 = run_script("app/router-interface-5.py")
