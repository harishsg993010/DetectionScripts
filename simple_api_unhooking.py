from pydbg import *
from pydbg.defines import *

def detect_api_unhooking(dbg, args):
    unhooked_api = dbg.get_system_dll(args[0])  # Get the DLL name of the unhooked API
    print(f"API Unhooked: {unhooked_api}")
    return DBG_CONTINUE

def detect_api_unhooking_tool(target_process_name):
    dbg = pydbg()
    pid = dbg.load(target_process_name)

    # Set a breakpoint on the LdrpHandleTlsData function
    # This function is commonly used to unhook APIs
    func_address = dbg.func_resolve("ntdll.dll", "LdrpHandleTlsData")
    dbg.bp_set(func_address, description="API Unhooking", handler=detect_api_unhooking)

    dbg.run()

if __name__ == '__main__':
    target_process_name = "target.exe"
    detect_api_unhooking_tool(target_process_name)
