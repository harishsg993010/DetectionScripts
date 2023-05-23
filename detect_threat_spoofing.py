import psutil
from pydbg import *
from pydbg.defines import *

def detect_thread_stack_spoofing(dbg):
    suspicious_threads = []

    # Iterate over the threads in the process
    for (thread_id, thread_handle, start_address, thread_data) in dbg.enumerate_threads():

        # Get the process name using the thread handle
        try:
            process_name = psutil.Process(dbg.get_process_id_from_thread(thread_handle)).name()
        except psutil.NoSuchProcess:
            continue

        # Check if the process name matches the expected binary name
        if process_name.lower() != target_process_name.lower():
            suspicious_threads.append(thread_id)

    # Print the suspicious threads
    if suspicious_threads:
        print("Threads with potential stack spoofing:")
        for thread_id in suspicious_threads:
            print(f"Thread ID: {thread_id}")
    else:
        print("No threads with stack spoofing detected.")

    return DBG_CONTINUE

def detect_thread_stack_spoofing_tool(target_process_name):
    dbg = pydbg()

    # Set a breakpoint on the ThreadEntry callback to detect new threads
    dbg.set_callback(EXCEPTION_BREAKPOINT, detect_thread_stack_spoofing)

    # Run the process
    dbg.attach(psutil.Process(target_process_name).pid)
    dbg.run()

if __name__ == '__main__':
    target_process_name = "target.exe"
    detect_thread_stack_spoofing_tool(target_process_name)
