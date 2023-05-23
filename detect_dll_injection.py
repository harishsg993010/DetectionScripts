import psutil

def detect_dll_injection():
    suspicious_processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
        try:
            p = psutil.Process(proc.info['pid'])
            if p.name().lower() in ['explorer.exe', 'taskmgr.exe']:
                continue  # Skip Windows system processes
            
            # Get the process memory maps
            memory_maps = p.memory_maps()
            
            # Check if any memory map contains writable executable memory
            for mem_map in memory_maps:
                if mem_map.path and mem_map.is_executable and mem_map.is_writable:
                    suspicious_processes.append((p.name(), proc.info['pid']))
                    break

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return suspicious_processes

if __name__ == '__main__':
    suspicious_procs = detect_dll_injection()
    
    if suspicious_procs:
        print("Processes with potential DLL injection:")
        for process in suspicious_procs:
            print(f"Process: {process[0]}, PID: {process[1]}")
    else:
        print("No processes with DLL injection detected.")
