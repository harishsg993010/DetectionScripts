import psutil

def detect_lsass_dumping():
    lsass_pid = None

    # Find the PID of the lsass.exe process
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == 'lsass.exe':
            lsass_pid = proc.pid
            break

    if lsass_pid is None:
        print("lsass.exe process not found.")
        return False

    # Check if any process is accessing the memory of lsass.exe
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_info = proc.as_dict(attrs=['pid', 'name', 'memory_maps'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if proc_info['pid'] != lsass_pid and 'lsass.exe' in proc_info['name'].lower():
            for mmap in proc_info['memory_maps']:
                if mmap.path == '' and mmap.perms == 'r':
                    print(f"Potential lsass.exe dumping detected. Process: {proc_info['name']}, PID: {proc_info['pid']}")
                    return True

    return False

if __name__ == '__main__':
    if detect_lsass_dumping():
        print("Potential lsass.exe dumping detected.")
    else:
        print("No lsass.exe dumping detected.")
