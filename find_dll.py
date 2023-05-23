import psutil

def find_executing_dlls():
    dlls = set()
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            p = psutil.Process(proc.info['pid'])
            if p.name().lower() in ['explorer.exe', 'taskmgr.exe']:
                continue  # Skip Windows system processes
            dll_list = p.memory_maps(grouped=True)
            for entry in dll_list:
                if entry.path.endswith('.dll'):
                    dlls.add(entry.path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return dlls

if __name__ == '__main__':
    executing_dlls = find_executing_dlls()
    print("Executing DLLs:")
    for dll in executing_dlls:
        print(dll)
