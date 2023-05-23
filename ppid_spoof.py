import psutil

def detect_ppid_spoofing():
    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            ppid = proc.info['ppid']
            parent_name = psutil.Process(ppid).name()
            if proc.info['name'].lower() != parent_name.lower():
                suspicious_processes.append((proc.info['name'], proc.info['pid'], parent_name, ppid))

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return suspicious_processes

if __name__ == '__main__':
    suspicious_procs = detect_ppid_spoofing()

    if suspicious_procs:
        print("Processes with potential PPID spoofing:")
        for process in suspicious_procs:
            print(f"Process: {process[0]}, PID: {process[1]}, Parent: {process[2]}, PPID: {process[3]}")
    else:
        print("No processes with PPID spoofing detected.")
