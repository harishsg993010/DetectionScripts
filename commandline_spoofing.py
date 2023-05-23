import psutil

def detect_commandline_spoofing():
    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline is not None and len(cmdline) > 1:
                # Check if the command-line arguments have been tampered with
                original_cmdline = ' '.join(cmdline[1:])
                actual_cmdline = ' '.join(psutil.Process(proc.info['pid']).cmdline()[1:])
                if original_cmdline.lower() != actual_cmdline.lower():
                    suspicious_processes.append((proc.info['name'], proc.info['pid'], original_cmdline, actual_cmdline))

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return suspicious_processes

if __name__ == '__main__':
    suspicious_procs = detect_commandline_spoofing()

    if suspicious_procs:
        print("Processes with potential command-line spoofing:")
        for process in suspicious_procs:
            print(f"Process: {process[0]}, PID: {process[1]}, Original Command-Line: {process[2]}, Actual Command-Line: {process[3]}")
    else:
        print("No processes with command-line spoofing detected.")
