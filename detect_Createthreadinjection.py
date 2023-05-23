import psutil
import ctypes
import re

def find_shellcode_injection():
    pattern = re.compile(rb'\x6A\x00\x68.{4}\xFF\xD0\xCC')
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            p = psutil.Process(proc.info['pid'])
            if p.name().lower() in ['explorer.exe', 'taskmgr.exe']:
                continue  # Skip Windows system processes
            data = p.memory_info().rss
            with open(f"/proc/{proc.info['pid']}/mem", "rb") as f:
                content = f.read(data)
                matches = pattern.findall(content)
                if matches:
                    processes.append((p.name(), proc.info['pid']))
        except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
            continue
    return processes

if __name__ == '__main__':
    shellcode_injection = find_shellcode_injection()
    if shellcode_injection:
        print("Processes with potential CreateRemoteThread shellcode injection:")
        for process in shellcode_injection:
            print(f"Process: {process[0]}, PID: {process[1]}")
    else:
        print("No processes with CreateRemoteThread shellcode injection found.")
