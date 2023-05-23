import os
import psutil
import winreg

def expand_system_root(path):
    system_root = os.environ.get("SystemRoot")
    if system_root:
        path = path.replace("%SystemRoot%", system_root)
    return path

def detect_suspicious_service_tampering():
    # Get the list of currently running services
    services = psutil.win_service_iter()

    # Iterate over the services and check for suspicious behavior
    for service in services:
        service_name = service.name()

        try:
            # Open the service key in the Windows Registry
            service_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                         f"SYSTEM\\CurrentControlSet\\Services\\{service_name}",
                                         access=winreg.KEY_READ)

            # Check if the service is set to auto-start on system boot
            start_type = winreg.QueryValueEx(service_key, "Start")[0]
            if start_type != 2:
                print(f"Suspicious start type for service {service_name}. Expected: 2 (Auto), Actual: {start_type}")

            # Check if the service executable path is modified
            image_path = winreg.QueryValueEx(service_key, "ImagePath")[0]
            expected_path = expand_system_root(service.binpath())
            actual_path = expand_system_root(image_path)
            
            expected_filename = os.path.basename(expected_path)
            actual_filename = os.path.basename(actual_path)

            if actual_path.lower() != expected_path.lower():
                print(f"Suspicious executable path for service {service_name}. Expected: {expected_path}, Actual: {actual_path}")
            elif actual_filename.lower() != expected_filename.lower():
                print(f"Suspicious filename for service {service_name}. Expected: {expected_filename}, Actual: {actual_filename}")

            # Close the service key
            winreg.CloseKey(service_key)

        except WindowsError:
            # Error occurred while accessing the service key
            continue

if __name__ == '__main__':
    detect_suspicious_service_tampering()
