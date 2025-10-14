import platform
import os
import psutil

# function to gather information about the operating system
def gather_os_info():
    info = {
        "architecture":platform.architecture(),
        "Network Node": platform.node(),
        "CPU":platform.processor()
    }
    return info

# getting running processes
def running_process():
    processes = []
    attr = ["pid", "name","username", "exe", "create_time"]
    for p in psutil.process_iter(attrs=attr):
        try:
            processes.append(p.info)
        except ( psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess ):
            print("Psutil error")
    return processes

# getting network connections of the target machine
def get_network_con():
    connections = []

    for conn in psutil.net_connections():
        if conn.status and conn.raddr:
            connections.append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                "status": conn.status,
                "type": conn.type,
                "pid": conn.pid
            })
    return connections

if __name__ == "__main__":
    network_conn = get_network_con()
    process = running_process()
    os_info = gather_os_info()
    
    # function specific calling
    print("=" * 75)
    print("[+] GETTING NETWORK INFORMATION")
    print("=" * 75)
    print(f"{'PID':<8} {'Status':<15} {'Local Address':<25} {'Remote Address':<25}")
    print("-" * 75)
    for conn in network_conn:
        # Look up the process name from the PID for more context
        proc_name = "N/A"
        if conn['pid']:
            try:
                proc_name = psutil.Process(conn['pid']).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Access Denied"
        print(f"{conn['pid'] or 'N/A':<8} {conn['status']:<15} {conn['local_address']:<25} {conn['remote_address']:<25} ({proc_name})")

    print("=" * 75)
    print("[+] GETTING OS INFORMATION")
    print("=" * 75)
    print(f"{'PID':<8} {'Username':<25} {'Name':<30}")
    print("-" * 63)
    for proc in process:
        # Some usernames can be None, handle this gracefully
        username = proc['username'] if proc['username'] is not None else 'N/A'
        print(f"{proc['pid']:<8} {username:<25} {proc['name']:<30}")