import sys
import os
import json
import requests
import time
import threading
import uuid
from datetime import datetime
import socket
import subprocess
import signal
import psutil
import traceback
import warnings
warnings.filterwarnings("ignore")

# ================= CONFIGURATION =================
SERVER_URL = "http://localhost:5000" 
DEVICE_ID = str(uuid.getnode())  # Unique device ID from MAC
# =================================================

class NetworkFlowMonitor:
    def __init__(self):
        self.running = False
        self.device_name = os.environ.get("COMPUTERNAME", socket.gethostname())
        self.local_ip = self.get_local_ip()
        
        # Path handling for PyInstaller
        if getattr(sys, 'frozen', False):
            self.base_dir = sys._MEIPASS
        else:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        print(f"=== Network Flow Monitor ===")
        print(f"Device: {self.device_name} ({DEVICE_ID})")
        print(f"IP: {self.local_ip}")
        print(f"Server: {SERVER_URL}")
        print("=" * 40)
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def get_network_interfaces(self):
        """List available network interfaces"""
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                # Skip loopback and virtual interfaces
                if interface.lower() != 'lo' and not interface.startswith('v'):
                    # Check if interface has IPv4 address
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                            interfaces.append(interface)
                            break
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        return list(set(interfaces))
    
    def register_device(self):
        """Register this device with the server"""
        try:
            device_info = {
                "device_id": DEVICE_ID,
                "device_name": self.device_name,
                "ip_address": self.local_ip,
                "location": "Unknown",
                "status": "active"
            }
            
            response = requests.post(
                f"{SERVER_URL}/api/register-device",
                json=device_info,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"Device registered with server")
                return True
            else:
                print(f"Device registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Could not connect to server: {e}")
            print("Will store data locally until server is available.")
            return False
    
    def run_pcap2csv(self, interface=None):
        """Run pcap2csv_win_v2.exe which now sends directly to server"""
        try:
            # Path to the embedded executable
            if getattr(sys, 'frozen', False):
                exe_path = os.path.join(self.base_dir, "pcap2csv_win_v2.exe")
            else:
                exe_path = "pcap2csv_win_v2.exe"
            
            if not os.path.exists(exe_path):
                print(f"ERROR: {exe_path} not found!")
                print("Make sure pcap2csv_win_v2.exe is in the same directory.")
                return False
            
            # Build command - NO OUTPUT FILE NEEDED!
            # pcap2csv now sends directly to server
            cmd = [exe_path, "--live", "--server", SERVER_URL, "--device-id", DEVICE_ID]
            
            if interface:
                cmd.extend(["--iface", interface])
            
            print(f"Live capture on: {interface or 'default'}")
            print(f"Command: {' '.join(cmd)}")
            print("=" * 40)
            
            # Run the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output in real-time
            def read_output():
                for line in iter(process.stdout.readline, ''):
                    if line.strip():
                        print(f"[PCAP2CSV] {line.strip()}")
            
            # Start output reader thread
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
            return process
            
        except Exception as e:
            print(f"Error running pcap2csv: {e}")
            traceback.print_exc()
            return None
    
    def monitor_and_send(self, interface=None, duration=None):
        """Main monitoring loop - SIMPLIFIED!"""
        print("\n" + "=" * 40)
        print("Starting Network Flow Monitor")
        print("=" * 40)
        
        # Try to register with server
        self.register_device()
        
        self.running = True
        process = None
        
        try:
            # Start pcap2csv - it sends data directly now
            process = self.run_pcap2csv(interface=interface)
            
            if not process:
                return
            
            print("\nMonitoring network traffic...")
            print("Data sent directly to server")
            print("Press Ctrl+C to stop\n")
            
            # Simple monitoring loop
            last_send_time = time.time()
            while self.running:
                time.sleep(1)  # Just keep alive
                
                # Check if process is still running
                if process.poll() is not None:
                    print("PCAP2CSV process stopped. Restarting...")
                    process = self.run_pcap2csv(interface=interface)
                
                # Check duration limit
                if duration and time.time() - last_send_time > duration:
                    print(f"\nCapture duration reached ({duration} seconds)")
                    break
                    
        except KeyboardInterrupt:
            print("\n\nStopped by user")
        except Exception as e:
            print(f"\nError in monitor: {e}")
            traceback.print_exc()
        finally:
            self.running = False
            
            # Cleanup
            if process:
                try:
                    print("Stopping pcap2csv process...")
                    # Send Ctrl+C to the process
                    if sys.platform == "win32":
                        process.send_signal(signal.CTRL_C_EVENT)
                    else:
                        process.send_signal(signal.SIGINT)
                        
                    # Wait for graceful shutdown
                    process.wait(timeout=5)
                    print("pcap2csv process stopped")
                except subprocess.TimeoutExpired:
                    print("Process did not stop gracefully, forcing termination...")
                    process.kill()
                    process.wait()
                except Exception as e:
                    print(f"Error stopping process: {e}")
            
            print("\nNetwork monitor stopped.")
    
    def show_menu(self):
        """Show interactive menu"""
        print("\n" + "=" * 40)
        print("NETWORK FLOW MONITOR")
        print("=" * 40)
        
        # Get available interfaces
        interfaces = self.get_network_interfaces()
        
        print("\nAvailable Network Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        
        print(f"  {len(interfaces) + 1}. Default Interface (auto-select)")
        print(f"  {len(interfaces) + 2}. Exit")
        
        try:
            choice = input(f"\nSelect option (1-{len(interfaces) + 2}): ").strip()
            
            if choice.isdigit():
                choice = int(choice)
                
                if 1 <= choice <= len(interfaces):
                    interface = interfaces[choice - 1]
                    self.monitor_and_send(interface=interface)
                elif choice == len(interfaces) + 1:
                    self.monitor_and_send()
                elif choice == len(interfaces) + 2:
                    return False
                else:
                    print("Invalid choice!")
            else:
                print("Please enter a number")
            
            return True
            
        except (KeyboardInterrupt, EOFError):  # Handle Ctrl+C and Ctrl+Z
            return False  # Return False to exit the program
        except ValueError:
            print("Invalid input!")
            return True
        except Exception as e:
            print(f"Unexpected error: {e}")
            return True

def main():
    """Main entry point"""
    print("Initializing Network Flow Monitor...")
    
    # Create monitor instance
    monitor = NetworkFlowMonitor()
    
    # Show interactive menu
    while monitor.show_menu():
        pass
    
if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted.")
    except Exception as e:
        print(f"\nFatal error: {e}")
        traceback.print_exc()
        input("\nPress Enter to exit...")