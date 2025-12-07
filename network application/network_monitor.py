import sys
import os
import json
import requests
import time
import threading
import uuid
from datetime import datetime
from pathlib import Path
import tempfile
import csv
import socket
import subprocess
import signal
import psutil
import traceback
import warnings
warnings.filterwarnings("ignore")

# ================= CONFIGURATION =================
SERVER_URL = "http://localhost:5000"  # Change to your server IP/domain
DEVICE_ID = str(uuid.getnode())  # Unique device ID from MAC
BATCH_SIZE = 20  # Send 20 flows at a time
CAPTURE_DURATION = 300  # Capture for 5 minutes between sends
# =================================================

class NetworkFlowMonitor:
    def __init__(self):
        self.running = False
        self.flows = {}
        self.flows_lock = threading.Lock()
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
        
        return list(set(interfaces))  # Remove duplicates
    
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
                print(f"✓ Device registered with server")
                return True
            else:
                print(f"✗ Device registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Could not connect to server: {e}")
            print("Will store data locally until server is available.")
            return False
    
    def send_flows_to_server(self, flows_data):
        """Send flows to server"""
        if not flows_data:
            return False
        
        try:
            batch_data = {
                "device_id": DEVICE_ID,
                "device_name": self.device_name,
                "ip_address": self.local_ip,
                "flows": flows_data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            response = requests.post(
                f"{SERVER_URL}/api/batch-flows",
                json=batch_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ Sent {len(flows_data)} flows: {result.get('message')}")
                return True
            else:
                print(f"✗ Server error: {response.text}")
                self.save_failed_batch(batch_data)
                return False
                
        except Exception as e:
            print(f"✗ Network error: {e}")
            self.save_failed_batch(batch_data)
            return False
    
    def save_failed_batch(self, batch_data):
        """Save failed batch for later retry"""
        try:
            os.makedirs("offline_data", exist_ok=True)
            filename = f"batch_{int(time.time())}.json"
            filepath = os.path.join("offline_data", filename)
            
            with open(filepath, 'w') as f:
                json.dump(batch_data, f, indent=2)
            
            print(f"  ↳ Saved offline: {filename}")
        except Exception as e:
            print(f"  ↳ Failed to save offline: {e}")
    
    def retry_failed_batches(self):
        """Retry sending failed batches"""
        if not os.path.exists("offline_data"):
            return
        
        print("Checking for offline data...")
        files = os.listdir("offline_data")
        if not files:
            return
        
        success_count = 0
        for filename in files:
            filepath = os.path.join("offline_data", filename)
            try:
                with open(filepath, 'r') as f:
                    batch_data = json.load(f)
                
                response = requests.post(
                    f"{SERVER_URL}/api/batch-flows",
                    json=batch_data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    os.remove(filepath)
                    success_count += 1
                    print(f"✓ Resent: {filename}")
                else:
                    print(f"✗ Still failed: {filename}")
                    
            except Exception as e:
                print(f"Error retrying {filename}: {e}")
        
        if success_count > 0:
            print(f"✓ Resent {success_count} offline batches")
    
    def extract_flows_from_csv(self, csv_path):
        """Extract flows from CSV and prepare for server"""
        flows_data = []
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row_idx, row in enumerate(reader):
                    # Generate unique flow ID
                    flow_id = f"{DEVICE_ID}_{int(time.time())}_{row_idx}"
                    
                    # Convert row to flow document
                    flow_doc = {
                        "flow_id": flow_id,
                        "device_id": DEVICE_ID,
                        "timestamp": datetime.utcnow().isoformat(),
                        "local_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        **{k: self.convert_value(v) for k, v in row.items()}
                    }
                    
                    flows_data.append(flow_doc)
                    
                    # Send in batches
                    if len(flows_data) >= BATCH_SIZE:
                        self.send_flows_to_server(flows_data)
                        flows_data = []
                        time.sleep(1)  # Small delay between batches
            
            # Send any remaining flows
            if flows_data:
                self.send_flows_to_server(flows_data)
                
            return True
            
        except Exception as e:
            print(f"Error processing CSV: {e}")
            traceback.print_exc()
            return False
    
    def convert_value(self, value):
        """Convert string values to appropriate types"""
        if value == '' or value is None:
            return None
        
        try:
            # Try to convert to float
            if '.' in str(value):
                return float(value)
            # Try to convert to int
            return int(value)
        except:
            # Return as string
            return str(value)
    
    def run_pcap2csv(self, interface=None, output_file=None, pcap_file=None):
        """Run your pcap2csv_win_v2.exe to capture/convert"""
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
            
            # Create temp directory for output
            temp_dir = tempfile.mkdtemp()
            if not output_file:
                output_file = os.path.join(temp_dir, "flows.csv")
            
            # Build command
            cmd = [exe_path, "-o", output_file]
            
            if pcap_file:
                # Process existing PCAP file
                cmd.extend(["-i", pcap_file])
                print(f"Processing PCAP file: {pcap_file}")
            else:
                # Live capture
                cmd.append("--live")
                if interface:
                    cmd.extend(["--iface", interface])
                print(f"Live capture on: {interface or 'default'}")
            
            print(f"Command: {' '.join(cmd)}")
            print(f"Output: {output_file}")
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
            
            return process, output_file, temp_dir
            
        except Exception as e:
            print(f"Error running pcap2csv: {e}")
            traceback.print_exc()
            return None, None, None
    
    def monitor_and_send(self, interface=None, duration=None):
        """Main monitoring loop"""
        print("\n" + "=" * 40)
        print("Starting Network Flow Monitor")
        print("=" * 40)
        
        # Try to register with server
        server_online = self.register_device()
        
        # Retry any offline data
        if server_online:
            self.retry_failed_batches()
        
        process = None
        last_send_time = time.time()
        
        try:
            # Start pcap2csv
            process, output_file, temp_dir = self.run_pcap2csv(interface=interface)
            
            if not process:
                return
            
            self.running = True
            
            print("\nMonitoring network traffic...")
            print("Press Ctrl+C to stop\n")
            
            # Main monitoring loop
            while self.running:
                time.sleep(5)  # Check every 5 seconds
                
                # Check if CSV file exists and has data
                if os.path.exists(output_file) and os.path.getsize(output_file) > 100:
                    print(f"Processing {os.path.getsize(output_file)} bytes of flow data...")
                    
                    # Extract and send flows
                    self.extract_flows_from_csv(output_file)
                    
                    # Clear the CSV file after processing
                    try:
                        open(output_file, 'w').close()
                    except:
                        pass
                
                # Check if process is still running
                if process.poll() is not None:
                    print("PCAP2CSV process stopped. Restarting...")
                    process, output_file, temp_dir = self.run_pcap2csv(interface=interface)
                
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
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    process.kill()
            
            print("\nNetwork monitor stopped.")
    
    def process_pcap_file(self, pcap_file):
        """Process a single PCAP file"""
        print(f"\nProcessing PCAP file: {pcap_file}")
        
        temp_dir = tempfile.mkdtemp()
        csv_file = os.path.join(temp_dir, "flows.csv")
        
        try:
            process, output_file, _ = self.run_pcap2csv(
                pcap_file=pcap_file,
                output_file=csv_file
            )
            
            if process:
                process.wait()  # Wait for conversion to complete
                
                if os.path.exists(csv_file) and os.path.getsize(csv_file) > 100:
                    print("Extracting flows from CSV...")
                    self.extract_flows_from_csv(csv_file)
                    print("✓ Processing complete!")
                else:
                    print("✗ No flows found in PCAP file")
            
        except Exception as e:
            print(f"Error processing PCAP: {e}")
        finally:
            # Cleanup
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass
    
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
        print(f"  {len(interfaces) + 2}. Process PCAP File")
        print(f"  {len(interfaces) + 3}. Settings")
        print(f"  {len(interfaces) + 4}. Exit")
        
        try:
            choice = input(f"\nSelect option (1-{len(interfaces) + 4}): ").strip()
            
            if choice.isdigit():
                choice = int(choice)
                
                if 1 <= choice <= len(interfaces):
                    interface = interfaces[choice - 1]
                    self.monitor_and_send(interface=interface)
                elif choice == len(interfaces) + 1:
                    self.monitor_and_send()
                elif choice == len(interfaces) + 2:
                    self.select_pcap_file()
                elif choice == len(interfaces) + 3:
                    self.show_settings()
                elif choice == len(interfaces) + 4:
                    print("Goodbye!")
                    return False
                else:
                    print("Invalid choice!")
            else:
                print("Please enter a number")
            
            return True
            
        except ValueError:
            print("Invalid input!")
            return True
        except KeyboardInterrupt:
            print("\nGoodbye!")
            return False
    
    def select_pcap_file(self):
        """Open file dialog to select PCAP file"""
        try:
            import tkinter as tk
            from tkinter import filedialog
            
            root = tk.Tk()
            root.withdraw()  # Hide main window
            
            pcap_file = filedialog.askopenfilename(
                title="Select PCAP file",
                filetypes=[
                    ("PCAP files", "*.pcap *.pcapng *.cap"),
                    ("All files", "*.*")
                ]
            )
            
            if pcap_file:
                self.process_pcap_file(pcap_file)
            else:
                print("No file selected")
                
        except ImportError:
            # Fallback to command line input
            pcap_file = input("Enter path to PCAP file: ").strip()
            if os.path.exists(pcap_file):
                self.process_pcap_file(pcap_file)
            else:
                print("File not found!")
    
    def show_settings(self):
        """Show settings menu"""
        print("\n" + "=" * 40)
        print("SETTINGS")
        print("=" * 40)
        
        print(f"\nCurrent Configuration:")
        print(f"  Server URL: {SERVER_URL}")
        print(f"  Device ID: {DEVICE_ID}")
        print(f"  Batch Size: {BATCH_SIZE} flows")
        print(f"  Device Name: {self.device_name}")
        print(f"  IP Address: {self.local_ip}")
        
        print("\nOptions:")
        print("  1. Change Server URL")
        print("  2. View Recent Activity")
        print("  3. Clear Offline Data")
        print("  4. Back to Main Menu")
        
        try:
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == "1":
                new_url = input("Enter new server URL: ").strip()
                if new_url:
                    # Update the global variable
                    globals()['SERVER_URL'] = new_url
                    print(f"Server URL updated to: {SERVER_URL}")
            elif choice == "2":
                self.view_activity()
            elif choice == "3":
                self.clear_offline_data()
            elif choice == "4":
                pass
            else:
                print("Invalid choice")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def view_activity(self):
        """View recent activity"""
        print("\nRecent Activity:")
        print("-" * 40)
        
        # Count offline files
        if os.path.exists("offline_data"):
            offline_count = len(os.listdir("offline_data"))
            print(f"Offline batches pending: {offline_count}")
        else:
            print("Offline batches pending: 0")
        
        print("\nServer Status:")
        try:
            response = requests.get(f"{SERVER_URL}/", timeout=5)
            if response.status_code == 200:
                print("✓ Server is online")
            else:
                print("✗ Server returned error")
        except:
            print("✗ Cannot connect to server")
    
    def clear_offline_data(self):
        """Clear offline data directory"""
        if os.path.exists("offline_data"):
            try:
                import shutil
                shutil.rmtree("offline_data")
                print("✓ Cleared all offline data")
            except Exception as e:
                print(f"✗ Error clearing data: {e}")
        else:
            print("No offline data to clear")

def main():
    """Main entry point"""
    print("Initializing Network Flow Monitor...")
    
    # Create necessary directories
    os.makedirs("offline_data", exist_ok=True)
    
    # Create monitor instance
    monitor = NetworkFlowMonitor()
    
    # Show interactive menu
    while monitor.show_menu():
        pass
    
    print("\nThank you for using Network Flow Monitor!")

if __name__ == "__main__":
    # Handle Ctrl+C gracefully
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Goodbye!")
    except Exception as e:
        print(f"\nFatal error: {e}")
        traceback.print_exc()
        input("\nPress Enter to exit...")