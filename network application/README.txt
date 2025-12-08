=== NETWORK FLOW MONITOR ===
HOW TO SETUP:
1. Activate venv
2. pip install -r requirements.txt
3. Run pyinstaller --onefile pcap2csv_win_v2.py --name pcap2csv_win_v2
4. Run copy dist\pcap2csv_win_v2.exe . 
5. Run python build_network_monitor.py
6. Create env and add MONGO DB Connection String (MONGO_URI=" ")
7. Run python flow_server.py
8. Run the client
# Option A: Double-click in File Explorer
# Navigate to dist/ folder and double-click NetworkFlowMonitor.exe

# Option B: Run from Command Prompt
dist\NetworkFlowMonitor.exe

Expected Folder Structure:
network-flow-monitor/
├── 📁 dist/                          # Built executables
│   ├── NetworkFlowMonitor.exe       # Main client (use this!)
│   └── pcap2csv_win_v2.exe          # PCAP converter
├── pcap2csv_win_v2.exe              # Copied here for building
├── flow_server.py                   # Server (run this!)
├── network_monitor.py               # Client source
├── pcap2csv_win_v2.py               # PCAP converter source
├── requirements.txt                 # Dependencies
├── .env                            # Config 
└── README.md                       # This file



WHAT THIS DOES:
1. Captures network traffic from your computer
2. Extracts detailed flow information (packet size, timing, protocols)
3. Sends data to central server
4. Stores data in MongoDB for later review

HOW TO USE:
1. Double-click NetworkFlowMonitor.exe
2. Select your network interface (Wi-Fi/Ethernet)
3. The program will automatically:
   - Capture network traffic
   - Extract flows and URLs
   - Send to server every 30 seconds
   - Show real-time progress



SERVER SETUP:
The server should be running at: http://localhost:5000

