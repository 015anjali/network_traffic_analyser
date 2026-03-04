=== NETWORK FLOW MONITOR ===
HOW TO SETUP:
1. Activate venv
2. pip install -r requirements.txt
3. Run pyinstaller --onefile pcap2csv_win_v2.py --name pcap2csv_win_v2
4. Run copy dist\pcap2csv_win_v2.exe . 
5. Run python build_network_monitor.py
6. Create env and add MONGO DB Connection String (MONGO_URI=" ")

7. Run python flow_server.py
8. Run the client (Refer Application Flow)


APPLICATION FLOW:
1.START SERVER
 ├── python flow_server.py
 ├── Server runs on localhost:5000 
  
2.RUN CLIENT 
 ├── Go to dist folder
 ├── cd dist
 ├── ./NetworkFlowMonitor

3. IN THE NetworkFlowMonitor
 ├── Select Network interface (Wi-Fi for windows)
 ├── Device gets registered and Traffic Will be Captured
 ├── Flow Extraction Occurs and Send to Server
 ├── Gets stored in MongoDB 



Expected Folder Structure:
network-flow-monitor/
├── 📁 dist/                          # Built executables
│   ├── NetworkFlowMonitor.exe       # Main client (use this)
│   └── pcap2csv_win_v2.exe          # PCAP converter
├── pcap2csv_win_v2.exe              # Copied here for building
├── flow_server.py                   # Server (run this)
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


SERVER SETUP:
The server should be running at: http://localhost:5000

