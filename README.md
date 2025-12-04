
# AI POWERED Traffic Analyzer

### Summary 
This project provides a complete solution for **network traffic analysis** using PCAP files. Users can upload packet capture files (`.pcap` / `.pcapng`) or perform live capture, and the system classifies network flows into categories like Web, Multimedia, Social Media, or Malicious using a Python-based XGBoost model. The platform includes a **React frontend** for interactive visualization and a **Node.js/Express backend** for file handling, analysis, and WebSocket-based live updates.

---

## Features
- Upload `.pcap` or `.pcapng` files for automated flow extraction and classification.
- Live network capture and real-time classification.
- Traffic classification into Web, Multimedia, Social Media, and Malicious categories.
- Flow statistics and top-10 flow details visualization.
- Interactive charts for traffic distribution.
- WebSocket support for live capture updates.

---
## Installation & Setup

### Backend
```bash
cd backend
npm install
````

### Frontend

```bash
cd frontend
npm install
```

---

## Running the Application

### Start Backend

```bash
cd backend
npm run dev
```

### Start Frontend

```bash
cd frontend
npm run dev
```

* Backend runs on `http://localhost:3001`
* Frontend runs on `http://localhost:5173`


---

## 📁 Project Structure for Cron Job

The project is organized into the following Python scripts located in the `/python_files` directory:

| File | Description |
| :--- | :--- |
| `server.py` | Python server that hosts the ML model, stores data, and handles classification requests. |
| `realtime_sniffer.py`| A client script that captures live traffic and sends it to the server for classification. |
| `classify_ui.py` | A Streamlit web UI for uploading PCAP files or viewing live analysis. |
| `pcap2csv_win.py` | A utility script to convert `.pcap` files to `.csv` format (for Windows). |
| `pcap2csv_win_v2.py` | Updated version of `pcap2csv_win.py` with additional feature for viewing the urls visited. |
| `input.pcap` | A sample Wireshark-captured PCAP file for testing the upload functionality. |


Note: Run realtime_sniffer.py and server.py simultaneously for live flow capture and classification.
---
## Notes

* Ensure **Python 3** is installed and accessible (`py -3` on Windows, `python3` on macOS/Linux).
* Required Python packages for flow analysis: `pandas`, `numpy`, `joblib`, `scikit-learn`, `xgboost`.
* Uploaded files are stored in `backend/uploads/`.
* Use `.pcap` or `.pcapng` files only. File size limit: 100MB.
* Live capture requires proper network interface name (Windows: `Wi-Fi` / `Ethernet`).

---

## Update in Progress

* Add **authentication and session management**.
* Improve **real-time dashboard** for live capture flows.
* Optimize **Python flow classification** for large PCAP files.
* Add **frontend pagination and filtering** for flow table.

---

## License

This project is open-source. But only contributors allowed are my teammates✋


