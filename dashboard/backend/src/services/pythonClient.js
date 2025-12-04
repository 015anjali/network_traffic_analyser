
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs-extra');
const os = require('os');

class PythonClient {
  constructor() {
    this.workerPath = path.join(__dirname, '..', '..', '..', 'worker');
    this.dataPath = path.join(__dirname, '..', '..', '..', 'data'); 
    this.activeSessions = new Map();

    const venvPath = path.join(__dirname, '..', '..', '..', 'venv');
    if (os.platform() === 'win32') {
      // Use the venv Python executable
      this.pythonCmd = path.join(venvPath, 'Scripts', 'python.exe');
    } else {
      this.pythonCmd = path.join(venvPath, 'bin', 'python3');
    }
  }

  spawnPython(args, cwd) {
    // Always add '-3' for py launcher to force Python 3
    if (this.pythonCmd === 'py') args.unshift('-3');
    return spawn(this.pythonCmd, args, { cwd });
  }

  /** ===================== LIVE CAPTURE ===================== **/
  async startLiveCapture(sessionId, config = {}) {
    const { interface: iface = 'Wi-Fi', refreshRate = 30, lastNSeconds = null } = config;
    const outputFile = path.join(this.dataPath, `liveflows_${sessionId}.csv`);

    console.log(`[LIVE] Starting capture for session: ${sessionId}`);
    const pythonProcess = this.spawnPython(['pcap2csv_win_new.py', '--live', '--iface', iface, '-o', outputFile], this.workerPath);

    this.activeSessions.set(sessionId, { process: pythonProcess, outputFile, config, startTime: new Date(), status: 'running' });

    pythonProcess.stdout.on('data', data => console.log(`[LIVE ${sessionId}] stdout:`, data.toString()));
    pythonProcess.stderr.on('data', data => console.error(`[LIVE ${sessionId}] stderr:`, data.toString()));
    pythonProcess.on('close', code => {
      console.log(`[LIVE ${sessionId}] process exited with code ${code}`);
      const session = this.activeSessions.get(sessionId);
      if (session) session.status = 'stopped';
    });

    this.startPeriodicClassification(sessionId, refreshRate, lastNSeconds);
    return { success: true, sessionId, message: 'Live capture started' };
  }

  async stopLiveCapture(sessionId) {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    if (session.process && !session.process.killed) session.process.kill('SIGINT');
    if (session.classificationInterval) clearInterval(session.classificationInterval);
    session.status = 'stopped';
    console.log(`[LIVE] Stopped capture for session: ${sessionId}`);
    return { success: true, sessionId, message: 'Live capture stopped' };
  }
  /** ===================== PERIODIC CLASSIFICATION ===================== **/
  startPeriodicClassification(sessionId, refreshRate, lastNSeconds) {
    const session = this.activeSessions.get(sessionId);
    if (!session) return;

    console.log(`[LIVE ${sessionId}] Starting periodic classification every ${refreshRate}s`);

    const classifyAndBroadcast = async () => {
      try {
        console.log(`[LIVE ${sessionId}] === Starting classification cycle ===`);
        console.log(`[LIVE ${sessionId}] Checking file:`, session.outputFile);

        // Use null for lastNSeconds to get ALL flows, not just recent ones
        const flows = await this.classifyFlows(session.outputFile, null);
        
        if (!flows || flows.length === 0) {
          console.warn(`[LIVE ${sessionId}] No flows extracted after classification`);
          return;
        }

        console.log(`[LIVE ${sessionId}] Raw flows from Python:`, flows.length);

        // PROPERLY FORMAT FLOWS FOR FRONTEND
        const formattedFlows = flows.map((flow, index) => {
          // Extract the actual data from Python response
          return {
            id: flow.FlowID || index,
            srcIP: flow.SrcIP || flow.srcIP || 'Unknown',
            dstIP: flow.DstIP || flow.dstIP || 'Unknown',
            srcPort: flow.SrcPort || flow.srcPort || 0,
            dstPort: flow.DstPort || flow.dstPort || 0,
            protocol: flow.Protocol || flow.protocol || 'Unknown',
            prediction: flow.Prediction || flow.prediction || 'Unknown',
            bytes: flow.TotalBytes || flow.bytes || flow.TotalBytes || 0,
            packets: flow.TotalPackets || flow.packets || flow.TotalPackets || 0,
            // Add URL field - handle both cases
            URLs: flow.URLs || flow.urls || ''
          };
        });

        console.log(`[LIVE ${sessionId}] Formatted ${formattedFlows.length} flows for frontend`);

        const stats = this.calculateStats(formattedFlows);
        console.log(`🎉 [LIVE ${sessionId}] Classification successful:`, stats);

        // Broadcast to clients
        if (global.broadcast) {
          console.log(`[LIVE ${sessionId}] Broadcasting ${Math.min(formattedFlows.length, 20)} flows to clients...`);
          
          global.broadcast({
            type: 'live_update',
            sessionId,
            data: { 
              flows: formattedFlows.slice(-20), // Last 20 flows for display
              stats, 
              timestamp: new Date().toISOString(),
              totalProcessed: formattedFlows.length
            }
          });
          console.log(`✅ [LIVE ${sessionId}] Broadcast complete`);
        } else {
          console.error(`[LIVE ${sessionId}] No broadcast function available`);
        }
      } catch (err) {
        console.error(`[LIVE ${sessionId}] Periodic classification error:`, err);
      }
    };

    // Start first classification after 8 seconds (give time for initial capture)
    setTimeout(classifyAndBroadcast, 8000);
    
    // Set up periodic classification
    session.classificationInterval = setInterval(classifyAndBroadcast, refreshRate * 1000);
    
    console.log(`[LIVE ${sessionId}] Periodic classification scheduled`);
  }

  /** ===================== ANALYZE PCAP ===================== **/
  async analyzePcapFile(filePath, uploadId) {
    const absPath = path.isAbsolute(filePath) ? filePath : path.join(this.dataPath, filePath);
    console.log(`[ANALYZE] PCAP file: ${absPath}`);
    if (!await fs.pathExists(absPath)) return { success: false, uploadId, message: "PCAP not found", flows: [], stats: {}, outputFile: null };

    const outputFile = path.join(this.dataPath, `analysis_${uploadId}.csv`);
    console.log(`[ANALYZE] Output CSV: ${outputFile}`);

    const args = ['pcap2csv_win_new.py', '-i', absPath, '-o', outputFile];
    return new Promise(resolve => {
      const pythonProcess = this.spawnPython(args, this.workerPath);
      let stdout = '', stderr = '';
      pythonProcess.stdout.on('data', data => stdout += data.toString());
      pythonProcess.stderr.on('data', data => stderr += data.toString()); 

      pythonProcess.on('close', async (code) => {
        console.log(`[ANALYZE] Python process exited with code ${code}`);
        if (code !== 0) {
          console.error(`[ANALYZE] Python stderr:`, stderr);
          return resolve({ success: false, uploadId, message: stderr, flows: [], stats: {}, outputFile });
        }
          try {
            const flows = await this.classifyFlows(outputFile);
            if (!flows || flows.length === 0) return resolve({ success: false, uploadId, message: "No flows found", flows: [], stats: {}, outputFile });
            
    // PROPERLY FORMAT FLOWS FOR FRONTEND
            const formattedFlows = flows.map((flow, index) => ({
              id: flow.FlowID || index,
              srcIP: flow.SrcIP || flow.srcIP || 'Unknown',
              dstIP: flow.DstIP || flow.dstIP || 'Unknown', 
              srcPort: flow.SrcPort || flow.srcPort || 0,
              dstPort: flow.DstPort || flow.dstPort || 0,
              protocol: flow.Protocol || flow.protocol || 'Unknown',
              prediction: flow.Prediction || flow.prediction || 'Unknown',
              bytes: flow.TotalBytes || flow.bytes || 0,
              packets: flow.TotalPackets || flow.packets || 0,
              URLs: flow.URLs || flow.urls || ''
            }));
    
            console.log(`[ANALYZE] Formatted ${formattedFlows.length} flows for frontend`);
            const stats = this.calculateStats(formattedFlows);
            
            resolve({ success: true, uploadId, flows: formattedFlows, stats, outputFile });
          } catch (err) {
            console.error(`[ANALYZE] Classification error:`, err);
            resolve({ success: false, uploadId, message: err.message, flows: [], stats: {}, outputFile });
          }
        // try {
        //   const flows = await this.classifyFlows(outputFile);
        //   if (!flows || flows.length === 0) return resolve({ success: false, uploadId, message: "No flows found", flows: [], stats: {}, outputFile });
          
        //   // Format flows for frontend with URL support
        //   const formattedFlows = flows.map(flow => ({
        //     id: flow.FlowID || Math.random(),
        //     srcIP: flow.SrcIP,
        //     dstIP: flow.DstIP,
        //     srcPort: flow.SrcPort,
        //     dstPort: flow.DstPort,
        //     protocol: flow.Protocol,
        //     prediction: flow.Prediction,
        //     bytes: flow.TotalBytes,
        //     packets: flow.TotalPackets,
        //     URLs: flow.URLs || flow.urls || ''
        //   }));
          
        //   console.log(`[ANALYZE] Flows classified: ${formattedFlows.length}`);
        //   resolve({ success: true, uploadId, flows: formattedFlows, stats: this.calculateStats(flows), outputFile });
        // } catch (err) {
        //   console.error(`[ANALYZE] Classification error:`, err);
        //   resolve({ success: false, uploadId, message: err.message, flows: [], stats: {}, outputFile });
        // }
      });
    }); 
  } 

  /** ===================== CLASSIFY FLOWS ===================== **/
  async classifyFlows(csvFile, lastNSeconds = null) {
    console.log(`[CLASSIFY] Starting classification for: ${csvFile}`);
    
    if (!await fs.pathExists(csvFile)) {
      console.log(`[CLASSIFY] CSV file not found: ${csvFile}`);
      return [];
    }

    const escapedCsv = csvFile.replace(/\\/g, '\\\\');
    const pythonLastN = lastNSeconds === null ? 'None' : lastNSeconds;
    const escapedWorker = this.workerPath.replace(/\\/g, '\\\\');

    const code = `
import sys, json, traceback
sys.path.append(r'${escapedWorker}')

# Force flush for real-time output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(line_buffering=True)

try:
    from classifier_core import classify_flows
    print("[NODE->PYTHON] Successfully imported classifier_core", flush=True)
    
    result_df = classify_flows(r'${escapedCsv}', ${pythonLastN})
    print(f"[NODE->PYTHON] Classification returned DataFrame with {len(result_df)} rows", flush=True)
    
    if result_df is not None and not result_df.empty:
        flows = result_df.to_dict('records')
        print(f"[NODE->PYTHON] Converted {len(flows)} flows to JSON", flush=True)
        
        # Print JSON as a SINGLE LINE to make parsing easier
        json_output = json.dumps(flows)
        print("===JSON_START===" + json_output + "===JSON_END===")
    else:
        flows = []
        print("[NODE->PYTHON] No flows in result", flush=True)
        print("===JSON_START===[]===JSON_END===")
        
except Exception as e:
    print(f"[NODE->PYTHON ERROR] {str(e)}", flush=True)
    traceback.print_exc(file=sys.stderr)
    print("===JSON_START===[]===JSON_END===")
`;

    return new Promise(resolve => {
      console.log(`[CLASSIFY] Executing Python classification code...`);
      
      const pythonProcess = this.spawnPython(['-c', code], this.workerPath);
      let stdout = '', stderr = '';

      pythonProcess.stdout.on('data', data => {
        const output = data.toString();
        stdout += output;
        console.log(`[PYTHON STDOUT]`, output.trim());
      });
      
      pythonProcess.stderr.on('data', data => {
        const error = data.toString();
        stderr += error;
        if (error.trim()) {
          console.error(`[PYTHON STDERR]`, error.trim());
        }
      });

      pythonProcess.on('close', (code) => {
        console.log(`[CLASSIFY] Python process exited with code ${code}`);
        
        try {
          // Look for the JSON between markers
          const jsonMatch = stdout.match(/===JSON_START===(.*)===JSON_END===/s);
          
          if (jsonMatch && jsonMatch[1]) {
            const result = JSON.parse(jsonMatch[1].trim());
            console.log(`🎉 [CLASSIFY] SUCCESS! Parsed ${result.length} flows from Python`);
            resolve(Array.isArray(result) ? result : []);
          } else {
            console.log(`[CLASSIFY] No JSON markers found in stdout`);
            console.log(`[CLASSIFY] Looking for raw JSON array...`);
            
            // Fallback: look for any JSON array
            const lines = stdout.split('\n');
            for (let i = lines.length - 1; i >= 0; i--) {
              const line = lines[i].trim().replace(/\r/g, ''); // Remove \r
              if (line.startsWith('[') && line.endsWith(']')) {
                try {
                  const result = JSON.parse(line);
                  console.log(`🎉 [CLASSIFY] FALLBACK SUCCESS! Parsed ${result.length} flows`);
                  resolve(result);
                  return;
                } catch (e) {
                  // Continue searching
                }
              }
            }
            console.log(`[CLASSIFY] No valid JSON found anywhere`);
            resolve([]);
          }
        } catch (err) {
          console.error('❌ [CLASSIFY] Error parsing Python result:', err);
          console.error('Raw stdout for debugging:', stdout);
          resolve([]);
        }
      });
    });
  }

  // /** ===================== STATS ===================== **/
  // calculateStats(flows) {
  //   if (!flows || flows.length === 0) return { totalFlows: 0, webCount: 0, multimediaCount: 0, socialCount: 0, maliciousCount: 0 };
  //   return {
  //     totalFlows: flows.length,
  //     webCount: flows.filter(f => f.Prediction === 'Web').length,
  //     multimediaCount: flows.filter(f => f.Prediction === 'Multimedia').length,
  //     socialCount: flows.filter(f => f.Prediction === 'Social Media').length,
  //     maliciousCount: flows.filter(f => f.Prediction === 'Malicious').length
  //   };
  // }
  /** ===================== STATS ===================== **/
  calculateStats(flows) {
    if (!flows || flows.length === 0) {
      console.log('[STATS] No flows to calculate stats');
      return { totalFlows: 0, webCount: 0, multimediaCount: 0, socialCount: 0, maliciousCount: 0 };
    }
    
    console.log('[STATS] Calculating stats for:', flows.length, 'flows');
    console.log('[STATS] Sample flow:', flows[0]);
    
    const stats = {
      totalFlows: flows.length,
      webCount: flows.filter(f => f.prediction === 'Web').length,
      multimediaCount: flows.filter(f => f.prediction === 'Multimedia').length,
      socialCount: flows.filter(f => f.prediction === 'Social Media').length,
      maliciousCount: flows.filter(f => f.prediction === 'Malicious').length
    };
    
    console.log('[STATS] Calculated:', stats);
    return stats;
  }

  async getLiveFlows(sessionId, lastNSeconds = null) {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Session not found');
    const flows = await this.classifyFlows(session.outputFile, lastNSeconds);
    
    // Format flows with URL support
    const formattedFlows = flows.map(flow => ({
      id: flow.FlowID || Math.random(),
      srcIP: flow.SrcIP,
      dstIP: flow.DstIP,
      srcPort: flow.SrcPort,
      dstPort: flow.DstPort,
      protocol: flow.Protocol,
      prediction: flow.Prediction,
      bytes: flow.TotalBytes,
      packets: flow.TotalPackets,
      URLs: flow.URLs || flow.urls || ''
    }));
    
    return { flows: formattedFlows, stats: this.calculateStats(flows) };
  }

  getSessionInfo(sessionId) {
    const session = this.activeSessions.get(sessionId);
    return session ? { sessionId, status: session.status, startTime: session.startTime, config: session.config } : null;
  }

  getAllSessions() {
    return Array.from(this.activeSessions.entries()).map(([id, s]) => ({ sessionId: id, status: s.status, startTime: s.startTime, config: s.config }));
  }
}

module.exports = new PythonClient();