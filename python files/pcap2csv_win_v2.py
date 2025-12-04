# pcap2csv_win.py [Convert PCAP/Live to CSV + capture HTTP URLs & TLS SNI]
# Minimal CIC-style flow features + Host/SNI
# Requires: scapy[tls]

import argparse, csv, math, statistics, time, threading, signal, sys, os, re
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, sniff, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
import numpy as np
import socket
from threading import Lock
import re
import socket

# Add these after other global variables
flows_lock = Lock()
ip_to_hostname = {}

def is_valid_hostname(hostname):
    """Validate if a string looks like a real hostname"""
    if not hostname or len(hostname) > 253:
        return False
    
    # Check for common invalid patterns
    invalid_patterns = [
        r'^[0-9\.]+$',  # All numbers and dots
        r'[^a-zA-Z0-9\.\-]',  # Invalid characters
        r'\.\.',  # Double dots
        r'^\.|\.$',  # Starts or ends with dot
        r'^-|-$',  # Starts or ends with hyphen
    ]
    
    for pattern in invalid_patterns:
        if re.search(pattern, hostname):
            return False
    
    # Should have at least one dot and valid TLD
    if '.' not in hostname or len(hostname.split('.')[-1]) < 2:
        return False
    
    return True

def reverse_dns_lookup(ip):
    """Try to get hostname from IP using reverse DNS"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if is_valid_hostname(hostname):
            return hostname
    except:
        pass
    return None

flows = {}
running = True

# ---------- helpers ----------
def safe_mean(x): return statistics.fmean(x) if x else 0.0
def safe_std(x): return statistics.pstdev(x) if len(x) > 1 else 0.0
def safe_div(a,b): return a/b if b!=0 else 0.0
def pctile(lst,q): return float(np.percentile(lst,q)) if lst else 0.0

def iat_stats(times):
    if len(times)<2: return (0,0,0,0)
    gaps=[t2-t1 for t1,t2 in zip(times[:-1],times[1:])]
    return (safe_mean(gaps),safe_std(gaps),min(gaps),max(gaps))

def iat_all(times):
    if len(times)<2: return (0,0,0,0,0,0,0,0)
    gaps=[t2-t1 for t1,t2 in zip(times[:-1],times[1:])]
    return (safe_mean(gaps),safe_std(gaps),min(gaps),max(gaps),
            pctile(gaps,25),pctile(gaps,50),pctile(gaps,75),pctile(gaps,90))

def total_iat(times):
    if len(times)<2: return 0.0
    gaps=[t2-t1 for t1,t2 in zip(times[:-1],times[1:])]
    return sum(gaps)

def active_idle_stats(times,threshold=1.0):
    if len(times)<2: return (0,0,0,0,0,0,0,0)
    times_sorted=sorted(times)
    gaps=[t2-t1 for t1,t2 in zip(times_sorted[:-1],times_sorted[1:])]
    actives,idles=[],[]
    cur_start=times_sorted[0]
    for g in gaps:
        if g<=threshold: continue
        actives.append(times_sorted[gaps.index(g)]-cur_start)
        idles.append(g)
        cur_start=times_sorted[gaps.index(g)+1]
    if cur_start!=times_sorted[-1]:
        actives.append(times_sorted[-1]-cur_start)
    def stats(lst):
        return (min(lst) if lst else 0,
                safe_mean(lst) if lst else 0,
                max(lst) if lst else 0,
                safe_std(lst) if lst else 0)
    min_act,mean_act,max_act,std_act=stats(actives)
    min_idle,mean_idle,max_idle,std_idle=stats(idles)
    return (min_act,mean_act,max_act,std_act,min_idle,mean_idle,max_idle,std_idle)

def pkt_len(pkt):
    try: return len(bytes(pkt))
    except: return 0

def get_ip_layer(pkt):
    if IP in pkt: return pkt[IP],'IPv4'
    if IPv6 in pkt: return pkt[IPv6],'IPv6'
    return None,None

def get_l4_info(pkt):
    if TCP in pkt:
        l4=pkt[TCP]; return 'TCP',int(l4.sport),int(l4.dport),l4.flags
    if UDP in pkt:
        l4=pkt[UDP]; return 'UDP',int(l4.sport),int(l4.dport),None
    return None,None,None,None

def make_bi_key(proto,a_ip,a_port,b_ip,b_port):
    a=(a_ip,a_port); b=(b_ip,b_port)
    return (proto,a,b) if a<=b else (proto,b,a)

# ---------- main flow building ----------
def process_packet(src,dst,sport,dport,proto,ts,length,flags):
    key=make_bi_key(proto,src,sport,dst,dport)
    f=flows.get(key)
    if f is None:
        f={"src":src,"dst":dst,"sport":sport,"dport":dport,"proto":proto,
           "start":ts,"end":ts,
           "fwd_times":[ts],"bwd_times":[],
           "fwd_lens":[length],"bwd_lens":[],
           "fwd_flags":[],"bwd_flags":[],
           "urls":set()}  # <--- add urls/sni holder
        if flags is not None: f["fwd_flags"].append(flags)
        flows[key]=f
    else:
        f["end"]=max(f["end"],ts)
        if src==f["src"] and dst==f["dst"] and sport==f["sport"] and dport==f["dport"]:
            f["fwd_times"].append(ts); f["fwd_lens"].append(length)
            if flags is not None: f["fwd_flags"].append(flags)
        else:
            f["bwd_times"].append(ts); f["bwd_lens"].append(length)
            if flags is not None: f["bwd_flags"].append(flags)
def handle_packet(pkt):
    ip,_=get_ip_layer(pkt)
    if ip is None: 
        return
    proto,sport,dport,flags=get_l4_info(pkt)
    if proto is None: 
        return

    # always process the flow
    process_packet(ip.src,ip.dst,sport,dport,proto,float(pkt.time),pkt_len(pkt),flags)

    url = None
    # --- Extract HTTP Host+Path ---
    try:
        if pkt.haslayer(HTTPRequest):
            http_layer = pkt[HTTPRequest]
            host = http_layer.Host.decode(errors="ignore") if http_layer.Host else None
            path = http_layer.Path.decode(errors="ignore") if http_layer.Path else None
            if host and is_valid_hostname(host):
                full_url = f"http://{host}{path}" if path else f"http://{host}/"
                print(f"[HTTP] FOUND FULL URL: {full_url}")  # This will show in console
                url = full_url
    except:
        pass
    # # --- Extract HTTP Host+Path ---
    # try:
    #     if pkt.haslayer(HTTPRequest):
    #         http_layer = pkt[HTTPRequest]
    #         host = http_layer.Host.decode(errors="ignore") if http_layer.Host else None
    #         path = http_layer.Path.decode(errors="ignore") if http_layer.Path else None
    #         if host and is_valid_hostname(host):
    #             url = f"http://{host}{path}" if path else f"http://{host}/"
    #             print(f"[HTTP] Found URL: {url}")  # Debug line
    #     elif TCP in pkt and pkt.haslayer(Raw) and (sport == 80 or dport == 80):
    #         raw = pkt[Raw].load
    #         try:
    #             decoded = raw.decode(errors="ignore")
    #             if "HTTP" in decoded[:100]:  # Check only beginning
    #                 host_match = re.search(r"Host:\s*([^\r\n]+)", decoded)
    #                 path_match = re.search(r"(GET|POST|PUT|DELETE)\s+([^\s]+)\s+HTTP", decoded)
    #                 if host_match and path_match and is_valid_hostname(host_match.group(1)):
    #                     url = f"http://{host_match.group(1)}{path_match.group(2)}"
    #                     print(f"[HTTP Raw] Found URL: {url}")  # Debug line
    #         except:
    #             pass
    # except Exception as e:
    #     pass

    # --- Extract TLS SNI properly ---
    if url is None and TCP in pkt and pkt.haslayer(Raw) and (sport == 443 or dport == 443):
        raw = pkt[Raw].load
        try:
            # Minimum TLS header length check
            if len(raw) < 40 or raw[0] != 0x16:  # Not a Handshake
                return
                
            # Parse TLS Record Layer
            pos = 0
            content_type = raw[pos]; pos += 1
            version = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
            # Parse Handshake Protocol
            handshake_type = raw[pos]; pos += 1
            handshake_length = int.from_bytes(raw[pos:pos+3], byteorder='big'); pos += 3
            handshake_version = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
            # Skip random (32 bytes)
            pos += 32
            
            # Session ID
            session_id_length = raw[pos]; pos += 1
            pos += session_id_length
            
            # Cipher Suites
            cipher_suites_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            pos += cipher_suites_length
            
            # Compression Methods
            compression_methods_length = raw[pos]; pos += 1
            pos += compression_methods_length
            
            # Extensions
            if pos + 2 > len(raw):
                return
                
            extensions_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
            # Parse each extension
            extensions_end = pos + extensions_length
            while pos + 4 <= extensions_end:
                ext_type = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                ext_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                
                if ext_type == 0:  # SNI extension
                    if pos + 2 > len(raw):
                        break
                    sni_list_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                    sni_list_end = pos + sni_list_length
                    
                    while pos + 3 <= sni_list_end:
                        name_type = raw[pos]; pos += 1
                        name_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                        
                        if name_type == 0:  # host_name
                            if pos + name_length <= len(raw):
                                sni = raw[pos:pos+name_length].decode('utf-8', errors='ignore')
                                if is_valid_hostname(sni):
                                    url = f"https://{sni}/"  # Add https:// prefix
                                    print(f"[HTTPS] Found domain: {url}")  # Debug line
                                    break
                            pos += name_length
                        else:
                            pos += name_length
                    break
                else:
                    pos += ext_length
                    
        except Exception as e:
            #print(f"TLS parsing error: {e}")
            pass

    # --- Enhanced TLS detection for modern sites ---
    if url is None and TCP in pkt and pkt.haslayer(Raw):
        raw = pkt[Raw].load
        try:
            # Alternative TLS 1.3 patterns
            if len(raw) > 10:
                # Look for TLS handshake in any position
                for i in range(len(raw) - 10):
                    if (raw[i] == 0x16 and  # Handshake
                        raw[i+1] == 0x03 and  # TLS 1.x
                        raw[i+2] in [0x01, 0x02, 0x03, 0x04]):  # TLS versions
                        
                        # Simple SNI search pattern
                        sni_pattern = b'\x00\x00'
                        sni_pos = raw.find(sni_pattern, i)
                        if sni_pos != -1 and sni_pos + 5 < len(raw):
                            sni_len = raw[sni_pos + 3]
                            if sni_pos + 5 + sni_len <= len(raw):
                                sni = raw[sni_pos+5:sni_pos+5+sni_len].decode('utf-8', errors='ignore')
                                if is_valid_hostname(sni):
                                    url = f"https://{sni}/"  # Add https:// prefix
                                    print(f"[HTTPS Alt] Found domain: {url}")  # Debug line
                                    break
        except:
            pass

    if url:
        # Store the full URL as-is (no domain extraction)
        if is_valid_hostname(url.split('//')[-1].split('/')[0].split(':')[0]):
            key = make_bi_key(proto, ip.src, sport, ip.dst, dport)
            with flows_lock:
                if key in flows:
                    if "urls" not in flows[key]:
                        flows[key]["urls"] = set()
                    flows[key]["urls"].add(url)  # Store full URL
                    
                    # Also map IP to hostname for correlation
                    ip_to_hostname[ip.dst] = url.split('//')[-1].split('/')[0]

# def handle_packet(pkt):
#     ip,_=get_ip_layer(pkt)
#     if ip is None: 
#         return
#     proto,sport,dport,flags=get_l4_info(pkt)
#     if proto is None: 
#         return

#     # always process the flow
#     process_packet(ip.src,ip.dst,sport,dport,proto,float(pkt.time),pkt_len(pkt),flags)

#     url = None

#     # --- Extract HTTP Host+Path ---
#     try:
#         if pkt.haslayer(HTTPRequest):
#             http_layer = pkt[HTTPRequest]
#             host = http_layer.Host.decode(errors="ignore") if http_layer.Host else None
#             path = http_layer.Path.decode(errors="ignore") if http_layer.Path else None
#             if host and is_valid_hostname(host):
#                 url = f"http://{host}{path}" if path else f"http://{host}/"
#         elif TCP in pkt and pkt.haslayer(Raw) and (sport == 80 or dport == 80):
#             raw = pkt[Raw].load
#             try:
#                 decoded = raw.decode(errors="ignore")
#                 if "HTTP" in decoded[:100]:  # Check only beginning
#                     host_match = re.search(r"Host:\s*([^\r\n]+)", decoded)
#                     path_match = re.search(r"(GET|POST|PUT|DELETE)\s+([^\s]+)\s+HTTP", decoded)
#                     if host_match and path_match and is_valid_hostname(host_match.group(1)):
#                         url = f"http://{host_match.group(1)}{path_match.group(2)}"
#             except:
#                 pass
#     except Exception as e:
#         pass

#     # --- Extract TLS SNI properly ---
#     if url is None and TCP in pkt and pkt.haslayer(Raw) and (sport == 443 or dport == 443):
#         raw = pkt[Raw].load
#         try:
#             # Minimum TLS header length check
#             if len(raw) < 40 or raw[0] != 0x16:  # Not a Handshake
#                 return
                
#             # Parse TLS Record Layer
#             pos = 0
#             content_type = raw[pos]; pos += 1
#             version = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
#             length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
#             # Parse Handshake Protocol
#             handshake_type = raw[pos]; pos += 1
#             handshake_length = int.from_bytes(raw[pos:pos+3], byteorder='big'); pos += 3
#             handshake_version = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
#             # Skip random (32 bytes)
#             pos += 32
            
#             # Session ID
#             session_id_length = raw[pos]; pos += 1
#             pos += session_id_length
            
#             # Cipher Suites
#             cipher_suites_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
#             pos += cipher_suites_length
            
#             # Compression Methods
#             compression_methods_length = raw[pos]; pos += 1
#             pos += compression_methods_length
            
#             # Extensions
#             if pos + 2 > len(raw):
#                 return
                
#             extensions_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
            
#             # Parse each extension
#             extensions_end = pos + extensions_length
#             while pos + 4 <= extensions_end:
#                 ext_type = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
#                 ext_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                
#                 if ext_type == 0:  # SNI extension
#                     if pos + 2 > len(raw):
#                         break
#                     sni_list_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
#                     sni_list_end = pos + sni_list_length
                    
#                     while pos + 3 <= sni_list_end:
#                         name_type = raw[pos]; pos += 1
#                         name_length = int.from_bytes(raw[pos:pos+2], byteorder='big'); pos += 2
                        
#                         if name_type == 0:  # host_name
#                             if pos + name_length <= len(raw):
#                                 sni = raw[pos:pos+name_length].decode('utf-8', errors='ignore')
#                                 if is_valid_hostname(sni):
#                                     url = sni
#                                     break
#                             pos += name_length
#                         else:
#                             pos += name_length
#                     break
#                 else:
#                     pos += ext_length
                    
#         except Exception as e:
#             #print(f"TLS parsing error: {e}")
#             pass

#     # --- Extract HTTP/2 Host header ---
#     if url is None and TCP in pkt and pkt.haslayer(Raw):
#         raw = pkt[Raw].load
#         try:
#             # Look for HTTP/2 connection preface or headers frame
#             if raw.startswith(b'PRI * HTTP/2.0') or (len(raw) > 0 and raw[0] & 0xF0 == 0):
#                 decoded = raw.decode(errors='ignore')
#                 # Look for :authority header (HTTP/2 equivalent of Host)
#                 authority_match = re.search(r':authority:\s*([^\r\n]+)', decoded)
#                 if authority_match and is_valid_hostname(authority_match.group(1)):
#                     url = authority_match.group(1)
#         except:
#             pass

#     # --- Enhanced TLS detection for modern sites ---
#     if url is None and TCP in pkt and pkt.haslayer(Raw):
#         raw = pkt[Raw].load
#         try:
#             # Alternative TLS 1.3 patterns
#             if len(raw) > 10:
#                 # Look for TLS handshake in any position
#                 for i in range(len(raw) - 10):
#                     if (raw[i] == 0x16 and  # Handshake
#                         raw[i+1] == 0x03 and  # TLS 1.x
#                         raw[i+2] in [0x01, 0x02, 0x03, 0x04]):  # TLS versions
                        
#                         # Simple SNI search pattern
#                         sni_pattern = b'\x00\x00'
#                         sni_pos = raw.find(sni_pattern, i)
#                         if sni_pos != -1 and sni_pos + 5 < len(raw):
#                             sni_len = raw[sni_pos + 3]
#                             if sni_pos + 5 + sni_len <= len(raw):
#                                 sni = raw[sni_pos+5:sni_pos+5+sni_len].decode('utf-8', errors='ignore')
#                                 if is_valid_hostname(sni):
#                                     url = sni
#                                     break
#         except:
#             pass

#     if url:
#         # Extract domain for validation, but store the full URL
#         if '://' in url:
#             domain = url.split('//')[-1].split('/')[0].split(':')[0]
#         else:
#             domain = url.split('/')[0].split(':')[0]
        
#         if is_valid_hostname(domain):
#             key = make_bi_key(proto, ip.src, sport, ip.dst, dport)
#             with flows_lock:
#                 if key in flows:
#                     if "urls" not in flows[key]:
#                         flows[key]["urls"] = set()
#                     flows[key]["urls"].add(url)  # Store full URL instead of just domain
                    
#                     # Also map IP to hostname for correlation
#                     ip_to_hostname[ip.dst] = domain

def dump_flows_to_csv(filename):
    headers=[
        "FlowID","SrcIP","DstIP","SrcPort","DstPort","Protocol",
        "FlowDuration",
        "TotFwdPkts","TotBwdPkts","TotLenFwd","TotLenBwd",
        "FwdPktLenMean","FwdPktLenStd","FwdPktLenMin","FwdPktLenMax",
        "BwdPktLenMean","BwdPktLenStd","BwdPktLenMin","BwdPktLenMax",
        "FlowIATMean","FlowIATStd","FlowIATMin","FlowIATMax",
        "FwdIATMean","FwdIATStd","FwdIATMin","FwdIATMax",
        "BwdIATMean","BwdIATStd","BwdIATMin","BwdIATMax",
        "TotalFwdIAT","TotalBwdIAT",
        "TotalBytes","TotalPackets",
        "BytesPerSec","PktsPerSec","FwdBwdPktRatio","FwdBwdByteRatio",
        "FwdPktLenPct25","FwdPktLenPct50","FwdPktLenPct75","FwdPktLenPct90",
        "BwdPktLenPct25","BwdPktLenPct50","BwdPktLenPct75","BwdPktLenPct90",
        "FlowIAT25","FlowIAT50","FlowIAT75","FlowIAT90",
        "FwdIAT25","FwdIAT50","FwdIAT75","FwdIAT90",
        "BwdIAT25","BwdIAT50","BwdIAT75","BwdIAT90",
        "Fwd_SYN","Fwd_FIN","Fwd_RST","Fwd_PSH","Fwd_ACK","Fwd_URG",
        "Bwd_SYN","Bwd_FIN","Bwd_RST","Bwd_PSH","Bwd_ACK","Bwd_URG",
        "MinActive","MeanActive","MaxActive","StdActive",
        "MinIdle","MeanIdle","MaxIdle","StdIdle",
        "SrcPortCat","DstPortCat",
        "URLs"  # <--- full URLs instead of just hosts
    ]
    snapshot = list(flows.items())
    with open(filename,"w",newline="",encoding="utf-8") as fcsv:
        w=csv.DictWriter(fcsv,fieldnames=headers); w.writeheader()
        for idx,(key,fl) in enumerate(snapshot,start=1):
            dur=max(0.0,fl["end"]-fl["start"])
            all_times=sorted(fl["fwd_times"]+fl["bwd_times"])
            flow_iat=iat_stats(all_times)
            fwd_iat=iat_stats(fl["fwd_times"])
            bwd_iat=iat_stats(fl["bwd_times"])
            fwd_len_p=[pctile(fl["fwd_lens"],q) for q in (25,50,75,90)]
            bwd_len_p=[pctile(fl["bwd_lens"],q) for q in (25,50,75,90)]
            flow_iat_p=iat_all(all_times)
            fwd_iat_p=iat_all(fl["fwd_times"])
            bwd_iat_p=iat_all(fl["bwd_times"])
            total_bytes=sum(fl["fwd_lens"])+sum(fl["bwd_lens"])
            total_pkts=len(fl["fwd_lens"])+len(fl["bwd_lens"])
            bytes_per_sec=safe_div(total_bytes,dur)
            pkts_per_sec=safe_div(total_pkts,dur)
            pkt_ratio=safe_div(len(fl["fwd_lens"]),len(fl["bwd_lens"]))
            byte_ratio=safe_div(sum(fl["fwd_lens"]),sum(fl["bwd_lens"]))
            total_fiat=total_iat(fl["fwd_times"])
            total_biat=total_iat(fl["bwd_times"])
            act_idle=active_idle_stats(all_times)
            def count_flags(flags_list,mask): return sum(1 for f in flags_list if f & mask)
            fwd_syn=count_flags(fl["fwd_flags"],0x02)
            fwd_fin=count_flags(fl["fwd_flags"],0x01)
            fwd_rst=count_flags(fl["fwd_flags"],0x04)
            fwd_psh=count_flags(fl["fwd_flags"],0x08)
            fwd_ack=count_flags(fl["fwd_flags"],0x10)
            fwd_urg=count_flags(fl["fwd_flags"],0x20)
            bwd_syn=count_flags(fl["bwd_flags"],0x02)
            bwd_fin=count_flags(fl["bwd_flags"],0x01)
            bwd_rst=count_flags(fl["bwd_flags"],0x04)
            bwd_psh=count_flags(fl["bwd_flags"],0x08)
            bwd_ack=count_flags(fl["bwd_flags"],0x10)
            bwd_urg=count_flags(fl["bwd_flags"],0x20)
            def port_cat(p):
                if p in (80,443): return "Web"
                if p in (1935,554,8554): return "Multimedia"
                if p in (5222,5228,443): return "Social"
                if p<1024: return "System"
                return "Other"
            row={
                "FlowID":idx,
                "SrcIP":fl["src"],"DstIP":fl["dst"],
                "SrcPort":fl["sport"],"DstPort":fl["dport"],"Protocol":fl["proto"],
                "FlowDuration":dur,
                "TotFwdPkts":len(fl["fwd_lens"]), "TotBwdPkts":len(fl["bwd_lens"]),
                "TotLenFwd":sum(fl["fwd_lens"]), "TotLenBwd":sum(fl["bwd_lens"]),
                "FwdPktLenMean":safe_mean(fl["fwd_lens"]), "FwdPktLenStd":safe_std(fl["fwd_lens"]),
                "FwdPktLenMin":min(fl["fwd_lens"],default=0), "FwdPktLenMax":max(fl["fwd_lens"],default=0),
                "BwdPktLenMean":safe_mean(fl["bwd_lens"]), "BwdPktLenStd":safe_std(fl["bwd_lens"]),
                "BwdPktLenMin":min(fl["bwd_lens"],default=0), "BwdPktLenMax":max(fl["bwd_lens"],default=0),
                "FlowIATMean":flow_iat[0],"FlowIATStd":flow_iat[1],
                "FlowIATMin":flow_iat[2],"FlowIATMax":flow_iat[3],
                "FwdIATMean":fwd_iat[0],"FwdIATStd":fwd_iat[1],
                "FwdIATMin":fwd_iat[2],"FwdIATMax":fwd_iat[3],
                "BwdIATMean":bwd_iat[0],"BwdIATStd":bwd_iat[1],
                "BwdIATMin":bwd_iat[2],"BwdIATMax":bwd_iat[3],
                "TotalFwdIAT":total_fiat,"TotalBwdIAT":total_biat,
                "TotalBytes":total_bytes,"TotalPackets":total_pkts,
                "BytesPerSec":bytes_per_sec,"PktsPerSec":pkts_per_sec,
                "FwdBwdPktRatio":pkt_ratio,"FwdBwdByteRatio":byte_ratio,
                "FwdPktLenPct25":fwd_len_p[0],"FwdPktLenPct50":fwd_len_p[1],
                "FwdPktLenPct75":fwd_len_p[2],"FwdPktLenPct90":fwd_len_p[3],
                "BwdPktLenPct25":bwd_len_p[0],"BwdPktLenPct50":bwd_len_p[1],
                "BwdPktLenPct75":bwd_len_p[2],"BwdPktLenPct90":bwd_len_p[3],
                "FlowIAT25":flow_iat_p[4],"FlowIAT50":flow_iat_p[5],
                "FlowIAT75":flow_iat_p[6],"FlowIAT90":flow_iat_p[7],
                "FwdIAT25":fwd_iat_p[4],"FwdIAT50":fwd_iat_p[5],
                "FwdIAT75":fwd_iat_p[6],"FwdIAT90":fwd_iat_p[7],
                "BwdIAT25":bwd_iat_p[4],"BwdIAT50":bwd_iat_p[5],
                "BwdIAT75":bwd_iat_p[6],"BwdIAT90":bwd_iat_p[7],
                "Fwd_SYN":fwd_syn,"Fwd_FIN":fwd_fin,"Fwd_RST":fwd_rst,
                "Fwd_PSH":fwd_psh,"Fwd_ACK":fwd_ack,"Fwd_URG":fwd_urg,
                "Bwd_SYN":bwd_syn,"Bwd_FIN":bwd_fin,"Bwd_RST":bwd_rst,
                "Bwd_PSH":bwd_psh,"Bwd_ACK":bwd_ack,"Bwd_URG":bwd_urg,
                "MinActive":act_idle[0],"MeanActive":act_idle[1],
                "MaxActive":act_idle[2],"StdActive":act_idle[3],
                "MinIdle":act_idle[4],"MeanIdle":act_idle[5],
                "MaxIdle":act_idle[6],"StdIdle":act_idle[7],
                "SrcPortCat":port_cat(fl["sport"]), "DstPortCat":port_cat(fl["dport"]),
                "URLs":",".join(fl.get("urls",[]))
            }
            w.writerow(row)
    print(f"[+] Updated {filename} with {len(flows)} flows")

def periodic_dump(filename,interval=30):
    while running:
        time.sleep(interval)
        dump_flows_to_csv(filename)

def signal_handler(sig,frame):
    global running
    running=False
    print("\n[!] Stopping capture...")
    dump_flows_to_csv("final_liveflows.csv")
    sys.exit(0)

def main():
    ap=argparse.ArgumentParser(description="PCAP/Live -> CSV (CIC-like flow features + URL/SNI)")
    ap.add_argument("-i","--input",help="Input PCAP file")
    ap.add_argument("-o","--output",required=True,help="Output CSV file")
    ap.add_argument("--live",action="store_true",help="Enable live capture mode")
    ap.add_argument("--iface",default="Wi-Fi",help="Network interface for live capture")
    args=ap.parse_args()

    if args.live:
        signal.signal(signal.SIGINT,signal_handler)
        print(f"[*] Sniffing on {args.iface}... Press Ctrl+C to stop.")
        threading.Thread(target=periodic_dump,args=(args.output,),daemon=True).start()
        sniff(iface=args.iface,prn=handle_packet,store=False)
    else:
        with PcapReader(args.input) as pr:
            for pkt in pr:
                handle_packet(pkt)
        dump_flows_to_csv(args.output)

if __name__=="__main__":
    main()