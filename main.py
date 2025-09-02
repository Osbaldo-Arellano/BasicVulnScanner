import pyshark

def scan_for_protocols(pcap_file):
    """
    Scans for FTP, Telnet, and SSL in the provided pcap file.
    """
    protocols = {'ftp': 0, 'telnet': 0, 'ssl': 0}
    
    try:
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture:
            if 'FTP' in packet:
                protocols['ftp'] += 1
            if 'TELNET' in packet:
                protocols['telnet'] += 1
            if 'SSL' in packet or 'TLS' in packet:
                protocols['ssl'] += 1
    except Exception as e:
        print(f"Error processing file {pcap_file}: {e}")
    finally:
        capture.close()
    
    return protocols

def check_ports(pcap_file):
    """
    Checks if some ports are being used by the incorrect protocols.
    """
    mismatches = []
    try:
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture:
            if 'TCP' in packet:  # Check if the packet has a TCP layer
                source = int(packet.tcp.srcport)
                dst = int(packet.tcp.dstport)
                
                # port 22 for non-SSH traffic
                if source == 22 or dst == 22:
                    if 'SSH' not in packet:
                        mismatches.append(f"Port 22 not being used by SSH: {packet.number}")
                
                # port 80 for non-HTTP traffic
                if source == 80 or dst == 80:
                    if 'HTTP' not in packet:
                        mismatches.append(f"Port 80 used by non-HTTP traffic: {packet.number}")
                
                # port 53 for non-DNS traffic
                if source == 53 or dst == 53:
                    if 'DNS' not in packet:
                        mismatches.append(f"Port 53 used by non-DNS traffic: {packet.number}")
    except Exception as e:
        print(f"Error from check_ports(): {e}")
    finally:
        capture.close()
    
    return mismatches

def check_tls_version(pcap_file):
    """
    Checks if the TLS version is out of date. Checks for vulnerable versions of TLS (1.0 and 1.1)
    """
    out_of_date_packets = []
    try:
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture:
            if 'TLS' in packet:  # Check if the packet has a TLS layer
                version = packet.tls.record_version
                if version == '0x0301' or '0x0302':  
                    out_of_date_packets.append(f"{version} found in packet {packet.number}")
    except Exception as e:
        print(f"Error in check_tls_version(): {e}")
    finally:
        capture.close()
    
    return out_of_date_packets

def unencrypted_check(pcap_file):
    """
    Checks for unencrypted credentials in TELNET and FTP traffic.
    """
    packets = []
    try:
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture:
            payload = str(packet) # Cast payload to string 
            # Check for unencrypted common credential keywords
            keywords = ['user', 'pass', 'login']
            for keyword in keywords:
                if keyword in payload.lower():
                    print(f"Keyword found: {keyword}")
                    packets.append({'info': payload})
                    print(packet)
                    break
    except Exception as e:
        print(f"Error in unencrypted_check(): {e}")
    finally:
        capture.close()
    
    return packets

if __name__ == "__main__":
    pcap_files = ['FTPv6-1.cap', 'telnet.cap', 'mysql-ssl.pcapng']
    
    for pcap_file_path in pcap_files:
        # Scan for protocols
        results = scan_for_protocols(pcap_file_path)
        print(f"\nInsecure protocols found in capture {pcap_file_path}:")
        for protocol, count in results.items(): 
            print(f"Found {count} instances of insecure protocol: {protocol.upper()}")
        
        # Check port issues
        port_issues = check_ports(pcap_file_path)
        print("Port matching issues:")
        if port_issues:
            for issue in port_issues:
                print(issue)
        else:
            print("No port mismatch found.")

        # Check outdated TLS versions
        tls_issues = check_tls_version(pcap_file_path)
        print("Out of date TLS versions:")
        if tls_issues:
            for issue in tls_issues:
                print(issue)
        else:
            print("No TLS version issues found.")

        # Check for unencrypted traffic
        unencrypted_traffic = unencrypted_check(pcap_file_path)

