from scapy.all import rdpcap, TCP
import base64
import binascii

def ctf1(pcap_file):
    print(f"[*] Reading pcap file: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] File not found.")
        return
    
    # empty byte string to concatenate the data from packets
    raw_data = b""
    
    # extract payload from port 4444
    for packet in packets:
        if TCP in packet and (packet[TCP].sport == 4444 or packet[TCP].dport == 4444):
            if packet.haslayer("Raw"):
                raw_data += bytes(packet["Raw"].load)
                
    if not raw_data:
        print("[-] No data found on port 4444.")
        return
    
    # clean the extracted hex data and decode the Hex to ASCII
    try:
       
        ascii_data = raw_data.decode('utf-8', errors='ignore')
        
        ascii_data = ascii_data.replace("\n", "").replace("\r", "")
        
        print(f"[*] Extracted ASCII data: {ascii_data}")
        
        # extract the base64 encoded between MSG: and :EOF
        if "MSG:" in ascii_data and ":EOF" in ascii_data:
            b64_string = ascii_data.split("MSG:")[1].split(":EOF")[0]
        
            
        print(f"[*] Extracted Base64 string: {b64_string}")
        
        # decode the base64 string to get the flag
        flag = base64.b64decode(b64_string).decode('utf-8')
        print(f"[*] Decoded Flag: {flag}")
        
    except Exception as e:
        print(f"[!] Error decoding data: {e}")
    
if __name__ == "__main__":
    ctf1("traffic.pcapng")