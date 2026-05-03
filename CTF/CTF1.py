from scapy.all import rdpcap, TCP
import base64
import binascii

def ctf1(pcap_file):
    print(f"[*] Reading pcap file: {pcap_file}")
    
    packets = rdpcap(pcap_file)
   
    
    # empty byte string to concatenate the data from packets
    extracted_data = b""
    
    # extract payload from port 4444
    for packet in packets:
        
        if packet.haslayer(TCP) and packet.haslayer("Raw"):
            if packet[TCP].dport == 4444 or packet[TCP].sport == 4444:
                extracted_data += bytes(packet["Raw"].load)
                
                        
        # extract the base64 encoded between MSG: and :EOF
    if b"MSG:" in extracted_data and b":EOF" in extracted_data:
        base64_bytes = extracted_data.split(b"MSG:")[1].split(b":EOF")[0]
            
        base64_string = base64_bytes.decode('utf-8')
            
        print(f"[*] Extracted Base64 string: {base64_string}")
        
        # decode the base64 string to get the flag
        flag = base64.b64decode(base64_string).decode('utf-8')
        print(f"[*] Decoded Flag: {flag}")
   
    
if __name__ == "__main__":
    ctf1("traffic.pcapng")