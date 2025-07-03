import threading
import queue
from scapy.all import sniff, IP, TCP, UDP

packet_queue = queue.Queue()

def packet_callback(pkt):
    try:
        proto = "OTHER"
        src_ip = ""
        dst_ip = ""
        src_port = 0
        dst_port = 0
        raw_bytes = bytes(pkt)

        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            if TCP in pkt:
                proto = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif UDP in pkt:
                proto = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            else:
                proto = ip_layer.proto  # numeric protocol number fallback
        else:
            proto = pkt.name if hasattr(pkt, "name") else "OTHER"

        packet_queue.put((proto, src_ip, src_port, dst_ip, dst_port, raw_bytes)
        )
    except Exception as e:
        print(f"Packet parse error: {e}")

def start_sniffing():
    thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False))
    thread.daemon = True
    thread.start()
