import os
import pyshark
from scapy.all import rdpcap, wrpcap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hashlib import sha1
import binascii

# 配置参数
PCAP_FILE = "capture.pcap"  # 抓包文件路径
WIFI_PASSWORD = "88888888"  # Wi-Fi 密码
SSID = "YourSSID"           # Wi-Fi SSID
OUTPUT_DIR = "./output"     # 保存解密文件的目录

# 创建输出目录
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 1. 提取握手包并验证
def extract_handshake(pcap_file):
    print("[*] 检查 EAPOL 握手包...")
    capture = pyshark.FileCapture(pcap_file, display_filter="eapol")
    handshake_packets = [pkt for pkt in capture]
    if len(handshake_packets) < 4:
        print("[!] 未捕获完整的四次握手，无法解密流量！")
        exit(1)
    print(f"[*] 捕获到 {len(handshake_packets)} 个 EAPOL 数据包")
    return handshake_packets

# 2. 生成 PMK
def generate_pmk(password, ssid):
    print("[*] 生成 PMK...")
    kdf = PBKDF2HMAC(
        algorithm=sha1,
        length=32,
        salt=ssid.encode(),
        iterations=4096,
    )
    pmk = kdf.derive(password.encode())
    print(f"[*] PMK: {binascii.hexlify(pmk).decode()}")
    return pmk

# 3. 解密 WPA2 流量
def decrypt_wpa2(pcap_file, password, ssid):
    print("[*] 尝试解密 WPA2 流量...")
    pmk = generate_pmk(password, ssid)
    output_file = os.path.join(OUTPUT_DIR, "decrypted.pcap")
    os.system(f"airdecap-ng -e {ssid} -p {password} -k {pmk.hex()} {pcap_file}")
    print(f"[*] 解密完成，解密文件保存为: {output_file}")
    return output_file

# 4. 提取 HTTP 数据
def extract_http_data(decrypted_pcap):
    print("[*] 提取 HTTP 流量...")
    capture = pyshark.FileCapture(decrypted_pcap, display_filter="http")
    for packet in capture:
        try:
            if "image" in packet.http.content_type:
                print(f"[+] 发现图片: {packet.http.content_type}")
                file_data = packet.http.file_data
                file_name = os.path.join(OUTPUT_DIR, f"{packet.number}.jpg")
                with open(file_name, "wb") as f:
                    f.write(binascii.unhexlify(file_data))
                print(f"[+] 图片已保存到: {file_name}")
        except AttributeError:
            continue
    print("[*] HTTP 数据提取完成")

# 主流程
if __name__ == "__main__":
    print("[*] 开始处理抓包文件...")
    handshake_packets = extract_handshake(PCAP_FILE)
    decrypted_pcap = decrypt_wpa2(PCAP_FILE, WIFI_PASSWORD, SSID)
    extract_http_data(decrypted_pcap)
    print("[*] 全部处理完成！")
