from scapy.all import ARP, Ether, srp, sniff
from flask import Flask, render_template, jsonify
import os
import time
import requests
import logging
import threading

app = Flask(__name__)

# Logging
login_attempts = {}
ddos_attempts = {}
hacker_attempts = {}

# Logging aktivitas mencurigakan
logging.basicConfig(filename='network_security.log', level=logging.INFO)

# Fungsi untuk memindai perangkat terhubung
def scan_network(ip_range="YOUR_ROUTER_IP_ADDRESS/24"):
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            mac = received.hwsrc
            ip = received.psrc
            vendor = get_vendor(mac)
            devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
        return devices
    except Exception as e:
        logging.error(f"Error saat scan jaringan: {e}")
        return []

# Fungsi untuk mendapatkan vendor perangkat dari MAC Address
def get_vendor(mac):
    try:
        response = requests.get(f'https://api.macvendors.com/{mac}')
        return response.text if response.status_code == 200 else "Unknown"
    except Exception as e:
        logging.error(f"Error saat mendapatkan vendor dari MAC: {e}")
        return "Unknown"

# Fungsi untuk memutus perangkat
def disconnect_device(mac_address):
    try:
        os.system(f"arp -d {mac_address}")
        logging.info(f"Perangkat dengan MAC {mac_address} diputus.")
    except Exception as e:
        logging.error(f"Gagal memutus perangkat {mac_address}: {e}")

# Proteksi DDoS
def detect_ddos(ip):
    current_time = time.time()
    if ip not in ddos_attempts:
        ddos_attempts[ip] = []

    ddos_attempts[ip].append(current_time)
    ddos_attempts[ip] = [t for t in ddos_attempts[ip] if current_time - t < 10]  # 10 detik

    if len(ddos_attempts[ip]) > 100:  # Ambang batas
        logging.warning(f"Potensi serangan DDoS dari {ip}. Memblokir IP...")
        block_ip(ip)
        return True
    return False

# Proteksi Spam Login
def detect_spam_login(ip):
    current_time = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []

    login_attempts[ip].append(current_time)
    login_attempts[ip] = [t for t in login_attempts[ip] if current_time - t < 300]  # 5 menit

    if len(login_attempts[ip]) > 50:
        logging.warning(f"Deteksi spam login dari {ip}. Memblokir IP...")
        block_ip(ip)
        return True
    return False

# Deteksi aktivitas hacker dan brute force
def detect_hacker_traffic(packet):
    src_ip = packet[0][1].src
    dst_port = packet[0][2].dport if packet.haslayer('TCP') else None

    logging.info(f"Paket dari {src_ip} ke port {dst_port}")

    # Misal, brute force melalui SSH (port 22) atau Telnet (port 23)
    if dst_port in [22, 23]:
        logging.warning(f"Potensi serangan brute force dari {src_ip}. Memblokir IP...")
        block_ip(src_ip)

# Fungsi untuk memblokir IP menggunakan iptables
def block_ip(ip_address):
    try:
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        logging.info(f"IP {ip_address} diblokir karena aktivitas mencurigakan.")
    except Exception as e:
        logging.error(f"Gagal memblokir IP {ip_address}: {e}")

# Fungsi untuk memutus semua perangkat dari jaringan
def disconnect_all_devices():
    try:
        devices = scan_network()
        for device in devices:
            disconnect_device(device['mac'])
        logging.info(f"Semua perangkat diputus dari jaringan.")
    except Exception as e:
        logging.error(f"Error saat memutus semua perangkat: {e}")

# Deteksi serangan besar (DDoS atau hijacking)
def detect_large_attack():
    if len(ddos_attempts) > 10:
        logging.warning("Deteksi serangan besar. Memutus semua perangkat...")
        disconnect_all_devices()

# Monitoring lalu lintas jaringan untuk mendeteksi hacker
def monitor_traffic():
    sniff(prn=detect_hacker_traffic, store=0)

# Proteksi otomatis saat ada aktivitas mencurigakan
def automate_protection():
    devices = scan_network()
    for device in devices:
        ip = device['ip']
        if detect_ddos(ip):
            logging.info(f"DDoS Protection aktif untuk {ip}")
        if detect_spam_login(ip):
            logging.info(f"Proteksi spam login aktif untuk {ip}")
    
    detect_large_attack()

@app.route('/')
def index():
    devices = scan_network()
    return render_template('index.html', devices=devices)

@app.route('/disconnect/<mac>')
def disconnect(mac):
    disconnect_device(mac)
    return jsonify({'status': 'disconnected', 'mac': mac})

@app.route('/protect_ddos')
def protect_ddos():
    automate_protection()
    return jsonify({'status': 'Proteksi DDoS dan Spam aktif'})

@app.route('/start_hacker_protection')
def start_hacker_protection():
    threading.Thread(target=monitor_traffic).start()
    return jsonify({'status': 'Deteksi hacker aktif'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3090, debug=True)
