#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "arp_queue.h" // Includi l'header per la coda ARP

// Struttura per passare l'interfaccia al thread (non serve più il filtro qui)
typedef struct {
    char *interface;
    // Altri parametri se necessario
} receiver_args_t;

// Prototipo per inserire l'associazione ARP nella coda
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);

void *receiver_thread(void *arg) {
    receiver_args_t *args = (receiver_args_t *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    printf("Thread ricevitore ARP avviato per l'interfaccia: %s (solo ARP Reply)\n", args->interface);

    handle = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Impossibile aprire l'interfaccia %s: %s\n", args->interface, errbuf);
        pthread_exit(NULL);
    }

    // Compila e imposta il filtro per ARP Reply
    const char *arp_filter = "arp and arp[7] == 2";
    if (pcap_compile(handle, &fp, arp_filter, 1, net) == -1) {
        fprintf(stderr, "Errore nella compilazione del filtro ARP: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Errore nell'impostazione del filtro ARP: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        pthread_exit(NULL);
    }
    pcap_freecode(&fp);

    struct pcap_pkthdr header;
    const unsigned char *packet;

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet) {
            // Verifica che la lunghezza del pacchetto sia sufficiente per un ARP Reply
            if (header.caplen >= 14 + 28) { // Ethernet header + ARP header minimo
                const unsigned char *arp_header = packet + 14; // Salta l'header Ethernet

                // Estrai l'indirizzo MAC del mittente (Target MAC in Reply) - offset 22
                const unsigned char *mac_sender = arp_header + 6; // Offset del Sender MAC
                // Estrai l'indirizzo IP del mittente (Target IP in Reply) - offset 28
                const unsigned char *ip_sender_bytes = arp_header + 14; // Offset del Sender IP
                struct in_addr ip_sender_addr;
                memcpy(&ip_sender_addr.s_addr, ip_sender_bytes, 4);

                arp_association_t association;
                memcpy(association.mac_addr, mac_sender, ETH_ALEN);
                association.ip_addr = ip_sender_addr;

                // Inserisci l'associazione nella coda dedicata
                extern arp_association_queue_t arp_association_queue; // Dichiarazione della coda globale
                enqueue_arp_association(&arp_association_queue, association);

                // Puoi stampare l'associazione qui per verifica
                char mac_str[18];
                sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                        association.mac_addr[0], association.mac_addr[1], association.mac_addr[2],
                        association.mac_addr[3], association.mac_addr[4], association.mac_addr[5]);
                printf("ARP Reply trovato: Sender MAC=%s, Sender IP=%s\n", mac_str, inet_ntoa(association.ip_addr));
            }
        }
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

// Funzione per avviare un thread ricevitore per una data interfaccia
pthread_t start_receiver_thread(const char *interface_name) {
    pthread_t receiver_tid;
    receiver_args_t *args = malloc(sizeof(receiver_args_t));
    if (args == NULL) {
        perror("Errore nell'allocazione di memoria per gli argomenti del thread ricevitore");
        exit(EXIT_FAILURE);
    }
    args->interface = strdup(interface_name);
    if (pthread_create(&receiver_tid, NULL, receiver_thread, (void *)args) != 0) {
        perror("Errore nella creazione del thread ricevitore");
        free(args->interface);
        free(args);
        exit(EXIT_FAILURE);
    }
    return receiver_tid;
}