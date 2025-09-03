#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "arp_queue.h" // header per la coda ARP

// Dichiarazione esterna del mutex
extern pthread_mutex_t stdout_mutex;


// struttura per passare l'interfaccia al thread (non serve più il filtro qui)
typedef struct {
    char *interface;
    // + altro ?
} interface;

// prototipo per inserire l'associazione ARP nella coda
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);

void *receiver_thread(void *iface) {
    interface *args = (interface *)iface;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    pthread_mutex_lock(&stdout_mutex);
    printf("Thread ricevitore ARP avviato per l'interfaccia: %s (solo ARP Reply)\n", args->interface);
    pthread_mutex_unlock(&stdout_mutex);

    handle = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Impossibile aprire l'interfaccia %s: %s\n", args->interface, errbuf);
        pthread_exit(NULL);
    }

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
            // verifica della lunghezza del pacchetto sia sufficiente per un ARP Reply
            if (header.caplen >= 14 + 28) { // Ethernet header + ARP header minimo
                // estrae il MAC addr nell'header Ethernet (del Sender)
                const unsigned char *mac_sender = packet + 6; // cosí ho modo di fare un allert a posteriori

                const unsigned char *arp_header = packet + 14; // Salto aal'header Ethernet

                // estrae l'indirizzo MAC del mittente (target MAC in ARP Reply) - offset 20
                const unsigned char *mac_bind = arp_header + 6; 
 
                // estrai l'indirizzo IP del mittente (target IP in ARP Reply) - offset 26
                const unsigned char *ip_bind = arp_header + 14; 

                // mi salvo i bytes dell'IP all'offset ip_bind
                //struct in_addr ip_sender_addr;
                // memcpy(&ip_sender_addr.s_addr, ip_bind, 4);

                // creo l'associazione con mac_bind e ip_bind
                arp_association_t association;
                memcpy(association.mac_addr, mac_bind, ETH_ALEN);
                memcpy(&association.ip_addr, ip_bind, 4);
                memcpy(association.mac_addr_sender, mac_sender, ETH_ALEN);
                // association.ip_addr = ip_sender_addr;
                char ip_str[4];
                char mac_str[18];
                inet_ntop(AF_INET,&association.ip_addr,ip_str,INET_ADDRSTRLEN);
                sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                    association.mac_addr[0], association.mac_addr[1], association.mac_addr[2],
                    association.mac_addr[3], association.mac_addr[4], association.mac_addr[5]);
                pthread_mutex_lock(&stdout_mutex);
                printf("[%s] Associazione memorizzata in arp_association_t:\n[-] MAC -> %s \n[-] IP -> %s\n", args->interface, mac_str, ip_str);
                pthread_mutex_unlock(&stdout_mutex);

                // metto in coda l'associazione appena costituita
                arp_association_queue_t arp_association_queue; // Dichiarazione della coda globale
                enqueue_arp_association(&arp_association_queue, association); // chiamata di enqueue in queue.c

                //printf("ARP Reply trovato: Sender MAC=%s, Sender IP=%s\n", mac_str, inet_ntoa(association.ip_addr));
            }
        }
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

// Funzione per avviare un thread ricevitore per una data interfaccia
pthread_t start_receiver_thread(const char *iface) {
    printf(" - %s interface.\n",iface);
    pthread_t receiver_tid;
    interface *args = malloc(sizeof(interface));
    if (args == NULL) {
        printf("Errore nell'allocazione di memoria per gli argomenti del thread ricevitore");
        exit(1);
    }
    args->interface = strdup(iface);
    if (pthread_create(&receiver_tid, NULL, receiver_thread, (void *)args) != 0) {
        printf("Errore nella creazione del thread ricevitore");
        free(args->interface);
        free(args);
        exit(1);
    }
    return receiver_tid;
}