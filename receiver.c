#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "arp_queue.h" // header per la coda ARP
#include "receiver_t.h"
// Dichiarazione esterna del mutex
// extern pthread_mutex_t stdout_mutex;


// struttura per passare l'interfaccia al thread (non serve più il filtro qui)
// typedef struct {
//     char *interface;
//     // + altro ?
// } interface;

// prototipo per inserire l'associazione ARP nella coda
void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association);

void *receiver_thread(void *args) {
    receiver_t_args* t_args = (receiver_t_args *) args;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    // bpf_u_int32 mask;

    pthread_mutex_lock(t_args->stdout_mutex);
    printf("\t - Thread Receiver ARP avviato per l'interfaccia: %s\n", t_args->interface);
    pthread_mutex_unlock(t_args->stdout_mutex);

    handle = pcap_open_live(t_args->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        pthread_mutex_lock(t_args->stdout_mutex);
        fprintf(stderr, "Impossibile aprire l'interfaccia %s: %s\n", t_args->interface, errbuf);
        pthread_mutex_unlock(t_args->stdout_mutex);
        pthread_exit(NULL);
    }

    const char *arp_filter = "arp and arp[7] == 2";
    if (pcap_compile(handle, &fp, arp_filter, 1, net) == -1) {    
        pthread_mutex_lock(t_args->stdout_mutex);
        fprintf(stderr, "Errore nella compilazione del filtro ARP: %s\n", pcap_geterr(handle));
        pthread_mutex_unlock(t_args->stdout_mutex);
        pcap_close(handle);
        pthread_exit(NULL);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pthread_mutex_lock(t_args->stdout_mutex);
        fprintf(stderr, "Errore nell'impostazione del filtro ARP: %s\n", pcap_geterr(handle));
        pthread_mutex_unlock(t_args->stdout_mutex);
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
                const unsigned char *mac_bind = arp_header + 8;  //CORRETTO DA 6 A 8
 
                // estrai l'indirizzo IP del mittente (target IP in ARP Reply) - offset 26
                const unsigned char *ip_bind = arp_header + 14; 

                // creo l'associazione con mac_bind, ip_bind e il mac_sender
                arp_association_t association;
                memcpy(association.mac_addr, mac_bind, ETH_ALEN);
                memcpy(&association.ip_addr, ip_bind, 4);
                memcpy(association.mac_addr_sender, mac_sender, ETH_ALEN);
                
                char ip_str[INET_ADDRSTRLEN];
                char mac_str[18],mac_sender_str[18];
                inet_ntop(AF_INET,&association.ip_addr,ip_str,INET_ADDRSTRLEN);
                // conversione MAC address
                mac_to_str(association.mac_addr,mac_str);
                mac_to_str(association.mac_addr_sender,mac_sender_str);
                // stampa
                pthread_mutex_lock(t_args->stdout_mutex);
                printf("[%d|%s] Associazione memorizzata in arp_association_t:\n   [-] MAC -> \t\t%s \n   [-] IP -> \t\t%s\n   [-] SENDER MAC ->\t%s\n",
                    t_args->num, t_args->interface, mac_str, ip_str, mac_sender_str);
                pthread_mutex_unlock(t_args->stdout_mutex);
                // metto in coda l'associazione appena costituita
                arp_association_queue_t *arp_queue = t_args->queue; // Dichiarazione della coda globale
                enqueue_arp_association(arp_queue, association); // chiamata di enqueue in queue.c
                // list_arp_association(arp_queue,t_args->stdout_mutex);
                //printf("ARP Reply trovato: Sender MAC=%s, Sender IP=%s\n", mac_str, inet_ntoa(association.ip_addr));
            }
        }
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

// Funzione per avviare un thread ricevitore per una data interfaccia
pthread_t start_receiver_thread(receiver_t_args* args, pthread_mutex_t* mutex) {
    args->stdout_mutex = mutex;
    pthread_t receiver_tid;
    if (pthread_create(&receiver_tid, NULL,(void *) receiver_thread, args) != 0) {
        printf("Errore nella creazione del thread ricevitore");
        free(args);
        exit(1);
    }
    return receiver_tid;
}