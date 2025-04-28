#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include "frame_queue.h"

// Struttura per passare l'interfaccia al thread
typedef struct {
    char *interface;
    // Altri parametri se necessario
} receiver_args_t;

// Prototipo della funzione per inserire la trama nella coda (da definire in seguito)
void enqueue_frame(const unsigned char *frame, int len);

void *receiver_thread(void *arg) {
    receiver_args_t *args = (receiver_args_t *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    printf("Thread ricevitore avviato per l'interfaccia: %s\n", args->interface);

    // Apri l'interfaccia per la cattura
    handle = pcap_open_live(args->interface, BUFSIZ, 1, 1000, errbuf); // snaplen, promisc, timeout_ms
    if (handle == NULL) {
        fprintf(stderr, "Impossibile aprire l'interfaccia %s: %s\n", args->interface, errbuf);
        pthread_exit(NULL);
    }

    struct pcap_pkthdr header;
    const unsigned char *packet;

    // Loop di cattura delle trame
    while (1) {
        packet = pcap_next(handle, &header);
        if (packet) {
            // Inserisci la trama nella coda condivisa
            enqueue_frame(packet, header.caplen);
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
    args->interface = strdup(interface_name); // Assicurati di liberare questa memoria quando il thread termina (o nel main)
    if (pthread_create(&receiver_tid, NULL, receiver_thread, (void *)args) != 0) {
        perror("Errore nella creazione del thread ricevitore");
        free(args->interface);
        free(args);
        exit(EXIT_FAILURE);
    }
    return receiver_tid;
}