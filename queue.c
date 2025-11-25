#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h> 
#include "arp_queue.h"

void arp_queue_init(arp_association_queue_t *queue, pthread_mutex_t *stdout_mutex) {
    queue->stdout_mutex = stdout_mutex;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    queue->peak_count = 0;
}

void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == ARP_QUEUE_SIZE) { 
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    arp_association_t *new_association = malloc(sizeof(arp_association_t));
    if (new_association == NULL) {
        perror("Errore nell'allocazione di memoria per l'associazione ARP");
        pthread_mutex_unlock(&queue->mutex);
        return;
    }

    memcpy(new_association, &association, sizeof(arp_association_t));

    queue->buffer[queue->tail] = new_association;
    queue->tail = (queue->tail + 1) % ARP_QUEUE_SIZE; 
    queue->count++;

    // --- calcolo del max count per la coda ---
    if (queue->count > queue->peak_count) {
        queue->peak_count = queue->count;
    }
    // ------------------------------

    pthread_cond_signal(&queue->not_empty);

    // print ogni volta della coda, opzionale ne stampa solo 1
    // da quanto è veloce il thread analizzatore
    // list_arp_association(queue);

    pthread_mutex_unlock(&queue->mutex);
}

arp_association_t *dequeue_arp_association(arp_association_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    arp_association_t *association = queue->buffer[queue->head];
    queue->head = (queue->head + 1) % ARP_QUEUE_SIZE; 
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return association;
}

void free_arp_association(arp_association_t *association) {
    if (association) {
        free(association);
    }
}

void list_arp_association(arp_association_queue_t *queue){
    // Utilizziamo un buffer locale per la conversione dell'IP in stringa
    char ip_str[INET_ADDRSTRLEN];
    char mac_str[18], mac_sender_str[18];
    int current_index;
    int items_listed = 0;

    // pthread_mutex_lock(&queue->mutex); //mutex accesso coda

    // aspetto ci sia qualcosa nella coda 
    // (in teoria se viene chiamato questo metodo dovrebbe esserci qualcosa ma controllo lo stesso)
    // while (queue->count == 0) {
    //     pthread_cond_wait(&queue->not_empty, &queue->mutex);
    // }

    pthread_mutex_lock(queue->stdout_mutex);
    printf("\n=======================================================\n");
    printf("STATO ATTUALE DELLA CODA ARP (Totale: %d associazioni)\n", queue->count);
    printf("=======================================================\n");
    pthread_mutex_unlock(queue->stdout_mutex);

    // inizializzo l'index corrente alla testa e parto da essa per stampare le associazioni
    current_index = queue->head;

    // Si itera per 'count' volte per listare tutti gli elementi presenti
    for (int i = 0; i < queue->count; i++) {
        arp_association_t *association = queue->buffer[current_index];

        // L'oggetto 'association' è il puntatore all'elemento allocato nella coda.
        // Convertiamo i dati in stringhe per la stampa.
        
        // conversione MAC address
        mac_to_str(association->mac_addr,mac_str);
        
        // Conversione Sender MAC address (assumendo sia incluso nella struttura)
        // 
        mac_to_str(association->mac_addr_sender,mac_sender_str);
        // Conversione IP address
        // Usiamo inet_ntop() per la conversione sicura da binario a stringa
        inet_ntop(AF_INET, &association->ip_addr, ip_str, INET_ADDRSTRLEN);

        // Stampa dell'associazione
        pthread_mutex_lock(queue->stdout_mutex);
        printf("[%d] MAC: %s | IP: %s | Sender MAC: %s\n", i + 1, mac_str, ip_str, mac_sender_str);
        pthread_mutex_unlock(queue->stdout_mutex);


        items_listed++;

        // Passaggio all'indice successivo nel buffer circolare
        current_index = (current_index + 1) % ARP_QUEUE_SIZE;
    }

    pthread_mutex_lock(queue->stdout_mutex);
    printf("=======================================================\n\n");
    pthread_mutex_unlock(queue->stdout_mutex);


    // Sblocco la coda
    // pthread_mutex_unlock(&queue->mutex);

}

char *mac_to_str(const unsigned char *mac_addr, char *mac_str) {
    if (mac_addr == NULL || mac_str == NULL) {
        return NULL;
    }

    // Formatta i 6 byte dell'indirizzo MAC nella stringa di output.
    // %02x garantisce due cifre esadecimali con padding zero.
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5]);

    return mac_str;
}
