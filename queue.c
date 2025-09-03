#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "arp_queue.h"

void arp_queue_init(arp_association_queue_t *queue) {
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
}

void enqueue_arp_association(arp_association_queue_t *queue, arp_association_t association) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == ARP_QUEUE_SIZE) { // Usa la dimensione definita nell'header
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
    queue->tail = (queue->tail + 1) % ARP_QUEUE_SIZE; // Usa la dimensione definita nell'header
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
}

arp_association_t *dequeue_arp_association(arp_association_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    arp_association_t *association = queue->buffer[queue->head];
    queue->head = (queue->head + 1) % ARP_QUEUE_SIZE; // Usa la dimensione definita nell'header
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