#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Dichiarazione della coda condivisa (assicurati che sia globale o passata ai thread)
extern frame_queue_t frame_queue;

// Prototipi delle funzioni di analisi (da implementare)
void analyze_ethernet_header(const unsigned char *frame, int len);
void analyze_ip_header(const unsigned char *frame, int len);
// ... altre funzioni di analisi

void *analyzer_thread(void *arg) {
    while (1) {
        frame_t *frame = dequeue_frame(&frame_queue);
        if (frame) {
            printf("Thread analizzatore %lu ha prelevato una trama di %d byte.\n", pthread_self(), frame->len);
            // Esegui le tue funzioni di analisi qui
            analyze_ethernet_header(frame->data, frame->len);
            // Se la trama contiene un header IP (dovresti verificarlo), analizzalo
            // analyze_ip_header(frame->data, frame->len);
            // ... altre analisi
            free_frame(frame); // Importante liberare la memoria della trama
        }
        // Se la coda è vuota, il thread rimarrà bloccato nella dequeue_frame fino a quando non arriva una nuova trama
    }
    pthread_exit(NULL);
}

// Funzione per creare e avviare il pool di thread analyzer
void start_analyzer_pool(int num_threads) {
    pthread_t analyzer_tids[num_threads];
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&analyzer_tids[i], NULL, analyzer_thread, NULL) != 0) {
            perror("Errore nella creazione del thread analizzatore");
            exit(EXIT_FAILURE);
        }
        printf("Thread analizzatore %lu creato.\n", analyzer_tids[i]);
    }
}