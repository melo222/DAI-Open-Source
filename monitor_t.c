#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include "monitor_t.h"

void *monitor_thread_func(void *args) {
    monitor_args_t *m_args = (monitor_args_t *)args;
    
    unsigned long last_processed = 0;
    double last_latency_sum = 0.0;
    
    double time_elapsed = 0.0;
    int loop_counter = 0; 

    // Header CSV modificato: PeakQueue invece di QueueLoad generico
    if (m_args->csv_file) {
        fprintf(m_args->csv_file, "Time(s),Count,PeakQueue(%%),AvgLatency(us),AttacksTotal\n");
        fflush(m_args->csv_file);
    }

    while(1) {
        usleep(100000); // 0.1s
        time_elapsed += 0.1;
        loop_counter++;

        // Lettura Metriche Globali
        pthread_mutex_lock(&m_args->metrics->mutex);
        unsigned long current_processed = m_args->metrics->total_processed;
        unsigned long current_attacks = m_args->metrics->attacks_detected;
        double current_latency_sum = m_args->metrics->total_latency_accum;
        pthread_mutex_unlock(&m_args->metrics->mutex);

        // Calcoli Delta
        unsigned long delta_processed = current_processed - last_processed;
        double delta_latency_sum = current_latency_sum - last_latency_sum;
        
        double interval_avg_latency = 0.0;
        if (delta_processed > 0) {
             interval_avg_latency = delta_latency_sum / (double)delta_processed; 
        }

        // --- LETTURA E RESET DEL PICCO CODA ---
        pthread_mutex_lock(&m_args->queue->mutex);
        int peak_q = m_args->queue->peak_count; // leggiamo il max raggiunto
        m_args->queue->peak_count = 0;          // reset fino al prossimo intervallo
        pthread_mutex_unlock(&m_args->queue->mutex);
        
        // Calcolo percentuale sul PICCO
        double peak_queue_load = ((double)peak_q / ARP_QUEUE_SIZE) * 100.0;
        // --------------------------------------

        // Scrittura CSV
        if (m_args->csv_file) {
            fprintf(m_args->csv_file, "%.1f,%lu,%.2f,%.2f,%lu\n", 
                    time_elapsed, delta_processed, peak_queue_load, interval_avg_latency, current_attacks);
            fflush(m_args->csv_file);
        }

        // Stampa a Video (ogni 1s)
        if (loop_counter % 10 == 0) {
            pthread_mutex_lock(m_args->stdout_mutex);
            printf("[MONITOR] Time: %.1fs | Count: %lu | Peak Queue: %.1f%% | Latency: %.2f us | Attacks: %lu\n", 
                   time_elapsed, delta_processed, peak_queue_load, interval_avg_latency, current_attacks);
            pthread_mutex_unlock(m_args->stdout_mutex);
        }

        last_processed = current_processed;
        last_latency_sum = current_latency_sum;
    }
    return NULL;
}

// ... start_monitor_thread rimane uguale ...
pthread_t start_monitor_thread(monitor_args_t *args) {
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread_func, (void*)args) != 0) {
        perror("Errore creazione thread monitor");
        exit(1);
    }
    return monitor_tid;
}