#include <stdio.h>

#include <pthread.h>

volatile char* get_sdp_idx_file_r = NULL;
volatile char sdp_file_prefix[64] = {0};
volatile char sdp_file_prefix_offer[64] = {0};
pthread_mutex_t get_sdp_idx_file_mutex;
