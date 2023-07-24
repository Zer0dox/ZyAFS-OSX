#ifndef SHREDDER_H
#define SHREDDER_H

#include <gtk/gtk.h>

typedef struct {
    FILE* fp;
    long file_size;
    GtkProgressBar* progress_bar;
} ShredParams;

typedef enum {
    SHRED_ALGORITHM_NULL_BYTES,
    SHRED_ALGORITHM_RANDOM_DATA,
    SHRED_ALGORITHM_DOD,
    SHRED_ALGORITHM_GUTMANN,
    SHRED_ALGORITHM_POLYMORPHIC_12_PASS  // New algorithm added
} ShredAlgorithm;

void overwrite_with_null_bytes(FILE* fp, long file_size, GtkProgressBar* progress_bar);
void overwrite_with_random_data(FILE* fp, long file_size, GtkProgressBar* progress_bar);
void overwrite_with_gutmann(FILE* fp, long file_size, GtkProgressBar* progress_bar);
void overwrite_with_polymorphic_12_pass(FILE* fp, long file_size, GtkProgressBar* progress_bar);  // New function
void* shredder_thread(void* params);
void shred_file(GtkWidget *widget, gpointer data);

#endif /* SHREDDER_H */
