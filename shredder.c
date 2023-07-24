#include "shredder.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <gtk/gtk.h>

#define BUFFER_SIZE 1024

static void generate_random_iv(unsigned char *iv, size_t length) {
    randombytes_buf(iv, length);
}


void overwrite_with_null_bytes(FILE* fp, long file_size, GtkProgressBar* progress_bar) {
    char null_byte = 0;

    for (long i = 0; i < file_size; i++) {
        fwrite(&null_byte, sizeof(char), 1, fp);

        // Update the progress bar
        double progress = (double)i / (double)file_size;
        gtk_progress_bar_set_fraction(progress_bar, progress);
        while (gtk_events_pending())
            gtk_main_iteration();
    }
}

void overwrite_with_polymorphic_12_pass(FILE* fp, long file_size, GtkProgressBar* progress_bar) {

    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    unsigned char iv[crypto_stream_chacha20_NONCEBYTES];

    randombytes_buf(key, sizeof key);
    
    fseek(fp, 0, SEEK_SET);
    long num_iterations = file_size / BUFFER_SIZE;
    long remainder = file_size % BUFFER_SIZE;

    for (int pass = 0; pass < 12; pass++) {

        generate_random_iv(iv, sizeof iv);

        fseek(fp, 0, SEEK_SET);

        for (long i = 0; i < num_iterations; i++) {

            unsigned char buffer[BUFFER_SIZE];
            fread(buffer, sizeof(char), BUFFER_SIZE, fp);

            unsigned char ciphertext[BUFFER_SIZE];

            crypto_stream_chacha20(ciphertext, sizeof ciphertext, iv, key);

            fseek(fp, -BUFFER_SIZE, SEEK_CUR);
            fwrite(ciphertext, sizeof(char), BUFFER_SIZE, fp);

            double progress = (double)(i * BUFFER_SIZE) / (double)file_size;
            gtk_progress_bar_set_fraction(progress_bar, progress);
            while (gdk_events_pending())
                gdk_display_flush(gdk_display_get_default());
        }

        // Remainder handling
        if (remainder > 0) {

            unsigned char remainder_buffer[remainder];
            fread(remainder_buffer, sizeof(char), remainder, fp);

            unsigned char remainder_ciphertext[remainder];

            crypto_stream_chacha20(remainder_ciphertext, remainder, iv, key);

            fseek(fp, -remainder, SEEK_CUR);
            fwrite(remainder_ciphertext, sizeof(char), remainder, fp);

            double progress = (double)(file_size) / (double)file_size;
            gtk_progress_bar_set_fraction(progress_bar, progress);
            while (gdk_events_pending())
                gdk_display_flush(gdk_display_get_default());
        }
    }
}

void overwrite_with_random_data(FILE* fp, long file_size, GtkProgressBar* progress_bar) {
    char buffer[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = rand() % 256; // Generate random data (0-255)
    }

    fseek(fp, 0, SEEK_SET);
    long num_iterations = file_size / BUFFER_SIZE;
    long remainder = file_size % BUFFER_SIZE;

    for (long i = 0; i < num_iterations; i++) {
        fwrite(buffer, sizeof(char), BUFFER_SIZE, fp);

        // Update the progress bar
        double progress = (double)(i * BUFFER_SIZE) / (double)file_size;
        gtk_progress_bar_set_fraction(progress_bar, progress);
        while (gtk_events_pending())
            gtk_main_iteration();
    }

    if (remainder > 0) {
        fwrite(buffer, sizeof(char), remainder, fp);

        // Update the progress bar
        double progress = (double)file_size / (double)(file_size + remainder);
        gtk_progress_bar_set_fraction(progress_bar, progress);
        while (gtk_events_pending())
            gtk_main_iteration();
    }
}

void overwrite_with_gutmann(FILE* fp, long file_size, GtkProgressBar* progress_bar) {
    // Gutmann 35-pass overwrite patterns
    unsigned char patterns[35][BUFFER_SIZE];
    for (int i = 0; i < 35; i++) {
        for (int j = 0; j < BUFFER_SIZE; j++) {
            patterns[i][j] = i;
        }
    }

    fseek(fp, 0, SEEK_SET);
    long num_iterations = file_size / (35 * BUFFER_SIZE);
    long remainder = file_size % (35 * BUFFER_SIZE);

    for (long i = 0; i < num_iterations; i++) {
        for (int j = 0; j < 35; j++) {
            fwrite(patterns[j], sizeof(char), BUFFER_SIZE, fp);
        }

        // Update the progress bar
        double progress = (double)(i * 35 * BUFFER_SIZE) / (double)file_size;
        gtk_progress_bar_set_fraction(progress_bar, progress);
        while (gtk_events_pending())
            gtk_main_iteration();
    }

    if (remainder > 0) {
        for (int j = 0; j < 35; j++) {
            fwrite(patterns[j], sizeof(char), remainder, fp);
        }

        // Update the progress bar
        double progress = (double)file_size / (double)(file_size + remainder);
        gtk_progress_bar_set_fraction(progress_bar, progress);
        while (gtk_events_pending())
            gtk_main_iteration();
    }
}

void* shredder_thread(void* params) {

    ShredParams* shred_params = (ShredParams*)params;
    FILE* fp = shred_params->fp;
    long file_size = shred_params->file_size;
    GtkProgressBar* progress_bar = shred_params->progress_bar;

    overwrite_with_null_bytes(fp, file_size, progress_bar);
    overwrite_with_random_data(fp, file_size, progress_bar);
    overwrite_with_gutmann(fp, file_size, progress_bar);
    overwrite_with_polymorphic_12_pass(fp, file_size, progress_bar);

    fclose(fp);
    free(shred_params);

    return NULL;
}

void shred_file(GtkWidget *widget, gpointer data) {

    const gchar *file_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(data));
    if (!file_path) {

        g_print("Error: Invalid file path.\n");
        return;
    }

    FILE* fp = fopen(file_path, "r+b");

    if (!fp) {

        g_print("Error: Unable to open the file.\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    GtkWidget *combo = GTK_WIDGET(g_object_get_data(G_OBJECT(data), "combo"));
    const gchar *selected_algorithm = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));

    // Create the progress bar
    GtkWidget *progress_bar = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(progress_bar), TRUE);

    // Create the label to display the number of passes and the file name
    GtkWidget *label = gtk_label_new("");
    gchar *label_text = g_strdup_printf("Passes Left: 3\nShredding: %s", file_path);
    gtk_label_set_text(GTK_LABEL(label), label_text);
    g_free(label_text);

    // Create a vertical box to hold the label, progress bar, and other components
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), progress_bar, FALSE, FALSE, 0);

    // Add the vbox to the dialog
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Shredding Progress",
        GTK_WINDOW(gtk_widget_get_toplevel(widget)),
        GTK_DIALOG_DESTROY_WITH_PARENT,
        "Cancel", GTK_RESPONSE_CANCEL,
        NULL);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    gtk_widget_show_all(dialog);

    // Create shred parameters to pass to the shredder threads
    ShredParams* shred_params = (ShredParams*)malloc(sizeof(ShredParams));
    shred_params->fp = fp;
    shred_params->file_size = file_size;
    shred_params->progress_bar = GTK_PROGRESS_BAR(progress_bar);

    // Create 3 shredder threads, one for each pass
    pthread_t threads[3];

    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, shredder_thread, shred_params);
    }

    // Wait for all threads to finish
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    if (remove(file_path) == 0) {
        g_print("%s has been securely shredded using %s algorithm.\n", file_path, selected_algorithm);
    } else {
        g_print("Error: Unable to shred the file.\n");
    }

    gtk_widget_destroy(dialog); // Close the progress dialog
}
