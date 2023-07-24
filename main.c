/*

PROGRAM NAME:   ZyAFS-OSX 
FUNCTIONALITY:  Advanced Forensic Shredder for MacOS
Version:        1.0.0

Key Features:   

    - 3 pass shredding algorithm
    - Guttman algorithm
    - DoD 5220.22-M algorithm 
    - Optimized for SSD

*/

#include <gtk/gtk.h>
#include "shredder.h"

static GtkWidget *algorithm_dialog; // Global variable for the algorithm selection dialog

// Custom dialog for algorithm selection
static void create_algorithm_dialog(GtkWidget *file_chooser) {
    GtkWidget *combo, *button, *grid, *content_area;

    // Create the dialog
    algorithm_dialog = gtk_dialog_new_with_buttons("Select Algorithm",
                                         GTK_WINDOW(gtk_widget_get_toplevel(file_chooser)),
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         "Cancel", GTK_RESPONSE_CANCEL,
                                         "Shred", GTK_RESPONSE_ACCEPT,
                                         NULL);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(algorithm_dialog));

    // Create the algorithm selection dropdown
    combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "Null Bytes");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "Random Data");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "DoD 5220.22-M");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "Gutmann (35-pass)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "Polymorphic 12-pass"); // Added new algorithm option
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

    // Create the "Shred File" button
    button = gtk_button_new_with_label("Shred File");

    // Create a grid to hold the combo box and button
    grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_attach(GTK_GRID(grid), combo, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), button, 0, 1, 1, 1);

    // Add the grid to the content area of the dialog
    gtk_container_add(GTK_CONTAINER(content_area), grid);

    // Connect the "Shred File" button clicked signal to the shred_file function
    g_signal_connect(button, "clicked", G_CALLBACK(shred_file), file_chooser);

    // Show all the widgets
    gtk_widget_show_all(algorithm_dialog);
}

int main(int argc, char *argv[]) {
    GtkWidget *window, *file_chooser;

    // Initialize GTK
    gtk_init(&argc, &argv);

    // Create the main window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File Shredder");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    // Set the background color of the window to black
    GdkRGBA black_color;
    gdk_rgba_parse(&black_color, "#000000"); // #000000 corresponds to black color
    gtk_widget_override_background_color(window, GTK_STATE_NORMAL, &black_color);

    // Create the file chooser dialog
    file_chooser = gtk_file_chooser_dialog_new("Select a file to shred",
                                              GTK_WINDOW(window),
                                              GTK_FILE_CHOOSER_ACTION_OPEN,
                                              "Cancel", GTK_RESPONSE_CANCEL,
                                              "Open", GTK_RESPONSE_ACCEPT,
                                              NULL);

    // Connect the "Open" button clicked signal to create_algorithm_dialog function
    g_signal_connect(file_chooser, "response", G_CALLBACK(create_algorithm_dialog), file_chooser);

    // Show all the widgets
    gtk_widget_show_all(window);

    // Start the GTK main loop
    gtk_main();

    return 0;
}
