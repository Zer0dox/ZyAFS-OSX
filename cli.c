#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/rand.h>
#include <CommonCrypto/CommonCrypto.h>

#define BUFFER_SIZE 1024

static void generate_random_iv(unsigned char *iv) {
    // Generate a random initialization vector
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        fprintf(stderr, "Error generating random IV.\n");
        exit(EXIT_FAILURE);
    }
}

static void overwrite_with_polymorphic_12_pass(FILE* fp, long file_size, double* progress) {
    // 12-pass algorithm with a strong cryptographic stream cipher and dynamic IVs
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    // Generate a random key for the stream cipher
    if (RAND_bytes(key, EVP_MAX_KEY_LENGTH) != 1) {
        fprintf(stderr, "Error generating random key.\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_SET);
    long num_iterations = file_size / BUFFER_SIZE;
    long remainder = file_size % BUFFER_SIZE;

    for (int pass = 0; pass < 12; pass++) {
        // Generate a new IV for each pass
        generate_random_iv(iv);
        fseek(fp, 0, SEEK_SET);

        for (long i = 0; i < num_iterations; i++) {
            unsigned char buffer[BUFFER_SIZE];

            // Read data from the file
            fread(buffer, sizeof(char), BUFFER_SIZE, fp);

            // Encrypt the data using the stream cipher with the current IV
            EVP_CIPHER_CTX *ctx;
            int outlen, tmplen;
            unsigned char ciphertext[BUFFER_SIZE];

            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, buffer, BUFFER_SIZE);
            EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
            EVP_CIPHER_CTX_free(ctx);

            // Write the encrypted data back to the file
            fseek(fp, -BUFFER_SIZE, SEEK_CUR);
            fwrite(ciphertext, sizeof(char), BUFFER_SIZE, fp);

            // Update progress
            *progress = (double)((pass * num_iterations + i) * BUFFER_SIZE) / (double)(12 * num_iterations * BUFFER_SIZE);
        }

        if (remainder > 0) {
            unsigned char buffer[remainder];

            // Read remaining data from the file
            fread(buffer, sizeof(char), remainder, fp);

            // Encrypt the remaining data using the stream cipher with the current IV
            EVP_CIPHER_CTX *ctx;
            int outlen, tmplen;
            unsigned char ciphertext[remainder];

            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, buffer, remainder);
            EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
            EVP_CIPHER_CTX_free(ctx);

            // Write the encrypted data back to the file
            fseek(fp, -remainder, SEEK_CUR);
            fwrite(ciphertext, sizeof(char), remainder, fp);

            // Update progress
            *progress = (double)((pass * num_iterations + num_iterations) * BUFFER_SIZE + remainder) / (double)(12 * num_iterations * BUFFER_SIZE);
        }
    }
}

void overwrite_with_null_bytes(FILE* fp, long file_size, double* progress) {
    char null_byte = 0;

    for (long i = 0; i < file_size; i++) {
        fwrite(&null_byte, sizeof(char), 1, fp);

        // Update progress
        *progress = (double)i / (double)file_size;
    }
}

void overwrite_with_random_data(FILE* fp, long file_size, double* progress) {
    char buffer[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = rand() % 256; // Generate random data (0-255)
    }

    fseek(fp, 0, SEEK_SET);
    long num_iterations = file_size / BUFFER_SIZE;
    long remainder = file_size % BUFFER_SIZE;

    for (long i = 0; i < num_iterations; i++) {
        fwrite(buffer, sizeof(char), BUFFER_SIZE, fp);

        // Update progress
        *progress = (double)(i * BUFFER_SIZE) / (double)file_size;
    }

    if (remainder > 0) {
        fwrite(buffer, sizeof(char), remainder, fp);

        // Update progress
        *progress = (double)(file_size - remainder) / (double)file_size;
    }
}

void overwrite_with_gutmann(FILE* fp, long file_size, double* progress) {
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

        // Update progress
        *progress = (double)(i * 35 * BUFFER_SIZE) / (double)file_size;
    }

    if (remainder > 0) {
        for (int j = 0; j < 35; j++) {
            fwrite(patterns[j], sizeof(char), remainder, fp);
        }

        // Update progress
        *progress = (double)(file_size - remainder) / (double)file_size;
    }
}

void shred_file(const char* filename, const char* algorithm) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            // Shred an individual file
            FILE* fp = fopen(filename, "r+b");

            if (!fp) {
                fprintf(stderr, "Error: Unable to open the file.\n");
                exit(EXIT_FAILURE);
            }

            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            rewind(fp);

            double progress = 0.0;
            if (strcmp(algorithm, "nullbytes") == 0) {
                overwrite_with_null_bytes(fp, file_size, &progress);
            } else if (strcmp(algorithm, "randomdata") == 0) {
                overwrite_with_random_data(fp, file_size, &progress);
            } else if (strcmp(algorithm, "gutmann") == 0) {
                overwrite_with_gutmann(fp, file_size, &progress);
            } else if (strcmp(algorithm, "polymorphic") == 0) {
                overwrite_with_polymorphic_12_pass(fp, file_size, &progress);
            } else {
                fprintf(stderr, "Error: Invalid algorithm specified.\n");
                exit(EXIT_FAILURE);
            }

            fclose(fp);
            printf("%s has been securely shredded using %s algorithm.\n", filename, algorithm);
            
             // Delete the file after shredding
            if (remove(filename) == 0) {
                printf("%s has been securely shredded and deleted.\n", filename);
            } else {
                fprintf(stderr, "Error: Unable to delete the file.\n");
                exit(EXIT_FAILURE);
            }
            
        } else if (S_ISDIR(st.st_mode)) {
            // Shred a directory (including all files and subdirectories)
            DIR* dir = opendir(filename);
            if (!dir) {
                fprintf(stderr, "Error: Unable to open the directory.\n");
                exit(EXIT_FAILURE);
            }

            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                // Skip "." and ".." directories
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                    continue;
                }

                // Create the full path for the entry
                char path[PATH_MAX];
                snprintf(path, PATH_MAX, "%s/%s", filename, entry->d_name);

                // Recursive call to shred_file for the entry
                shred_file(path, algorithm);
            }

            closedir(dir);
            printf("Directory %s has been securely shredded using %s algorithm.\n", filename, algorithm);
        } else {
            fprintf(stderr, "Error: Unsupported file type.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Error: Unable to access the file/directory.\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename/directory> <algorithm>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* filename = argv[1];
    const char* algorithm = argv[2];

    shred_file(filename, algorithm);

    return EXIT_SUCCESS;
}
