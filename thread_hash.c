#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h> // Include the crypt.h header for crypt_rn
#include <unistd.h>
#include "thread_hash.h"
#include <bits/getopt_core.h>

#define BUF_SIZE 1024
#define MAX_HASHES 20000

int parse_input_file(const char *input_file, char ***hashes);
int decrypt_password(
    const char *hashed_password, 
    FILE *dict_fp, 
    char **cracked_password, 
    struct crypt_data *crypt_stuff, 
    int verbose);

// Function to parse input file and store hashes in a dynamically allocated array
int parse_input_file(const char *input_file, char ***hashes) {
    FILE *fp;
    char buffer[BUF_SIZE];
    int count = 0;

    // Open the input file for reading
    fp = fopen(input_file, "r");
    if (!fp) {
        perror("Error opening input file");
        return -1;
    }

    // Allocate memory for the array of hash strings
    *hashes = malloc(MAX_HASHES * sizeof(char *));
    if (!*hashes) {
        perror("Memory allocation failed");
        fclose(fp);
        return -1;
    }

    // Read each line from the file
    while (fgets(buffer, BUF_SIZE, fp) && count < MAX_HASHES) {
        // Remove the trailing newline character
        buffer[strcspn(buffer, "\n")] = '\0';

        // Allocate memory for the hash and store it
        (*hashes)[count] = strdup(buffer);
        if (!(*hashes)[count]) {
            perror("Memory allocation failed");
            fclose(fp);

            // Free previously allocated memory on failure
            for (int i = 0; i < count; i++) {
                free((*hashes)[i]);
            }
            free(*hashes);
            return -1;
        }

        count++;
    }

    fclose(fp);
    return count; // Return the number of hashes read
}

// Function to decrypt a hashed password using a dictionary and crypt_rn
int decrypt_password(
    const char *hashed_password, 
    FILE *dict_fp, 
    char **cracked_password, 
    struct crypt_data *crypt_stuff, 
    int verbose) 
{
    char dict_line[BUF_SIZE];
    char *result;

    // Reset dictionary file pointer to start for each hash
    rewind(dict_fp);

    while (fgets(dict_line, BUF_SIZE, dict_fp)) {
        char *plain_text = strtok(dict_line, "\n");
        if (!plain_text) {
            if (verbose) {
                fprintf(stderr, "Verbose: Skipping empty plaintext line\n");
            }
            continue;
        }

        // Clear crypt_data structure before each call
        memset(crypt_stuff, 0, sizeof(struct crypt_data));

        // Attempt to hash the plaintext password
        result = crypt_rn(plain_text, hashed_password, crypt_stuff, sizeof(struct crypt_data));
        if (!result) {
            fprintf(stderr, "Error: crypt_rn failed for plaintext: %s\n", plain_text);
            continue;
        }

        // Check if the hashed value matches
        if (strcmp(hashed_password, result) == 0) {
            *cracked_password = strdup(plain_text); // Save cracked plaintext
            return 1; // Password successfully cracked
        }
    }

    *cracked_password = NULL;
    return 0; // Failed to crack password
}

int main(int argc, char *argv[]) {
    char *input_file = NULL;
    char *output_file = NULL;
    char *dict_file = NULL;
    char **hashes = NULL;
    int hash_count;
    FILE *dict_fp, *output_fp;
    struct crypt_data crypt_stuff;
    int opt, verbose = 0, nice_value = 0, num_threads = 1;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'i':
            input_file = optarg;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'd':
            dict_file = optarg;
            break;
        case 't':
            num_threads = atoi(optarg);
            if (num_threads < 1) {
                fprintf(stderr, "Error: Number of threads must be at least 1.\n");
                return EXIT_FAILURE;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'n':
            nice_value = 1;
            break;
        case 'h':
            fprintf(stderr, "Usage: %s -i input -d dictionary [-o output] [-t threads] [-v] [-n]\n", argv[0]);
            return EXIT_SUCCESS;
        default:
            fprintf(stderr, "Invalid option: %c\n", opt);
            return EXIT_FAILURE;
        }
    }

    if (!input_file || !dict_file) {
        fprintf(stderr, "Error: -i and -d options are required.\n");
        return EXIT_FAILURE;
    }

    if (nice_value && nice(NICE_VALUE) == -1) {
        perror("Failed to apply nice value");
        return EXIT_FAILURE;
    }

    hash_count = parse_input_file(input_file, &hashes);
    if (hash_count < 0) {
        return EXIT_FAILURE;
    }

    dict_fp = fopen(dict_file, "r");
    if (!dict_fp) {
        perror("Error opening dictionary file");
        for (int i = 0; i < hash_count; i++) {
            free(hashes[i]);
        }
        free(hashes);
        return EXIT_FAILURE;
    }

    output_fp = stdout;
    if (output_file) {
        output_fp = fopen(output_file, "w");
        if (!output_fp) {
            perror("Error opening output file");
            fclose(dict_fp);
            for (int i = 0; i < hash_count; i++) {
                free(hashes[i]);
            }
            free(hashes);
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < hash_count; i++) {
        const char *hashed_password = hashes[i];
        char *cracked_password = NULL;

        if (verbose) {
            fprintf(stderr, "Verbose: Processing hash %s\n", hashed_password);
        }

        if (decrypt_password(hashed_password, dict_fp, &cracked_password, &crypt_stuff, verbose)) {
            fprintf(output_fp, "cracked: %s -> %s\n", hashed_password, cracked_password);
            free(cracked_password);
        } else {
            fprintf(output_fp, "*** failed to crack: %s\n", hashed_password);
        }
    }

    fclose(dict_fp);
    if (output_fp != stdout) {
        fclose(output_fp);
    }

    for (int i = 0; i < hash_count; i++) {
        free(hashes[i]);
    }
    free(hashes);

    return EXIT_SUCCESS;
}
