#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#define BUF_SIZE 1024
#define MAX_HASHES 20000
#define OPTIONS "i:o:d:t:vnh"
#define NICE_VALUE 10

// Algorithm names
const char *algorithm_names[] = {
    "DES", "NT", "MD5", "SHA256", "SHA512", "YESCRYPT", "GOST_YESCRYPT", "BCRYPT"
};

// Global variables for dynamic load balancing
int current_hash_index = 0;
int hash_count;
pthread_mutex_t index_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function prototypes
int parse_input_file(const char *input_file, char ***hashes);
int decrypt_password(
    const char *hashed_password,
    FILE *dict_fp,
    char **cracked_password,
    struct crypt_data *crypt_stuff,
    int verbose);
int get_hash_algorithm(const char *hash);
int get_next_hash_index(void);
void *thread_function(void *arg);

// Structure for thread arguments
typedef struct {
    int thread_id;
    char **hashes;
    char *dict_file;
    int verbose;
    int alg_counts[8];     // For counting each algorithm per thread
    int total_processed;
    int total_failed;
    double elapsed_time;
    pthread_mutex_t *output_mutex;
} ThreadArgs;

// Function to determine the hash algorithm
int get_hash_algorithm(const char *hash) {
    if (hash[0] != '$') {
        return 0; // DES
    } else if (strncmp(hash, "$3$", 3) == 0) {
        return 1; // NT
    } else if (strncmp(hash, "$1$", 3) == 0) {
        return 2; // MD5
    } else if (strncmp(hash, "$5$", 3) == 0) {
        return 3; // SHA256
    } else if (strncmp(hash, "$6$", 3) == 0) {
        return 4; // SHA512
    } else if (strncmp(hash, "$y$", 3) == 0) {
        return 5; // YESCRYPT
    } else if (strncmp(hash, "$gy$", 4) == 0) {
        return 6; // GOST_YESCRYPT
    } else if (strncmp(hash, "$2b$", 4) == 0) {
        return 7; // BCRYPT
    } else {
        return -1; // Unknown
    }
}

// Function to get the next hash index (dynamic load balancing)
int get_next_hash_index(void) {
    int index = -1;
    pthread_mutex_lock(&index_mutex);
    if (current_hash_index < hash_count) {
        index = current_hash_index;
        current_hash_index++;
    }
    pthread_mutex_unlock(&index_mutex);
    return index;
}

// Function to parse input file and store hashes in a dynamically allocated array
int parse_input_file(const char *input_file, char ***hashes) {
    FILE *fp;
    char buffer[BUF_SIZE];
    int count = 0;
    int i;

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
            for (i = 0; i < count; i++) {
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
    int verbose) {
    char dict_line[BUF_SIZE];
    char *result;
    char *plain_text;

    // Reset dictionary file pointer to start for each hash
    rewind(dict_fp);

    while (fgets(dict_line, BUF_SIZE, dict_fp)) {
        plain_text = strtok(dict_line, "\n");
        if (!plain_text) {
            if (verbose) {
                // Do not need to lock here as it's per-thread
                fprintf(stderr, "Verbose: Skipping empty plaintext line\n");
            }
            continue;
        }

        // Clear crypt_data structure before each call
        memset(crypt_stuff, 0, sizeof(struct crypt_data));

        // Attempt to hash the plaintext password
        result = crypt_rn(plain_text, hashed_password, crypt_stuff, sizeof(struct crypt_data));
        if (!result) {
            if (verbose) {
                fprintf(stderr, "Error: crypt_rn failed for plaintext: %s\n", plain_text);
            }
            continue;
        }

        // Check if the hashed value matches
        if (strcmp(hashed_password, result) == 0) {
            *cracked_password = strdup(plain_text); // Save cracked plaintext
            return 1;                               // Password successfully cracked
        }
    }

    *cracked_password = NULL;
    return 0; // Failed to crack password
}

// Thread function
void *thread_function(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    struct crypt_data crypt_stuff;
    FILE *dict_fp;
    int index;
    int alg_index;
    struct timeval start_time, end_time;
    double elapsed_time;
    const char *hashed_password;
    char *cracked_password;

    memset(&crypt_stuff, 0, sizeof(struct crypt_data));

    // Initialize per-thread statistics
    memset(args->alg_counts, 0, sizeof(args->alg_counts));
    args->total_processed = 0;
    args->total_failed = 0;

    // Open the dictionary file for this thread
    dict_fp = fopen(args->dict_file, "r");
    if (!dict_fp) {
        perror("Error opening dictionary file in thread");
        pthread_exit(NULL);
    }

    gettimeofday(&start_time, NULL);

    while ((index = get_next_hash_index()) != -1) {
        hashed_password = args->hashes[index];
        cracked_password = NULL;

        if (args->verbose) {
            pthread_mutex_lock(args->output_mutex);
            fprintf(stderr, "Verbose: Thread %d processing hash %s\n", args->thread_id, hashed_password);
            pthread_mutex_unlock(args->output_mutex);
        }

        // Determine hash algorithm
        alg_index = get_hash_algorithm(hashed_password);
        if (alg_index >= 0) {
            args->alg_counts[alg_index]++;
        }

        args->total_processed++;

        if (decrypt_password(hashed_password, dict_fp, &cracked_password, &crypt_stuff, args->verbose)) {
            // Output the cracked password immediately
            pthread_mutex_lock(args->output_mutex);
            printf("cracked  %s  %s\n", cracked_password, hashed_password);
            fflush(stdout);
            pthread_mutex_unlock(args->output_mutex);
            free(cracked_password);
        } else {
            pthread_mutex_lock(args->output_mutex);
            printf("*** failed to crack  %s\n", hashed_password);
            fflush(stdout);
            pthread_mutex_unlock(args->output_mutex);
            args->total_failed++;
        }
    }

    gettimeofday(&end_time, NULL);

    elapsed_time = ((end_time.tv_sec - start_time.tv_sec) * 1000000.0 + (end_time.tv_usec - start_time.tv_usec)) / 1000000.0;
    args->elapsed_time = elapsed_time;

    // Output per-thread statistics to stderr
    pthread_mutex_lock(args->output_mutex);
    fprintf(stderr, "thread: %2d %8.2f sec", args->thread_id, elapsed_time);
    for (alg_index = 0; alg_index < 8; alg_index++) {
        fprintf(stderr, " %15s: %5d", algorithm_names[alg_index], args->alg_counts[alg_index]);
    }
    fprintf(stderr, "  total: %8d  failed: %8d\n", args->total_processed, args->total_failed);
    pthread_mutex_unlock(args->output_mutex);

    fclose(dict_fp);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    char *input_file = NULL;
    char *output_file = NULL;
    char *dict_file = NULL;
    char **hashes = NULL;
    FILE *output_fp;
    int opt, verbose = 0, nice_value = 0, num_threads = 1;
    pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t *threads;
    ThreadArgs *thread_args;
    int i, j;
    int rc;
    int total_alg_counts[8] = {0};
    int total_processed = 0;
    int total_failed = 0;
    double max_elapsed_time = 0.0;
    struct timeval program_start_time, program_end_time;
    double total_elapsed_time;

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

    output_fp = stdout;
    if (output_file) {
        output_fp = fopen(output_file, "w");
        if (!output_fp) {
            perror("Error opening output file");
            for (i = 0; i < hash_count; i++) {
                free(hashes[i]);
            }
            free(hashes);
            return EXIT_FAILURE;
        }
        // Redirect stdout to the output file
        if (dup2(fileno(output_fp), STDOUT_FILENO) == -1) {
            perror("Error redirecting stdout");
            return EXIT_FAILURE;
        }
    }

    // Initialize threading
    threads = malloc(num_threads * sizeof(pthread_t));
    thread_args = malloc(num_threads * sizeof(ThreadArgs));

    if (!threads || !thread_args) {
        perror("Memory allocation failed for threads");
        return EXIT_FAILURE;
    }

    // Start total program timing
    gettimeofday(&program_start_time, NULL);

    // Create threads
    for (i = 0; i < num_threads; i++) {
        thread_args[i].thread_id = i;
        thread_args[i].hashes = hashes;
        thread_args[i].dict_file = dict_file;
        thread_args[i].verbose = verbose;
        thread_args[i].output_mutex = &output_mutex;

        rc = pthread_create(&threads[i], NULL, thread_function, (void *)&thread_args[i]);
        if (rc) {
            fprintf(stderr, "Error: Unable to create thread %d, %d\n", i, rc);
            exit(EXIT_FAILURE);
        }
    }

    // Wait for threads to finish
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    gettimeofday(&program_end_time, NULL);
    total_elapsed_time = ((program_end_time.tv_sec - program_start_time.tv_sec) * 1000000.0 + (program_end_time.tv_usec - program_start_time.tv_usec)) / 1000000.0;

    // Sum up statistics from all threads
    for (i = 0; i < num_threads; i++) {
        for (j = 0; j < 8; j++) {
            total_alg_counts[j] += thread_args[i].alg_counts[j];
        }
        total_processed += thread_args[i].total_processed;
        total_failed += thread_args[i].total_failed;
        // Find the maximum elapsed time among threads
        if (thread_args[i].elapsed_time > max_elapsed_time) {
            max_elapsed_time = thread_args[i].elapsed_time;
        }
    }

    // Output total statistics to stderr
    pthread_mutex_lock(&output_mutex);
    fprintf(stderr, "total:  %2d %8.2f sec", num_threads, max_elapsed_time);
    for (j = 0; j < 8; j++) {
        fprintf(stderr, " %15s: %5d", algorithm_names[j], total_alg_counts[j]);
    }
    fprintf(stderr, "  total: %8d  failed: %8d\n", total_processed, total_failed);
    pthread_mutex_unlock(&output_mutex);

    // Clean up
    if (output_fp != stdout) {
        fclose(output_fp);
    }

    for (i = 0; i < hash_count; i++) {
        free(hashes[i]);
    }
    free(hashes);
    free(threads);
    free(thread_args);
    pthread_mutex_destroy(&output_mutex);
    pthread_mutex_destroy(&index_mutex);

    return EXIT_SUCCESS;
}
