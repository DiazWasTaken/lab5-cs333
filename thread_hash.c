#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "thread_hash.h"
#include <bits/getopt_core.h>

int main(int argc, char *argv[]) {
    int opt;
    char *input_file = NULL;
    char *output_file = NULL;
    char *dict_file = NULL;
    int num_threads = 1; // Default value
    int verbose = 0;     // Flag for verbose mode
    int nice_value = 0;  // Nice value flag

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
            fprintf(stderr, "Options:\n");
            fprintf(stderr, "  -i input      Specify the input file (required).\n");
            fprintf(stderr, "  -d dictionary Specify the dictionary file (required).\n");
            fprintf(stderr, "  -o output     Specify the output file (optional, defaults to stdout).\n");
            fprintf(stderr, "  -t threads    Number of threads to use (default: 1).\n");
            fprintf(stderr, "  -v            Enable verbose mode.\n");
            fprintf(stderr, "  -n            Apply nice() to lower process priority.\n");
            fprintf(stderr, "  -h            Display this help message.\n");
            return EXIT_SUCCESS;
        default:
            fprintf(stderr, "Invalid option. Use -h for help.\n");
            return EXIT_FAILURE;
        }
    }

    // Check for required arguments
    if (!input_file || !dict_file) {
        fprintf(stderr, "Error: Both input (-i) and dictionary (-d) files are required.\n");
        return EXIT_FAILURE;
    }

    // Debugging output
    if (verbose) {
        fprintf(stderr, "Verbose mode enabled.\n");
        fprintf(stderr, "Input file: %s\n", input_file);
        fprintf(stderr, "Dictionary file: %s\n", dict_file);
        if (output_file) {
            fprintf(stderr, "Output file: %s\n", output_file);
        } else {
            fprintf(stderr, "Output file: stdout\n");
        }
        fprintf(stderr, "Number of threads: %d\n", num_threads);
        if (nice_value) {
            fprintf(stderr, "Process nice value will be set to 10.\n");
        }
    }

    // Apply nice value if requested
    if (nice_value) {
        if (nice(NICE_VALUE) == -1) {
            perror("Failed to apply nice value");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}