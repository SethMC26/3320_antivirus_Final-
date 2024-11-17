#include "Crypto/fingerprint.h"
#include "stdio.h"

#include "fileHandler.h"

int get_user_input(char *prompt)
{
    char input;

    // iterate until we get a good value
    while (1)
    {
        printf("%s", prompt);
        scanf("%c", &input);

        if (input == 'y' || input == 'Y')
        {
            return 1;
        }
        else if (input == 'n' || input == 'N')
        {
            return 0;
        }
        else
        {
            printf("\nInvalid input must be Y or N");
        }

        // Clear the buffer in case of invalid input
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }
}

// Function to get the hash of a file
void get_file_hash(const char* file_path) {
    char sha1_hash[SHA1_BUFFER_SIZE];
    char sha256_hash[SHA256_BUFFER_SIZE];
    char md5_hash[MD5_BUFFER_SIZE];

    if (sha1_fingerprint_file(file_path, sha1_hash) == 0) {
        printf("SHA1: %s\n", sha1_hash);
    } else {
        printf("Failed to calculate SHA1 hash for %s\n", file_path);
    }

    if (sha256_fingerprint_file(file_path, sha256_hash) == 0) {
        printf("SHA256: %s\n", sha256_hash);
    } else {
        printf("Failed to calculate SHA256 hash for %s\n", file_path);
    }

    if (md5_fingerprint_file(file_path, md5_hash) == 0) {
        printf("MD5: %s\n", md5_hash);
    } else {
        printf("Failed to calculate MD5 hash for %s\n", file_path);
    }
}