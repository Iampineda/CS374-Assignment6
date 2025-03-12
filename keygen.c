#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char* argv[]) {

    // Check if two arguments provided
    if(argc != 2) {
        printf("Error: Must provide one argument! \n");
        return 1; 
    }

    // Check for valid length
    int keyLength = atoi(argv[1]);
    if(keyLength <= 0) {
        printf("Error: provide a valid length");
        return 1;
    }

    // Seed random generator
    srand(time(NULL));

    // Allocate space for key 
    char* key = malloc((keyLength + 1)* sizeof(char));
    if(key == NULL) {
        printf("Error: Malloc failed \n");
        return 1; 
    }

    // Generate random key
    for(int i = 0; i < keyLength; i++) {
        int val = rand() % 27;
        if(val < 26) {
            key[i] = (val + 'A');
        }
        else {
            key[i] = ' '; 
        }
    }

    // Add string terminator 
    key[keyLength] = '\0';
    printf("%s\n", key);
    free(key);


    return 0; 
}
