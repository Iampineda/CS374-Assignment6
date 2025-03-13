#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      

#define BUFFER_SIZE 70000

// Error function used for reporting issues
void error(const char *msg) { 
    perror(msg); 
    exit(1); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname) {
    memset((char*) address, '\0', sizeof(*address)); 
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent* hostInfo = gethostbyname(hostname); 
    if (hostInfo == NULL) { 
        fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
        exit(1); 
    }

    memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}









//////////////////////////////////////////////////////////////////////////////////////////////

void sendMessage(int socketFD, char *message) {
    int totalSent = 0;
    int messageLength = strlen(message);

    while (totalSent < messageLength) {
        int sentAmount = send(socketFD, message + totalSent, messageLength - totalSent, 0);
        if (sentAmount < 0) {
            perror("ERROR sending message");
            close(socketFD);
            exit(1);
        }
        totalSent += sentAmount;
    }

    // Send a termination signal (`\n`) to mark end of message
    char endSignal = '\n';
    send(socketFD, &endSignal, 1, 0);

    // printf("Sent full message: \"%s\"\n", message);
}

void receiveMessage(int socketFD, char *buffer, int bufferSize) {
    memset(buffer, '\0', bufferSize);
    int totalReceived = 0;
    int charsRead;
    char tempBuffer[2];

    while (totalReceived < bufferSize - 1) {
        charsRead = recv(socketFD, tempBuffer, 1, 0); // Read 1 byte at a time
        if (charsRead < 0) {
            perror("ERROR reading from socket");
            close(socketFD);
            exit(1);
        }
        if (charsRead == 0 || tempBuffer[0] == '\n') { // End if client closed or newline received
            break;
        }
        buffer[totalReceived] = tempBuffer[0];
        totalReceived++;
    }

    buffer[totalReceived] = '\0'; // Null-terminate the received message
    // printf("Received full message: \"%s\"\n", buffer);

}


// Function to validate that the key is not shorter than the plaintext
void validateKeyLength(const char *plaintextFileName, const char *keyFileName) {
    // Open the plaintext file
    FILE *plaintextFile = fopen(plaintextFileName, "r");
    if (plaintextFile == NULL) {
        fprintf(stderr, "Error: could not open plaintext file\n");
        exit(1);
    }

    // Read plaintext content
    char plaintext[1024] = {0};
    fgets(plaintext, sizeof(plaintext) - 1, plaintextFile);
    fclose(plaintextFile);

    // Open the key file
    FILE *keyFile = fopen(keyFileName, "r");
    if (keyFile == NULL) {
        fprintf(stderr, "Error: could not open key file\n");
        exit(1);
    }

    // Read key content
    char key[1024] = {0};
    fgets(key, sizeof(key) - 1, keyFile);
    fclose(keyFile);

    // Check if key is shorter than plaintext
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "Error: key ‘%s’ is too short\n", keyFileName);
        exit(1);  // Ensure exit status is 1
    }
}

void readFileContents(const char *filename, char *buffer, int maxSize) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: could not open %s\n", filename);
        exit(1);
    }
    fgets(buffer, maxSize, file);
    fclose(file);

    // Strip newline character if present
    buffer[strcspn(buffer, "\n")] = '\0';
}


void performHandshake(int socketFD, const char *clientType, const char *expectedServerType, int port) {
    char handshakeMsg[16];
    memset(handshakeMsg, '\0', sizeof(handshakeMsg));

    // Send client identifier (ENC_CLIENT or DEC_CLIENT)
    int charsWritten = send(socketFD, clientType, strlen(clientType), 0);
    if (charsWritten < 0) {
        fprintf(stderr, "Error: could not contact %s on port %d\n", expectedServerType, port);
        close(socketFD);
        exit(2);  // Exit with status 2 as required
    }

    // Receive server confirmation
    int charsRead = recv(socketFD, handshakeMsg, sizeof(handshakeMsg) - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "Error: could not contact %s on port %d\n", expectedServerType, port);
        close(socketFD);
        exit(2);
    }

    // Validate that the server is the correct one
    if (strncmp(handshakeMsg, expectedServerType, strlen(expectedServerType)) != 0) {
        fprintf(stderr, "Error: could not contact %s on port %d\n", expectedServerType, port);
        close(socketFD);
        exit(2);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////








int main(int argc, char *argv[]) {
    int socketFD;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    if (argc < 4) { 
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]); 
        exit(1);
    }

    validateKeyLength(argv[1], argv[2]);  // Validate key length before sending

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (socketFD < 0){
        error("CLIENT: ERROR opening socket");
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");


    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
        error("CLIENT: ERROR connecting");
    }

    performHandshake(socketFD, "ENC_CLIENT", "ENC_SERVER", atoi(argv[3]));



    // Prepare the message to send (plaintext and key)
    char plaintext[BUFFER_SIZE] = {0};
    char key[BUFFER_SIZE] = {0};

    readFileContents(argv[1], plaintext, sizeof(plaintext));
    readFileContents(argv[2], key, sizeof(key));

    // Prepare the message to send (plaintext + key)
    memset(buffer, '\0', sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "%s\n%s", plaintext, key);

    // Send message to server
    sendMessage(socketFD, buffer);

    // Receive response from server
    receiveMessage(socketFD, buffer, sizeof(buffer));

    // Print ciphertext to stdout (ensuring it ends with a newline)
    printf("%s\n", buffer);

    // Close the socket
    close(socketFD); 
    // printf("CLIENT: Connection closed.\n");

    return 0;
}
