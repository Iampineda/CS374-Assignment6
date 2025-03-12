#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      

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

    printf("Sent full message: \"%s\"\n", message);
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
    printf("Received full message: \"%s\"\n", buffer);
}



//////////////////////////////////////////////////////////////////////////////////////////////








int main(int argc, char *argv[]) {
    int socketFD;
    struct sockaddr_in serverAddress;
    char buffer[1024];

    if (argc < 5) { 
        fprintf(stderr,"USAGE: %s hostname port ciphertext key\n", argv[0]); 
        exit(1); 
    } 

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (socketFD < 0){
        error("CLIENT: ERROR opening socket");
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[2]), argv[1]);

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
        error("CLIENT: ERROR connecting");
    }

    // Prepare the message to send (plaintext and key)
    memset(buffer, '\0', sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "%s %s", argv[3], argv[4]);

    // Send message to server
    sendMessage(socketFD, buffer);

    // Receive response from server
    receiveMessage(socketFD, buffer, sizeof(buffer));

    // Close the socket
    close(socketFD); 
    printf("CLIENT: Connection closed.\n");

    return 0;
}
