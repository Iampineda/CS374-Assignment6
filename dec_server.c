
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;

  // Store the port number
  address->sin_port = htons(portNumber);

  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

// Encryption algorithm
void encryptMessage(const char *plaintext, const char *key, char *ciphertext) {

    int length = strlen(plaintext);
    if (plaintext[length - 1] == '\n') {
      length--; 
    }

    for (int i = 0; i < length; i++) {
        int plainVal, keyVal, cipherVal;

        if (plaintext[i] == ' ') {
            plainVal = 26;  
        } else {
            plainVal = plaintext[i] - 'A';  
        }

        if (key[i] == ' ') {
            keyVal = 26;  
        } else {
            keyVal = key[i] - 'A';  
        }

        cipherVal = (plainVal + keyVal) % 27;  

        if (cipherVal == 26) {
            ciphertext[i] = ' ';  
        } else {
            ciphertext[i] = 'A' + cipherVal;  
        }
    }
    ciphertext[length] = '\n'; 
    ciphertext[length + 1] = '\0'; 
}


int main(int argc, char *argv[]){

  int connectionSocket, charsRead;
  char buffer[1024];
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  // Check usage & args
  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 
  
  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }


  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  int reuse = 1;
  if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
      error("ERROR: setsockopt failed");
      exit(1);
  }

  // Associate the socket to the port
  if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5); 
  

  // Accept a connection, blocking if one is not available until one connects
  while(1){
    
    // Accept the connection request which creates a connection socket
    connectionSocket = accept(listenSocket, (struct sockaddr *) &clientAddress, &sizeOfClientInfo); 
    if (connectionSocket < 0){
      error("ERROR on accept");
      continue; 
    }

    printf("SERVER: Connected to client running at host %d port %d\n", ntohs(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port));


    pid_t spawnPid = fork();

    switch (spawnPid) {
      case -1:

        printf("ERROR on fork \n"); 
        break; 

      case 0: // Child Process

        close(listenSocket); 

        // Verify client is ENC_CLIENT
        char whatClient[16];
        memset(whatClient, '\0', sizeof(whatClient));
        int checkClient = recv(connectionSocket, whatClient, sizeof(whatClient) - 1, 0);

        if (checkClient < 0) { 
            fprintf(stderr, "ERROR: Reading handshake\n");
            close(connectionSocket);
            exit(1);
        }
        if (strncmp(whatClient, "ENC_CLIENT", 10) != 0) {
            fprintf(stderr, "ERROR: Not ENC_CLIENT\n");
            close(connectionSocket);
            exit(1);
        }

        // Send handshake confirmation
        int handshakeSent = send(connectionSocket, "ENC_SERVER", 10, 0);
        if (handshakeSent < 0) {
            fprintf(stderr, "ERROR: Sending handshake response failed\n");
            close(connectionSocket);
            exit(1);
        }


        // Loop to receive full message
        memset(buffer, '\0', sizeof(buffer));
        int totalReceived = 0;
        int charsRead;

        while (totalReceived < sizeof(buffer) - 1) {
            
            charsRead = recv(connectionSocket, buffer + totalReceived, sizeof(buffer) - 1 - totalReceived, 0);
            
            if (charsRead < 0) { 
                fprintf(stderr, "ERROR: Reading from socket\n");
                close(connectionSocket);
                exit(1);
            }
            if (charsRead == 0) { 
                break;
            }
            totalReceived += charsRead;
        }

        buffer[totalReceived] = '\0';
        if (totalReceived <= 0) {
            fprintf(stderr, "ERROR: Received Empty Message\n");
            close(connectionSocket);
            exit(1); 
        }

        // Extract plaintext and key
        char plaintext[1024] = {0};
        char key[1024] = {0};
        char ciphertext[1024] = {0};

        char *saveptr;  

        char *token = strtok_r(buffer, " ", &saveptr);  // plaintext portion
        if (token != NULL) {
            strncpy(plaintext, token, sizeof(plaintext) - 1);
        }

        token = strtok_r(NULL, " ", &saveptr);  // key
        if (token != NULL) {
            strncpy(key, token, sizeof(key) - 1);
        }

        if (strlen(key) < strlen(plaintext)) {
            fprintf(stderr, "ERROR: Key is too short\n");
            close(connectionSocket);
            exit(1);
        }

        // Encrypt message
        encryptMessage(plaintext, key, ciphertext);

        // Loop to send full message
        int totalSent = 0;
        int messageLength = strlen(ciphertext);

        while (totalSent < messageLength) {
            int sentAmount = send(connectionSocket, ciphertext + totalSent, messageLength - totalSent, 0);
            if (sentAmount < 0) { 
                fprintf(stderr, "ERROR: could not write to socket\n");
                close(connectionSocket);
                exit(1); 
            }
            if (sentAmount == 0) { 
                break;
            }
            totalSent += sentAmount; 
        }

        close(connectionSocket);
        exit(0); 
        break;


      default: // Parent Process
        close(connectionSocket); 
        break;
    }

  }

  // Close the listening socket
  close(listenSocket); 
  return 0;
}
