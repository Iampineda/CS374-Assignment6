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

// Decryption algorithm
void decryptMessage(const char *ciphertext, const char *key, char *plaintext) {
    for (int i = 0; i < strlen(ciphertext); i++) {
        int cipherVal, keyVal, plainVal;

        if (ciphertext[i] == ' ') {
            cipherVal = 26; 
        } else {
            cipherVal = ciphertext[i] - 'A';  
        }

        if (key[i] == ' ') {
            keyVal = 26;  
        } else {
            keyVal = key[i] - 'A';  
        }
 
        plainVal = (cipherVal - keyVal + 27) % 27;

        if (plainVal == 26) {
            plaintext[i] = ' ';  
        } else {
            plaintext[i] = 'A' + plainVal; 
        }
    }
    plaintext[strlen(ciphertext)] = '\0';  
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
    }

    printf("SERVER: Connected to client running at host %d port %d\n", ntohs(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port));

// ** Changes start from SERVER TEMPLATE ** //

    pid_t spawnPid = fork();

    switch (spawnPid) {
      case -1:

        printf("ERROR on fork \n"); 
        break; 

      case 0: // Child Process

        close(listenSocket); 
        
        memset(buffer, '\0', sizeof(buffer));
        int charsRead = recv(connectionSocket, buffer, sizeof(buffer) - 1, 0);
        if (charsRead < 0) {
            error("ERROR reading from socket");
        }

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
          printf("ERROR: Key is too short \n");
          close(connectionSocket);
          exit(1);
        }

        decryptMessage(plaintext, key, ciphertext);
        send(connectionSocket, ciphertext, strlen(ciphertext), 0);

        close(connectionSocket);
        exit(0);
        break; 

      default: // Parent Process
        close(connectionSocket); 
        waitpid(-1, NULL, WNOHANG);
        break;
    }

// ** Changes end from SERVER TEMPLATE ** //




  }

  // Close the listening socket
  close(listenSocket); 
  return 0;
}
