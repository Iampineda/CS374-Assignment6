#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  
#include <sys/wait.h>   


// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

// Function to receive a full message from a client
void receiveMessage(int connectionSocket, char *buffer, int bufferSize) {
  memset(buffer, '\0', bufferSize);
  int totalReceived = 0;
  int charsRead;

  while (totalReceived < bufferSize - 1) {
      charsRead = recv(connectionSocket, buffer + totalReceived, bufferSize - 1 - totalReceived, 0);
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
}

// Function to send a full message to a client
void sendMessage(int connectionSocket, char *message) {
  int totalSent = 0;
  int messageLength = strlen(message);

  while (totalSent < messageLength) {
      int sentAmount = send(connectionSocket, message + totalSent, messageLength - totalSent, 0);
      if (sentAmount < 0) {
          fprintf(stderr, "ERROR: Could not write to socket\n");
          close(connectionSocket);
          exit(1);
      }
      if (sentAmount == 0) {
          break;
      }
      totalSent += sentAmount;
  }
}

// Function to parse message received 
void parseMessage(char *buffer, char *plaintext, char *key, int connectionSocket) {
  char *saveptr;
  memset(plaintext, '\0', 1024);
  memset(key, '\0', 1024);

  // Extract plaintext
  char *token = strtok_r(buffer, " ", &saveptr);
  if (token != NULL) {
      strncpy(plaintext, token, sizeof(plaintext) - 1);
  } else {
      fprintf(stderr, "ERROR: Missing plaintext\n");
      sendMessage(connectionSocket, "ERROR: Missing plaintext");
      close(connectionSocket);
      exit(1);
  }

  // Extract key
  token = strtok_r(NULL, " ", &saveptr);
  if (token != NULL) {
      strncpy(key, token, sizeof(key) - 1);
  } else {
      fprintf(stderr, "ERROR: Missing key\n");
      sendMessage(connectionSocket, "ERROR: Missing key");
      close(connectionSocket);
      exit(1);
  }

  // Ensure the key is at least as long as the plaintext
  if (strlen(key) < strlen(plaintext)) {
      fprintf(stderr, "ERROR: Key is too short\n");
      sendMessage(connectionSocket, "ERROR: Key is too short");
      close(connectionSocket);
      exit(1);
  }
}



int main(int argc, char *argv[]){
  int connectionSocket, charsRead;
  char buffer[256];
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
  }

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5); 
  
  // Accept a connection, blocking if one is not available until one connects
  while(1){

    // Accept the connection request which creates a connection socket
    connectionSocket = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (connectionSocket < 0){
      error("ERROR on accept");
    }

    printf("SERVER: Connected to client running at host %d port %d\n", 
                          ntohs(clientAddress.sin_addr.s_addr),
                          ntohs(clientAddress.sin_port));
                  
  
    // Child and Parent Process
    pid_t spawnPid = fork();

    switch (spawnPid) {
      case -1:

        printf("ERROR on fork \n"); 
        break; 

      case 0: // Child Process

        close(listenSocket); 

        //  ** Receive message from client **
        receiveMessage(connectionSocket, buffer, sizeof(buffer));

       // ** Parse plaintext and key **
        char plaintext[1024], key[1024]; 
        parseMessage(buffer, plaintext, key, connectionSocket);

        // ** Send response back to client **
        sendMessage(connectionSocket, "Message received!");

        close(connectionSocket);
        exit(0); 
        break;


      default: // Parent Process
        close(connectionSocket); 
        while (waitpid(-1, NULL, WNOHANG) > 0);
        break;
    }

  }
  // Close the listening socket
  close(listenSocket); 
  return 0;
}
