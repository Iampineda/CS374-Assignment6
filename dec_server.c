#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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


// Function to parse message received from the client
void parseMessage(char *buffer, char *plaintext, char *key, int connectionSocket) {
  memset(plaintext, '\0', 1024);
  memset(key, '\0', 1024);

  char *saveptr;

  // Extract plaintext
  char *token = strtok_r(buffer, " ", &saveptr);
  if (token != NULL) {
      strncpy(plaintext, token, sizeof(plaintext) - 1);
  }

  // Extract key
  token = strtok_r(NULL, " ", &saveptr);
  if (token != NULL) {
      strncpy(key, token, sizeof(key) - 1);
  }

  // Validate key length
  if (strlen(key) < strlen(plaintext)) {
      fprintf(stderr, "ERROR: Key is too short\n");
      close(connectionSocket);
      exit(1);
  }

  printf("SERVER: Parsed plaintext: \"%s\"\n", plaintext);
  printf("SERVER: Parsed key: \"%s\"\n", key);
}


// Decryption algorithm
void decryptMessage(const char *ciphertext, const char *key, char *plaintext) {

  int length = strlen(ciphertext);
  if (ciphertext[length - 1] == '\n') {
      length--; 
  }

  for (int i = 0; i < length; i++) {
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

      plainVal = (cipherVal - keyVal + 27) % 27;  // Ensure non-negative result

      if (plainVal == 26) {
          plaintext[i] = ' ';  
      } else {
          plaintext[i] = 'A' + plainVal;  
      }
  }
  plaintext[length] = '\0';  
}


//////////////////////////////////////////////////////////////////////////////////////////////









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

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5); 
  
  // Accept a connection, blocking if one is not available until one connects
  while (1) {

    connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
    if (connectionSocket < 0) {
        error("ERROR on accept");
    }

    printf("SERVER: Connected to client running at port %d\n", ntohs(clientAddress.sin_port));

    // Fork to handle the client connection
    pid_t spawnPid = fork();

    switch (spawnPid) {
        case -1:  // Fork failed
            printf("ERROR on fork\n");
            break;

        case 0:  // Child Process
          close(listenSocket); 

          // ** Step 1: Receive the full message from the client **
          char buffer[1024];
          receiveMessage(connectionSocket, buffer, sizeof(buffer));
          printf("SERVER: Received full message: \"%s\"\n", buffer);

          // ** Step 2: Parse plaintext and key **
          char plaintext[1024], key[1024];
          parseMessage(buffer, plaintext, key, connectionSocket);

  
         // ** Step 3: Encrpty Message **
          char ciphertext[1024] = {0}; // Buffer for encrypted message

          printf("SERVER: Decrypting message...\n");
          decryptMessage(plaintext, key, ciphertext);

          // ** Step 4: Send the full message to the client ***
          printf("SERVER: Sending decrypted  message: \"%s\"\n", ciphertext);
          sendMessage(connectionSocket, ciphertext);

          close(connectionSocket);
          exit(0);

        default:  // Parent Process
            close(connectionSocket); // Parent closes the connection socket
            break;
    }
  }
  
  // Close the listening socket
  close(listenSocket); 
  return 0;
}
