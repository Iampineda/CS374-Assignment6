#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 70000
const int bool = 0;

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

// -- Helper Functions --
// ----------------------------------------------------------------------------------------------

// Function: 
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

}

// Function: 
void receiveMessage(int socketFD, char *buffer, int bufferSize) {
  memset(buffer, '\0', bufferSize);
  int totalReceived = 0;
  int charsRead;

  while (totalReceived < bufferSize - 1) {
      charsRead = recv(socketFD, buffer + totalReceived, bufferSize - totalReceived - 1, 0);
      
      if (charsRead < 0) {
          perror("ERROR reading from socket");
          close(socketFD);
          exit(1);
      }
      if (charsRead == 0) {  // Stop if connection closes
          break;
      }

      totalReceived += charsRead;

      // ** Check if two newlines exist (plaintext + key) **
      char *firstNewline = strchr(buffer, '\n');
      if (firstNewline != NULL) {
          char *secondNewline = strchr(firstNewline + 1, '\n');  // Look for second newline
          if (secondNewline != NULL) {
              break;  // We have received both lines
          }
      }
  }

  buffer[totalReceived] = '\0';  // Ensure null termination
}

// Function: 
void extractPlaintext(char *buffer, char *plaintext, int connectionSocket) {
  memset(plaintext, '\0', BUFFER_SIZE);

  char *newlinePos = strchr(buffer, '\n');
  if (newlinePos != NULL) {
      size_t plaintextLength = newlinePos - buffer;
      strncpy(plaintext, buffer, plaintextLength);
      plaintext[plaintextLength] = '\0';  // Null-terminate
  } else {
      printf("SERVER ERROR: No newline found in received message!\n");
      fflush(stdout);
      close(connectionSocket);
      exit(1);
  }
}

// Function: 
void extractKey(char *buffer, char *key, int connectionSocket) {
  memset(key, '\0', BUFFER_SIZE);

  
  char *newlinePos = strchr(buffer, '\n');
  if (newlinePos != NULL) {
      char *keyStart = newlinePos + 1;  
      strncpy(key, keyStart, 1023);  
      key[1023] = '\0'; 

  } else {
      printf("SERVER ERROR: No newline found when extracting key!\n");
      fflush(stdout);
      close(connectionSocket);
      exit(1);
  }
}

// Function: 
void parseMessage(char *buffer, char *plaintext, char *key, int connectionSocket) {
  extractPlaintext(buffer, plaintext, connectionSocket);
  extractKey(buffer, key, connectionSocket);
}

// Function: 
void verifyClient(int connectionSocket, const char *expectedClientType, const char *serverType) {
  char clientType[16];
  memset(clientType, '\0', sizeof(clientType));

  // Receive client identifier
  int checkClient = recv(connectionSocket, clientType, sizeof(clientType) - 1, 0);
  if (checkClient < 0) {
      fprintf(stderr, "SERVER: ERROR reading handshake\n");
      close(connectionSocket);
      exit(1);
  }

  // Validate client type (ENC_CLIENT or DEC_CLIENT)
  if (strncmp(clientType, expectedClientType, strlen(expectedClientType)) != 0) {
      fprintf(stderr, "SERVER: ERROR - incorrect client type\n");
      close(connectionSocket);
      exit(1);
  }

  // Send server confirmation (ENC_SERVER or DEC_SERVER)
  int handshakeSent = send(connectionSocket, serverType, strlen(serverType), 0);
  if (handshakeSent < 0) {
      fprintf(stderr, "SERVER: ERROR sending handshake response\n");
      close(connectionSocket);
      exit(1);
  }
}

// Function: 
void decryptMessage(const char *ciphertext, const char *key, char *plaintext) {
  int length = strlen(ciphertext);

  if (length > 0 && ciphertext[length - 1] == '\n') {
      length--;
  }

  for (int i = 0; i < length; i++) {
      int cipherVal, keyVal, plainVal;

      cipherVal = (ciphertext[i] == ' ') ? 26 : (ciphertext[i] - 'A');
      keyVal = (key[i] == ' ') ? 26 : (key[i] - 'A');

      plainVal = (cipherVal - keyVal + 27) % 27;  // Decryption formula

      plaintext[i] = (plainVal == 26) ? ' ' : ('A' + plainVal);
  }

  plaintext[length] = '\n';
  plaintext[length + 1] = '\0';
}

// ----------------------------------------------------------------------------------------------

int main(int argc, char *argv[]){
  int connectionSocket, charsRead;
  char buffer[BUFFER_SIZE];
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

    // Concurrency Handling 
    pid_t spawnPid = fork();
    switch (spawnPid) {
        case -1:  // Fork failed
            printf("ERROR on fork\n");
            break;

        case 0:  // Child Process

          close(listenSocket); 

          // ** Step 0: Check Correct Client and Server Connection **
          verifyClient(connectionSocket, "DEC_CLIENT", "DEC_SERVER");

          // ** Step 1: Receive the full message from the client **
          char buffer[BUFFER_SIZE];
          receiveMessage(connectionSocket, buffer, sizeof(buffer));

          // ** Step 2: Parse ciphertext and key **
          char ciphertext[BUFFER_SIZE], key[BUFFER_SIZE];
          parseMessage(buffer, ciphertext, key, connectionSocket);
  
          // ** Step 3: decrypt Message **
          char plaintext[BUFFER_SIZE] = {0};
          decryptMessage(ciphertext, key, plaintext);

          // ** Step 4: Send the full message to the client ***
          sendMessage(connectionSocket, plaintext);

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
