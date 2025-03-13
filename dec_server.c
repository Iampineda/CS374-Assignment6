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









/////////////////////
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

  // ** Debugging Output **
  printf("SERVER: Received full message:\n---START---\n%s\n---END---\n", buffer);
  fflush(stdout);
}




// void parseMessage(char *buffer, char *plaintext, char *key, int connectionSocket) {
//   memset(plaintext, '\0', 1024);
//   memset(key, '\0', 1024);

//   // ** Debugging: Print raw message before parsing **
//   printf("SERVER: Raw buffer before parsing:\n---START---\n%s\n---END---\n", buffer);
//   fflush(stdout);

//   // ** Step 1: Find the first newline **
//   char *newlinePos = strchr(buffer, '\n');
//   if (newlinePos != NULL) {
//       // ** Step 2: Extract plaintext (everything before the newline) **
//       size_t plaintextLength = newlinePos - buffer;
//       strncpy(plaintext, buffer, plaintextLength);
//       plaintext[plaintextLength] = '\0';  // Null-terminate

//       // ** Debugging Output: Print extracted plaintext **
//       printf("SERVER: Extracted plaintext: \"%s\"\n", plaintext);
//       fflush(stdout);
//   } else {
//       printf("SERVER ERROR: No newline found in received message!\n");
//       fflush(stdout);
//       close(connectionSocket);
//       exit(1);
//   }
// }



// Function to extract plaintext (everything before the first newline)
void extractPlaintext(char *buffer, char *plaintext, int connectionSocket) {
  memset(plaintext, '\0', 1024);

  printf("SERVER: Raw buffer before extracting plaintext:\n---START---\n%s\n---END---\n", buffer);
  fflush(stdout);

  // ** Step 1: Find the first newline **
  char *newlinePos = strchr(buffer, '\n');
  if (newlinePos != NULL) {
      // ** Step 2: Extract plaintext (everything before the newline) **
      size_t plaintextLength = newlinePos - buffer;
      strncpy(plaintext, buffer, plaintextLength);
      plaintext[plaintextLength] = '\0';  // Null-terminate

      // ** Debugging Output: Print extracted plaintext **
      printf("SERVER: Extracted plaintext: \"%s\"\n", plaintext);
      fflush(stdout);
  } else {
      printf("SERVER ERROR: No newline found in received message!\n");
      fflush(stdout);
      close(connectionSocket);
      exit(1);
  }
}

// Function to extract key (everything after the first newline)
void extractKey(char *buffer, char *key, int connectionSocket) {
  memset(key, '\0', 1024);

  // ** Step 1: Find the first newline **
  char *newlinePos = strchr(buffer, '\n');
  if (newlinePos != NULL) {
      // ** Step 2: Extract key (everything after the newline) **
      char *keyStart = newlinePos + 1;  // Move past the newline
      strncpy(key, keyStart, 1023);  // Copy remaining data
      key[1023] = '\0';  // Null-terminate just in case

      // ** Debugging Output: Print extracted key **
      printf("SERVER: Extracted key: \"%s\"\n", key);
      fflush(stdout);
  } else {
      printf("SERVER ERROR: No newline found when extracting key!\n");
      fflush(stdout);
      close(connectionSocket);
      exit(1);
  }
}

void parseMessage(char *buffer, char *plaintext, char *key, int connectionSocket) {
  extractPlaintext(buffer, plaintext, connectionSocket);
  extractKey(buffer, key, connectionSocket);
}


///////////////////////////













// Encryption algorithm
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

      printf("Decrypting: ciphertext[%d] = '%c' (%d), key[%d] = '%c' (%d) -> plaintext[%d] = '%c' (%d)\n",
      i, ciphertext[i], cipherVal, 
      i, key[i], keyVal, 
      i, plaintext[i], plainVal);
  }

  plaintext[length] = '\n';
  plaintext[length + 1] = '\0';
}


//////////////////////////////////////////////////////////////////////////////////////////////









int main(int argc, char *argv[]) {
  int connectionSocket;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 
  
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }

  setupAddressStruct(&serverAddress, atoi(argv[1]));

  if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  listen(listenSocket, 5);
  
  while (1) {
    connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
    if (connectionSocket < 0) {
        error("ERROR on accept");
    }

    printf("SERVER: Connected to client running at port %d\n", ntohs(clientAddress.sin_port));

    pid_t spawnPid = fork();

    switch (spawnPid) {
        case -1:
            printf("ERROR on fork\n");
            break;

        case 0:
          close(listenSocket);

          char buffer[1024];
          receiveMessage(connectionSocket, buffer, sizeof(buffer));

          char ciphertext[1024], key[1024];
          parseMessage(buffer, ciphertext, key, connectionSocket);

          char plaintext[1024] = {0};

          printf("SERVER: Decrypting message...\n");
          decryptMessage(ciphertext, key, plaintext);

          sendMessage(connectionSocket, plaintext);

          close(connectionSocket);
          exit(0);

        default:
            close(connectionSocket);
            break;
    }
  }
  
  close(listenSocket);
  return 0;
}