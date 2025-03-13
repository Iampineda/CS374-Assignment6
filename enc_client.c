
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

    // printf("Sent full message: \"%s\"\n", message);
}

// Function: 
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


// Function: 
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

// Function: 
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


// Function: 
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

// ----------------------------------------------------------------------------------------------


int main(int argc, char *argv[]) {
    int socketFD;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    if (argc < 4) { 
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]); 
        exit(1);
    }

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
    validateKeyLength(argv[1], argv[2]);  // Validate key length before sending
    
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

 enc_server.c
 Download
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 70000

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

///////////////////////////













// Encryption algorithm
void encryptMessage(const char *plaintext, const char *key, char *ciphertext) {
  int length = strlen(plaintext);

  // Ignore newline at the end if present
  if (length > 0 && plaintext[length - 1] == '\n') {
      length--;
  }

  for (int i = 0; i < length; i++) {
      int plainVal, keyVal, cipherVal;

      // Convert plaintext character to numeric value
      plainVal = (plaintext[i] == ' ') ? 26 : (plaintext[i] - 'A');
      keyVal = (key[i] == ' ') ? 26 : (key[i] - 'A');

      // Apply the One-Time Pad encryption formula: (plainVal + keyVal) % 27
      cipherVal = (plainVal + keyVal) % 27;

      // Convert numeric value back to character
      ciphertext[i] = (cipherVal == 26) ? ' ' : ('A' + cipherVal);

      // ** Debugging Output **
      // printf("Encrypting: plaintext[%d] = '%c' (%d), key[%d] = '%c' (%d) -> ciphertext[%d] = '%c' (%d)\n",
      // i, plaintext[i], plainVal, 
      // i, key[i], keyVal, 
      // i, ciphertext[i], cipherVal);
  }

  
  // Add newline at the end (per project requirements)
  ciphertext[length] = '\n';
  ciphertext[length + 1] = '\0';  // Ensure null termination
}




//////////////////////////////////////////////////////////////////////////////////////////////









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


    printf("SERVER: Connected to client running at port %d\n", ntohs(clientAddress.sin_port));

    // Fork to handle the client connection
    pid_t spawnPid = fork();

    switch (spawnPid) {
        case -1:  // Fork failed
            printf("ERROR on fork\n");
            break;

        case 0:  // Child Process
          close(listenSocket); 
          verifyClient(connectionSocket, "ENC_CLIENT", "ENC_SERVER");  // For encryption server
          // ** Step 1: Receive the full message from the client **
          char buffer[BUFFER_SIZE];
          receiveMessage(connectionSocket, buffer, sizeof(buffer));

          // ** Step 2: Parse plaintext and key **
          char plaintext[BUFFER_SIZE], key[BUFFER_SIZE];
          parseMessage(buffer, plaintext, key, connectionSocket);

  
         // ** Step 3: Encrpty Message **
          char ciphertext[BUFFER_SIZE] = {0}; // Buffer for encrypted message

          printf("SERVER: Encrypting message...\n");
          encryptMessage(plaintext, key, ciphertext);

          // ** Step 4: Send the full message to the client ***
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