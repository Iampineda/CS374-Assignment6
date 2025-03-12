#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(), recv()
#include <netdb.h>      // gethostbyname()

// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
  exit(1); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);

  // Get the DNS entry for this host name
  struct hostent* hostInfo = gethostbyname(hostname); 
  if (hostInfo == NULL) { 
    fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
    exit(1); 
  }
  // Copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

int main(int argc, char *argv[]) {
  int socketFD, charsWritten, charsRead;
  struct sockaddr_in serverAddress;
  char buffer[8192]; // Increased buffer size for large messages

  // Check usage & args
  if (argc < 5) { 
    fprintf(stderr,"USAGE: %s hostname port plaintext key\n", argv[0]); 
    exit(1); 
  }

  // Check that the key is at least as long as the plaintext
  if (strlen(argv[4]) < strlen(argv[3])) {
    fprintf(stderr, "ERROR: Key is too short\n");
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

  // Handshake: Send client type
  charsWritten = send(socketFD, "ENC_CLIENT", 10, 0);
  if (charsWritten < 0) {
    error("CLIENT: ERROR sending handshake");
  }

  // Handshake: Receive confirmation from the server
  char handshakeMsg[16];
  memset(handshakeMsg, '\0', sizeof(handshakeMsg));

  charsRead = recv(socketFD, handshakeMsg, sizeof(handshakeMsg) - 1, 0);
  if (charsRead < 0) {
    error("CLIENT: ERROR receiving handshake");
  }
  if (strncmp(handshakeMsg, "ENC_SERVER", 10) != 0) {
    fprintf(stderr, "CLIENT: ERROR - connected to wrong server\n");
    close(socketFD);
    exit(2);
  }

  // Prepare the message to send
  memset(buffer, '\0', sizeof(buffer));
  snprintf(buffer, sizeof(buffer), "%s %s", argv[3], argv[4]);

  // Send message to server
  int totalSent = 0, messageLen = strlen(buffer);
  while (totalSent < messageLen) {
    charsWritten = send(socketFD, buffer + totalSent, messageLen - totalSent, 0);
    if (charsWritten < 0){
      error("CLIENT: ERROR writing to socket");
    }
    if (charsWritten == 0) break;  
    totalSent += charsWritten;
  }

  // Get return message from server
  memset(buffer, '\0', sizeof(buffer));

  int totalReceived = 0;
  while (totalReceived < sizeof(buffer) - 1) {
    charsRead = recv(socketFD, buffer + totalReceived, sizeof(buffer) - 1 - totalReceived, 0);
    if (charsRead < 0) {
      error("CLIENT: ERROR reading from socket");
    }
    if (charsRead == 0) break; 
    totalReceived += charsRead;
  }

  buffer[totalReceived] = '\0';  
  // Print the encrypted message 
  printf("%s\n", buffer);

  // Close the socket
  close(socketFD); 
  return 0;
}
