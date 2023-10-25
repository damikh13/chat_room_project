#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>

// HEADER FILES
#include "ChatRoom.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error creating client socket" << std::endl;
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);  // Port number
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);  // Server's IP address

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error connecting to the server" << std::endl;
        close(clientSocket);
        return 1;
    }

    const char* message = "Hello, Server!";
    if (send(clientSocket, message, strlen(message), 0) == -1) {
        std::cerr << "Error sending data" << std::endl;
        close(clientSocket);
        return 1;
    }

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Create thread-safe queues for input and output messages
    TSQueue<std::string> inputQueue;
    TSQueue<std::string> outputQueue;

    // Input thread
    std::thread inputThread([&inputQueue]() {
        std::string userInput;
        while (true) {
            std::getline(std::cin, userInput);
            inputQueue.push(userInput);
        }
        });

    // Main client logic
    while (true) {
        // Check for user input
        if (!inputQueue.empty()) {
            std::string userInput = inputQueue.pop();
            if (send(clientSocket, userInput.c_str(), userInput.size(), 0) == -1) {
                std::cerr << "Error sending data" << std::endl;
                break;
            }
        }

        // Check for server messages
        char recvBuffer[1024];
        memset(recvBuffer, 0, sizeof(recvBuffer));
        int bytesRead = recv(clientSocket, recvBuffer, sizeof(recvBuffer), 0);
        if (bytesRead == -1) {
            std::cerr << "Error receiving data" << std::endl;
            break;
        }
        else if (bytesRead > 0) {
            std::string serverMessage(recvBuffer, bytesRead);
            outputQueue.push(serverMessage);
        }

        // Display chat history
        // TODO: Display chat history properly
        while (!outputQueue.empty()) {
            std::string message = outputQueue.pop();
            std::cout << "Received: " << message << std::endl;
        }
    }

    // Close the socket and join the input thread
    close(clientSocket);
    inputThread.join();

    return 0;
}
