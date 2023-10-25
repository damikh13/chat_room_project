#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <algorithm>

// HEADER FILES
#include "ChatRoom.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

const int MAX_CLIENTS = 5;

int main()
{
    // LOGGING
    Logger logger(Logger::log_level::DEBUG);

    // CONNECTION
    // Create a server socket
    logger.log(Logger::log_level::DEBUG, "Creating server socket...");
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    bool socket_created = (server_socket != -1);
    // check if socket() was successful
    if (!socket_created)
    {
        logger.log(Logger::log_level::ERROR, "Error creating server socket");
        return 1;
    }
    logger.log(Logger::log_level::DEBUG, "...Server socket created");
    // Bind the socket to an IP address and port
    logger.log(Logger::log_level::DEBUG, "Binding server socket...");
    // define the server address
    sockaddr_in server_address_info;
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(12345);  // Port number
    server_address_info.sin_addr.s_addr = INADDR_ANY;
    // call bind()
    int bind_result = bind(
        server_socket,
        (struct sockaddr*)&server_address_info,
        sizeof(server_address_info)
    );
    bool bind_success = (bind_result != -1);
    // check if bind() was successful
    if (!bind_success)
    {
        logger.log(Logger::log_level::ERROR, "Error binding server socket");
        close(server_socket);
        return 1;
    }
    logger.log(Logger::log_level::DEBUG, "...Server socket bound");

    // Listen for incoming connections
    logger.log(Logger::log_level::DEBUG, "Listening on server socket...");
    int listen_result = listen(server_socket, MAX_CLIENTS);
    bool listen_success = (listen_result != -1);
    if (!listen_success)
    {
        logger.log(Logger::log_level::ERROR, "Error listening on server socket");
        close(server_socket);
        return 1;
    }
    logger.log(Logger::log_level::DEBUG, "...Server socket listening");

    // CHAT ROOM
    // Create thread-safe queues for input and output messages
    TSQueue<std::string> input_queue; // for server input and client messages
    TSQueue<std::string> output_queue; // for server output

    std::vector<int> client_sockets; // To store client sockets

    // Input thread (for server input, e.g., commands)
    std::thread input_thread([&input_queue, &logger]()
        {
            std::string server_input;
            while (true)
            {
                // Read server commands or other input and push them to the input_queue
                std::getline(std::cin, server_input);
                logger.log(Logger::log_level::DEBUG, "Server input: " + server_input);
                input_queue.push(server_input);
            }
        }
    );
    // TODO: need to join this thread? or detach it? or something else?

    while (true)
    {
        // Accept incoming client connections
        logger.log(Logger::log_level::DEBUG, "Accepting client connection...");
        sockaddr_in client_address_info;
        socklen_t client_address_info_size = sizeof(client_address_info);
        int client_socket = accept(
            server_socket,
            (struct sockaddr*)&client_address_info,
            &client_address_info_size
        );
        bool accept_result = (client_socket != -1);
        if (!accept_result)
        {
            logger.log(Logger::log_level::ERROR, "Error accepting client connection");
            continue;
        }
        logger.log(Logger::log_level::DEBUG, "...Client connection accepted");

        client_sockets.push_back(client_socket);

        logger.log(Logger::log_level::DEBUG, "Creating client thread...");
        std::thread client_thread([client_socket, &input_queue, &output_queue, &logger]()
            {
                char recv_buffer[1024];
                size_t recv_buffer_size = sizeof(recv_buffer);
                memset(recv_buffer, 0, recv_buffer_size);
                while (true)
                {
                    logger.log(Logger::log_level::DEBUG, "Receiving message from client...");
                    int bytes_read = recv(client_socket, recv_buffer, sizeof(recv_buffer), 0);
                    bool recv_success = (bytes_read != -1);
                    if (!recv_success)
                    {
                        logger.log(Logger::log_level::ERROR, "Error receiving data from client");
                        break;
                    }
                    // // TODO: use Message class
                    std::string client_message(recv_buffer, bytes_read);
                    input_queue.push(client_message); // Push client messages to the input_queue
                    logger.log(Logger::log_level::DEBUG, "...Recieved client message: " + client_message + ", Pushed it to the input queue");
                }
            }
        );

        client_thread.detach(); // Detach the client thread

        // Broadcast messages to all clients
        while (true)
        {
            if (!input_queue.empty())
            {
                std::string message = input_queue.pop();
                // Broadcast the message to all connected clients
                for (int socket : client_sockets)
                {
                    bool send_success = (send(socket, message.c_str(), message.size(), 0) != -1);
                    if (!send_success)
                    {
                        logger.log(Logger::log_level::ERROR, "Error sending data to client");
                    }
                }
            }
        }
    }

    // Close the server socket and join the input thread
    close(server_socket);
    input_thread.join();

    return 0;
}
