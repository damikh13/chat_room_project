#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <algorithm>
#include <map>

// HEADER FILES
#include "ChatRoom.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

const int MAX_CLIENTS = 5;
const int PORT_NUMBER = 8080;
const int BUFFER_SIZE = 1024; // TODO: change to this instead of sizeof(recv_buffer)

// Function to receive data from a client socket
int receive_data(int client_socket, char* buffer, size_t buffer_size, std::string& received_data, Logger& logger)
{
    memset(buffer, 0, buffer_size);
    int bytes_read = recv(client_socket, buffer, buffer_size, 0);
    if (bytes_read > 0) // TODO: handle this better
    {
        received_data = std::string(buffer, bytes_read);
    }
    return bytes_read;
}

int main()
{
    // ---------------------------------------------------------------------------
    // LOGGING
    Logger logger("server.log", Logger::log_level::DEBUG);
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // CONNECTION
    // Create a server socket
    logger.log(Logger::log_level::DEBUG, "Creating server socket...");
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    bool socket_created = (server_socket != -1);
    if (!socket_created) // check if socket was created successfully
    {
        logger.log(Logger::log_level::ERROR, "Error creating server socket");
        return 1;
    }
    logger.log(Logger::log_level::DEBUG, "...Server socket created");

    // Bind the socket to an IP address and port
    logger.log(Logger::log_level::DEBUG, "Binding server socket...");
    struct sockaddr_in server_address_info; // Set up the server address structure
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(PORT_NUMBER);  // Port number
    server_address_info.sin_addr.s_addr = INADDR_ANY;
    int bind_result = bind(
        server_socket,
        (struct sockaddr*)&server_address_info,
        sizeof(server_address_info)
    );
    bool bind_success = (bind_result != -1);
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
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // MAIN SERVER LOOP
    TSQueue<Message> input_queue; // for server input (e.g., commands)
    TSQueue<Message> output_queue; // for server output (e.g., messages to clients)

    std::vector<int> client_sockets; // to store client sockets
    std::map<int, User> connected_clients; // to store connected clients (key: socket, value: User object)

    // Input thread (for server input, e.g., commands)
    // TODO: remove this thread and use the main thread instead?
    std::thread input_thread([&input_queue, &logger]()
        {
            std::string server_input;
            while (true)
            {
                // Read server commands or other input and push them to the input_queue
                std::getline(std::cin, server_input);
                logger.log(Logger::log_level::DEBUG, "Server input: " + server_input);
                Message server_message(server_input, "server");
                input_queue.push(server_message);
            }
        }
    );
    input_thread.detach(); // TODO: need to detach this thread?

    // Output thread (for broadcasting messages to clients)
    std::thread output_thread([&output_queue, &connected_clients, &logger]()
        {
            while (true)
            {
                if (!output_queue.empty())
                {
                    Message message = output_queue.pop();

                    // Check if the message is an exit message
                    bool client_disconnected = (message.get_content() == "exit");
                    if (client_disconnected)
                    {
                        // Message is an exit message, so remove the client from the connected_clients map
                        auto it = std::find_if(connected_clients.begin(), connected_clients.end(),
                            [&message](const std::pair<int, User>& client)
                            {
                                return client.second.get_username() == message.get_sender();
                            });

                        if (it != connected_clients.end())
                        {
                            connected_clients.erase(it);
                        }

                        message.set_content("Client [" + message.get_sender() + "] disconnected.");
                        message.set_sender("server");
                    }
                    logger.log(Logger::log_level::DEBUG, "Broadcasting message: " + message.to_string() + "...");

                    for (const auto& client : connected_clients)
                    {
                        // check if the client that sent the message is the same as the client we're broadcasting to
                        // if so, skip this client
                        bool same_client = (client.second.get_username() == message.get_sender());
                        if (client.second.get_username() == message.get_sender())
                        {
                            continue;
                        }

                        bool send_success = (send(
                            client.first,
                            message.to_string().c_str(),
                            message.to_string().size(),
                            0) != -1);
                        if (!send_success)
                        {
                            logger.log(Logger::log_level::ERROR, "Error sending data to client");
                        }
                        logger.log(Logger::log_level::DEBUG, "...Message broadcasted to client " + std::to_string(client.first));
                    }
                }
            }
        });
    output_thread.detach(); // detach the output thread so it can run independently

    // std::map<int, User> connected_clients; // to store connected clients (key: socket, value: User object)
    while (true) // Accept incoming connections
    {
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

        std::string credentials;
        char recv_buffer[BUFFER_SIZE];
        int credentials_bytes = receive_data(client_socket, recv_buffer, sizeof(recv_buffer), credentials, logger);
        if (credentials_bytes == 0)
        {
            logger.log(Logger::log_level::ERROR, "Client disconnected");
        }
        else if (credentials_bytes == -1)
        {
            logger.log(Logger::log_level::ERROR, "Error receiving credenttials from client");
        }

        // divide credentials into username and password, format: 'username:password'
        std::string username = credentials.substr(0, credentials.find(':'));
        std::string password = credentials.substr(credentials.find(':') + 1);
        connected_clients[client_socket] = User(username, password);
        logger.log(Logger::log_level::DEBUG, "Client connected: " + username + ":" + password);

        logger.log(Logger::log_level::DEBUG, "Creating client thread...");
        // Create a thread for each client
        // Received client messages will be pushed to the output_queue
        std::thread client_thread([client_socket, &output_queue, &logger, &connected_clients]()
            {
                char recv_buffer[BUFFER_SIZE];
                size_t recv_buffer_size = sizeof(recv_buffer);
                std::string message_content;
                while (true)
                {
                    int received_message_bytes = receive_data(client_socket, recv_buffer, recv_buffer_size, message_content, logger);

                    // Check if the client disconnected
                    // it's either if the received message is empty or if the received message is 'exit'
                    bool client_disconnected = (message_content.empty() || message_content == "exit");

                    if (client_disconnected)
                    {
                        logger.log(Logger::log_level::ERROR, "Client disconnected");
                        Message message("exit", connected_clients[client_socket].get_username());
                        output_queue.push(message);
                        break;
                    }
                    else if (received_message_bytes == -1)
                    { // TODO: do nothing?
                        // logger.log(Logger::log_level::ERROR, "Error receiving data from client");
                        // break;
                    }

                    logger.log(Logger::log_level::DEBUG, "Received message from client: " + message_content);
                    Message message(message_content, connected_clients[client_socket].get_username());

                    output_queue.push(message);
                }
            }
        );
        client_thread.detach(); // detach the client thread so it can run independently
    }

    // Close the server socket and join the input thread
    close(server_socket);
    input_thread.join(); // wait for the input thread to finish

    return 0;
}