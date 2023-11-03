#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <deque>
#include <map>
#include <algorithm>
#include <thread>
#include <sstream>

// HEADER FILES
#include "ChatRoom.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

const int MAX_CLIENTS = 5;
const int PORT_NUMBER = 2048; // TODO: put this in a 
const size_t BUFFER_SIZE = 1024;
const int MAX_HISTORY_SIZE = 10;
const int NUM_AUTH_ATTEMPTS = 3; // TODO: make this configurable

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

inline void chat_history_push(std::deque<Message>& chat_history, const Message& message)
{
    if (chat_history.size() == MAX_HISTORY_SIZE)
    {
        chat_history.pop_front();
    }
    chat_history.push_back(message);
}

void send_data(int socket, const std::string& data, Logger& logger)
{
    std::string data_with_delimiter = data + ";";
    bool send_success = (send(socket, data_with_delimiter.c_str(), data_with_delimiter.size(), 0) != -1);
    if (!send_success)
    {
        logger.log(Logger::log_level::ERROR, "Error sending data to client");
    }
}

void split(const std::string& string_to_split, char delimiter, std::vector<std::string>& result)
{
    std::stringstream ss(string_to_split);
    std::string token;
    while (std::getline(ss, token, delimiter))
    {
        result.push_back(token);
    }
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

    std::deque<Message> chat_history;

    // Input thread (for server input, e.g., commands)
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
    input_thread.detach();

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
                        if (same_client)
                        {
                            continue;
                        }

                        // handle the case when the message is 

                        send_data(client.first, message.to_string(), logger);

                        logger.log(Logger::log_level::DEBUG, "...Message broadcasted to client " + std::to_string(client.first));
                    }
                }
            }
        });
    output_thread.detach(); // detach the output thread so it can run independently

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
        logger.log(Logger::log_level::DEBUG, "Client connected");

        std::string handshake_message;
        char recv_buffer[BUFFER_SIZE];
        // int handshake_message_bytes = receive_data(client_socket, recv_buffer, sizeof(recv_buffer), handshake_message, logger);
        int handshake_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, handshake_message, logger);
        if (handshake_message_bytes == 0)
        {
            logger.log(Logger::log_level::ERROR, "Client disconnected");
        }
        else if (handshake_message_bytes == -1)
        {
            logger.log(Logger::log_level::ERROR, "Error receiving handshake message from client");
        }
        logger.log(Logger::log_level::DEBUG, "Handshake message: \"" + handshake_message + "\"");

        // parse the handshake message
        std::vector<std::string> initial_message_split;
        split(handshake_message, ':', initial_message_split);
        std::string new_or_existing_user = initial_message_split[0];
        std::string username = initial_message_split[1];
        std::string password = initial_message_split[2];
        std::string client_chat_history_size_str = initial_message_split[3];

        // check if there is already a client with the same credentials
        bool username_already_taken = false;
        for (const auto& client : connected_clients)
        {
            if (client.second.get_username() == username)
            {
                username_already_taken = true;
                break;
            }
        }

        if (username_already_taken)
        {
            send_data(client_socket, "Credentials already in use. Please, try again.", logger);
            close(client_socket);
            continue;
        }

        connected_clients[client_socket] = User(username, password);
        logger.log(Logger::log_level::DEBUG, "Client connected: " + username + ":" + password);
        Message connected_info_message("Client [" + username + "][" + new_or_existing_user + "] connected.", "server");

        // get chat history size from client
        int cilent_chat_history_size = std::stoi(client_chat_history_size_str);
        int chat_history_size_to_send = std::min(cilent_chat_history_size, (int)chat_history.size());

        if (new_or_existing_user == "existing_user")
        {
            logger.log(Logger::log_level::DEBUG, "Reading database...");
            std::ifstream database_file("database.txt"); // TODO: make this configurable
            std::map<std::string, std::string> database;
            while (getline(database_file, handshake_message))
            {
                std::vector<std::string> handshake_message_split;
                split(handshake_message, ':', handshake_message_split);
                database[handshake_message_split[0]] = handshake_message_split[1];
            }
            database_file.close();
            logger.log(Logger::log_level::DEBUG, "...Database read");

            bool user_exists = false;
            for (int i = 0; i < NUM_AUTH_ATTEMPTS - 1; ++i) // TODO: explain why -1
            {
                // Check if the username and password match the database
                logger.log(Logger::log_level::DEBUG, "Checking if user[" + username + ":" + password + "] exists...");
                user_exists = (database.find(username) != database.end() && database[username] == password);

                if (user_exists)
                {
                    logger.log(Logger::log_level::DEBUG, "User exists");
                    send_data(client_socket, "User exists. Welcome back!", logger);
                    break;
                }
                else
                {
                    logger.log(Logger::log_level::DEBUG, "User does not exist, asking for new password...");
                    send_data(client_socket, "User does not exist. Please, try again.", logger);

                    // receive new password from client
                    std::string new_handshake_message;
                    char recv_buffer[BUFFER_SIZE];
                    // int new_handshake_message_bytes = receive_data(client_socket, recv_buffer, sizeof(recv_buffer), new_handshake_message, logger);
                    int new_handshake_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, new_handshake_message, logger);
                    if (new_handshake_message_bytes == 0)
                    {
                        logger.log(Logger::log_level::ERROR, "Client disconnected");
                        // TODO: close the client socket
                    }

                    // parse the new handshake message
                    std::vector<std::string> new_initial_message_split;
                    split(new_handshake_message, ':', new_initial_message_split);
                    password = new_initial_message_split[2];

                    logger.log(Logger::log_level::DEBUG, "New handshake message: \"" + new_handshake_message + "\"");
                }
            }
            if (!user_exists)
            {
                send_data(client_socket, "Too many authentication attempts. Disconnecting...", logger);
                close(client_socket);
                continue;
            }
            else
            {
                send_data(client_socket, "Chat history [" + client_chat_history_size_str + "]:", logger);
                for (int i = 0; i < chat_history_size_to_send; ++i)
                {
                    send_data(client_socket, chat_history[i].to_string(), logger);
                }
                if (cilent_chat_history_size < chat_history.size())
                {
                    send_data(client_socket, "Chat history is too large to send. Please, increase CHAT_HISTORY_SIZE in the config file.", logger);
                }
                send_data(client_socket, "End of chat history.", logger);
            }
        }
        else if (new_or_existing_user == "new_user")
        {
            logger.log(Logger::log_level::DEBUG, "Writing new user's info: " + username + ":" + password + " to database");
            std::ofstream database_file("database.txt", std::ios_base::app); // TODO: make this configurable
            database_file << username << ":" << password << std::endl;
        }

        chat_history_push(chat_history, connected_info_message);
        output_queue.push(connected_info_message); // push the message to the output_queue so it can be broadcasted to all clients

        // Create a thread for each client
        // Received client messages will be pushed to the output_queue
        logger.log(Logger::log_level::DEBUG, "Creating client thread...");
        std::thread client_thread([client_socket, &output_queue, &logger, &connected_clients, &chat_history]()
            {
                char recv_buffer[BUFFER_SIZE];
                // size_t recv_buffer_size = sizeof(recv_buffer);

                std::string message_content;
                while (true)
                {
                    int received_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, message_content, logger);

                    // Check if the client disconnected
                    // it's either if the received message is empty or if the received message is 'exit'
                    bool client_disconnected = (received_message_bytes == 0 || message_content == "exit");

                    if (client_disconnected)
                    {
                        logger.log(Logger::log_level::ERROR, "Client disconnected");
                        Message message("exit", connected_clients[client_socket].get_username());
                        output_queue.push(message);
                        chat_history_push(chat_history, message);
                        break;
                    }
                    else if (received_message_bytes == -1)
                    {
                        continue;
                    }

                    logger.log(Logger::log_level::DEBUG, "Received message from client: " + message_content);
                    Message message(message_content, connected_clients[client_socket].get_username());

                    output_queue.push(message);
                    chat_history_push(chat_history, message);
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