#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <sstream>
#include "TSQueue.h"

// HEADER FILES
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

// Function to send data to the server
bool send_data(int client_socket, const std::string& data, Logger& logger)
{
    logger.log(
        Logger::log_level::DEBUG,
        "Sending data to server: \"" + data + "\""
    );

    int bytes_sent = send(
        client_socket,
        data.c_str(),
        data.size(),
        0
    );

    bool send_success = (bytes_sent != -1);
    if (!send_success)
    {
        logger.log(Logger::log_level::ERROR, "Error sending data to server");
    }

    return send_success;
}

bool is_valid_message(const std::string& message)
{
    size_t message_length = message.size();
    bool is_valid_length = true;
    if (!(message_length >= 1 && message_length <= 64))
    {
        is_valid_length = false;
    }

    bool contains_only_valid_characters = true;
    for (char c : message)
    {
        if (!(c >= 32))
        {
            contains_only_valid_characters = false;
            break;
        }
    }

    bool proper_ending = true;
    if (!(message[message_length - 1] == '.' || message[message_length - 1] == '!' || message[message_length - 1] == '?'))
    {
        proper_ending = false;
    }

    return is_valid_length && contains_only_valid_characters && proper_ending;
}

// CONNECTION HELPERS
inline int create_client_socket(Logger& logger)
{
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1)
    {
        logger.log(Logger::log_level::ERROR, "Error creating client socket");
    }
    return client_socket;
}
inline void set_read_timeout(int client_socket, timeval& read_timeout)
{
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
}
inline sockaddr_in setup_server_address_info(const int& PORT_NUMBER, const std::string& IP_ADDRESS)
{
    sockaddr_in server_address_info;
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(PORT_NUMBER);
    server_address_info.sin_addr.s_addr = inet_addr(IP_ADDRESS.c_str());
    inet_pton(AF_INET, IP_ADDRESS.c_str(), &server_address_info.sin_addr);
    return server_address_info;
}
inline bool connect_to_server(int client_socket, sockaddr_in& server_address_info, Logger& logger)
{
    int connect_result = connect(client_socket, (struct sockaddr*)&server_address_info, sizeof(server_address_info));
    if (connect_result == -1)
    {
        std::cout << "Error connecting to the server" << std::endl;
        logger.log(Logger::log_level::ERROR, "Error connecting to the server");
        close(client_socket);
        return false;
    }
    else
    {
        logger.log(Logger::log_level::DEBUG, "Connected to server");
        return true;
    }
}

// AUTHORIZATION HELPERS
inline std::string get_user_input()
{
    std::string input;
    std::getline(std::cin, input);
    return input;
}
inline std::string create_handshake_message(const std::string& user_type, const std::string& username, const std::string& password, int chat_history_size)
{
    return user_type + ":" + username + ":" + password + ":" + std::to_string(chat_history_size);
}
inline void send_handshake_message(int client_socket, const std::string& handshake_message, Logger& logger)
{
    send_data(client_socket, handshake_message, logger);
    logger.log(Logger::log_level::DEBUG, "Sent handshake message to server");
}
inline std::string receive_server_response(int client_socket, Logger& logger, const int& BUFFER_SIZE)
{
    char recv_buffer[BUFFER_SIZE];
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int bytes_read = recv(client_socket, recv_buffer, sizeof(recv_buffer), 0);
    if (bytes_read > 0)
    {
        return std::string(recv_buffer, bytes_read - 1); // skip ';' delimiter
    }
    else
    {
        logger.log(Logger::log_level::ERROR, "Error receiving data from server");
        return "";
    }
}
void handle_new_user_registration(int client_socket, const std::string& username, Logger& logger, int CHAT_HISTORY_SIZE)
{
    logger.log(Logger::log_level::DEBUG, "New user");
    std::cout << "Enter password your new password: ";
    std::string password = get_user_input();
    std::cout << std::endl;

    std::string handshake_message = "new_user:" + username + ":" + password + ":" + std::to_string(CHAT_HISTORY_SIZE);
    send_handshake_message(client_socket, handshake_message, logger);
}
bool process_server_response(std::string& server_message, TSQueue<std::string>& output_queue, int client_socket)
{
    bool authorized = false;
    bool password_was_correct = (server_message.find("User exists. Welcome back!") != std::string::npos);
    bool password_was_incorrect = (server_message.find("User does not exist. Please, try again.") != std::string::npos);
    bool too_many_authentication_attempts = (server_message.find("Too many authentication attempts. Disconnecting...") != std::string::npos);
    bool credentials_already_in_use = (server_message.find("Credentials already in use. Please, try again.") != std::string::npos);

    if (password_was_correct)
    {
        authorized = true;

        // print first part of the message (up to and including the first ';')
        std::cout << std::endl;
        std::cout << server_message.substr(0, server_message.find(';')) << std::endl;

        // remove first part of the message (up to and including the first ';')
        server_message.erase(0, server_message.find(';') + 1);

        // push the rest of the message (chat history) to the output queue
        output_queue.push(server_message);
    }
    else if (password_was_incorrect)
    {
        std::cout << "User does not exist. Please, try again." << std::endl;
    }
    else if (too_many_authentication_attempts)
    {
        std::cout << "Too many authentication attempts. Disconnecting..." << std::endl;
        close(client_socket);
        return false;
    }
    else if (credentials_already_in_use)
    {
        std::cout << "Credentials already in use. Please, try again." << std::endl;
        close(client_socket);
        return false;
    }

    return authorized;
}
bool handle_existing_user(int client_socket, const std::string& username, Logger& logger, int CHAT_HISTORY_SIZE, TSQueue<std::string>& output_queue, size_t BUFFER_SIZE)
{
    logger.log(Logger::log_level::DEBUG, "Existing user");
    std::string handshake_message;
    bool password_authenticated = false;

    while (true)
    {
        // Get client password
        std::cout << "Enter password: ";
        std::string password_attempt = get_user_input();

        // Send handshake message with client password to server
        handshake_message = "existing_user:" + username + ":" + password_attempt + ":" + std::to_string(CHAT_HISTORY_SIZE);
        send_handshake_message(client_socket, handshake_message, logger);

        // Receive server response
        usleep(100000); // TODO: make this better
        logger.log(Logger::log_level::DEBUG, "Receiving message from server...");
        std::string server_message = receive_server_response(client_socket, logger, BUFFER_SIZE);
        if (server_message.empty())
        {
            continue;
        }

        logger.log(Logger::log_level::DEBUG, "...Received message from server: " + server_message);

        bool password_was_correct = (server_message.find("User exists. Welcome back!") != std::string::npos);
        bool password_was_incorrect = (server_message.find("User does not exist. Please, try again.") != std::string::npos);
        bool too_many_authentication_attempts = (server_message.find("Attempts left: 0") != std::string::npos);
        bool credentials_already_in_use = (server_message.find("Credentials already in use. Please, try again.") != std::string::npos);

        if (password_was_correct)
        {
            password_authenticated = true;
            std::cout << std::endl;

            // print first part of the message (up to and including the first ';')
            std::cout << server_message.substr(0, server_message.find(';')) << std::endl;

            // remove first part of the message (up to and including the first ';')
            server_message.erase(0, server_message.find(';') + 1);

            // push the rest of the message (chat history) to the output queue
            output_queue.push(server_message);
            break;
        }
        else if (too_many_authentication_attempts)
        {
            std::cout << "Too many authentication attempts. Disconnecting..." << std::endl;
            close(client_socket);
            return false;
        }
        else if (password_was_incorrect)
        {
            std::cout << server_message << std::endl;
        }
        else if (credentials_already_in_use)
        {
            std::cout << "Credentials already in use. Please, try again." << std::endl;
            close(client_socket);
            return false;
        }
    }

    return password_authenticated;
}

// MAIN CLIENT LOGIC HELPERS
void handle_user_input(TSQueue<std::string>& input_queue, Logger& logger, bool& disconnect)
{
    std::string user_input;
    while (true)
    {
        std::getline(std::cin, user_input);

        if (user_input == "exit")
        {
            disconnect = true;
            input_queue.push(user_input);
            logger.log(Logger::log_level::DEBUG, "Pushed user input \"" + user_input + "\" to input_queue");
            break;
        }

        bool valid_message = is_valid_message(user_input);
        if (!valid_message)
        {
            std::cout << "Invalid message. Please, try again" << std::endl;
            continue;
        }

        input_queue.push(user_input);
        logger.log(Logger::log_level::DEBUG, "Pushed user input \"" + user_input + "\" to input_queue");
    }
}
void send_user_input(int client_socket, TSQueue<std::string>& input_queue, Logger& logger, bool& disconnect)
{
    if (!input_queue.empty())
    {
        std::string user_input = input_queue.pop();
        logger.log(Logger::log_level::DEBUG, "Popped user input \"" + user_input + "\" from input_queue, sending to server...");

        bool message_sent = send_data(client_socket, user_input, logger);
        if (message_sent)
        {
            logger.log(Logger::log_level::DEBUG, "...Sent user input to server");
        }
        if (disconnect)
        {
            return;
        }
    }
}
void handle_server_messages(int client_socket, TSQueue<std::string>& output_queue, Logger& logger, size_t BUFFER_SIZE)
{
    char recv_buffer[BUFFER_SIZE];
    memset(recv_buffer, 0, sizeof(recv_buffer));
    int bytes_read = recv(client_socket, recv_buffer, sizeof(recv_buffer), 0);

    if (bytes_read > 0)
    {
        logger.log(Logger::log_level::DEBUG, "...Received message from server: \"" + std::string(recv_buffer, bytes_read) + "\""
            + ", pushing to output_queue...");
        std::string server_message(recv_buffer, bytes_read);
        output_queue.push(server_message);
    }
}
void display_chat(TSQueue<std::string>& output_queue, Logger& logger)
{
    while (!output_queue.empty())
    {
        std::string messages_with_delimiter = output_queue.pop();
        std::stringstream ss(messages_with_delimiter);

        std::string actual_message;
        while (std::getline(ss, actual_message, ';'))
        {
            if (!actual_message.empty()) // To avoid printing empty lines due to trailing delimiter
            {
                std::cout << actual_message << std::endl;
                logger.log(Logger::log_level::DEBUG, "Displayed message from server: " + actual_message);
            }
            if ("End of chat history." == actual_message)
            {
                std::cout << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[])
{
    // ---------------------------------------------------------------------------
    // ARGUMENT PARSING
    if (argc != 3)
    {
        std::cout << "Usage: " << argv[0] << " <config_file_path> <log_file_path>" << std::endl;
        return 1;
    }

    std::string config_file_path(argv[1]);
    std::string log_file_path(argv[2]);
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // LOGGING
    Logger logger(log_file_path, Logger::log_level::DEBUG);
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // CONFIG PARSING
    ConfigParser config_parser(config_file_path, logger);
    std::string username = config_parser.get_string("USERNAME");                // Username
    const int PORT_NUMBER = config_parser.get_int("PORT_NUMBER");               // Port number
    const int BUFFER_SIZE = config_parser.get_int("BUFFER_SIZE");               // Size of the buffer for receiving data from the server
    const int CHAT_HISTORY_SIZE = config_parser.get_int("CHAT_HISTORY_SIZE");   // Number of messages to display when a user joins the chat
    const std::string IP_ADDRESS = config_parser.get_string("IP_ADDRESS");      // IP address of the server
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // CONNECTION

    // Create a client socket
    int client_socket = create_client_socket(logger);
    bool socket_created = (client_socket != -1);
    if (!socket_created)
    {
        return 1;
    }

    // Set read timeout
    timeval read_timeout;
    set_read_timeout(client_socket, read_timeout);

    // Set up the server address structure
    sockaddr_in server_address_info = setup_server_address_info(PORT_NUMBER, IP_ADDRESS);

    // Connect to the server
    bool connected_to_server = connect_to_server(client_socket, server_address_info, logger);
    if (!connected_to_server)
    {
        return 1;
    }
    // ---------------------------------------------------------------------------


    // Create thread-safe queues for input and output messages
    TSQueue<std::string> input_queue; // for user input
    TSQueue<std::string> output_queue; // for server messages

    // ---------------------------------------------------------------------------
    // AUTHORIZATION
    bool password_authenticated = false;
    std::cout << "Welcome to the chat room!" << std::endl;
    std::string password;
    std::string handshake_message;
    logger.log(Logger::log_level::DEBUG, "Asking user if they are a new user or an existing user...");
    std::cout << "Are you a new user? (y/n): ";
    while (true)
    {
        std::string answer = get_user_input();
        char first_answer_char = answer[0];
        if (first_answer_char == 'y' || first_answer_char == 'Y') // new user
        {
            logger.log(Logger::log_level::DEBUG, "...New user");
            handle_new_user_registration(client_socket, username, logger, CHAT_HISTORY_SIZE);
        }
        else if (first_answer_char == 'n' || first_answer_char == 'N') // existing user
        {
            logger.log(Logger::log_level::DEBUG, "...Existing user");
            bool password_authenticated = handle_existing_user(client_socket, username, logger, CHAT_HISTORY_SIZE, output_queue, BUFFER_SIZE);
            if (!password_authenticated)
            {
                return 1;
            }
        }
        else // invalid input
        {
            std::cout << std::endl;
            std::cout << "Invalid input. Please, try again." << std::endl;
            std::cout << "Are you a new user? (y/n): ";
        }
    }
    logger.log(Logger::log_level::DEBUG, "Sent handshake message to server");
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // MAIN CLIENT LOGIC

    // Create a thread to handle user input
    bool disconnect = false;
    std::thread input_thread(handle_user_input, std::ref(input_queue), std::ref(logger), std::ref(disconnect));

    // Main client loop
    while (true)
    {
        // Send existing user's input to the server
        send_user_input(client_socket, input_queue, logger, disconnect);
        if (disconnect)
        {
            break;
        }

        // Push server messages to the output queue
        handle_server_messages(client_socket, output_queue, logger, BUFFER_SIZE);

        // Display chat (if there are any messages in the output queue)
        display_chat(output_queue, logger);
    }
    // ---------------------------------------------------------------------------

    // Close the socket and join the input thread
    close(client_socket);
    input_thread.join();

    return 0;
}