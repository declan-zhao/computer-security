/********************************************************************
 * Author : Carlos Moreno
 * Created: 2019-06
 *
 * Description:
 *
 *      You may use this file as a sample / starting point for the
 *      server in both questions.  In particular, you are allowed
 *      to submit your code containing verbatim fragments from this
 *      file.
 *
 *      For the most part, although the file is a .c++ file, the
 *      code is also valid C code  (with some exceptions --- pun
 *      intended! :-) )
 *
 * Copyright and permissions:
 *      This file is for the exclusive purpose of our ECE-458
 *      assignment 1, and you are not allowed to use it for any
 *      other purpose.
 *
 ********************************************************************/

#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>

class connection_closed
{
};
class socket_error
{
};

void listen_connections(int port);
void process_connection(int client_socket);
string read_packet(int client_socket);

int main(int argc, char *arg[])
{
    listen_connections(10458);

    return 0;
}

void listen_connections(int port)
{
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_len;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_address.sin_family      = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port        = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
    {
        cout << "Could not bind socket to address:port" << endl;
        throw socket_error();
    }

    listen(server_socket, 5);

    while (true)
    {
        client_len    = sizeof(client_address);
        client_socket = accept(server_socket,
                               (struct sockaddr *)&client_address,
                               &client_len);

        pid_t pid = fork();
        if (pid == 0) // if we're the child process
        {
            close(server_socket); // only the parent listens for new connections

            if (fork() == 0) // detach grandchild process -- parent returns immediately
            {
                usleep(10000); // Allow the parent to finish, so that the grandparent
                               // can continue listening for connections ASAP

                process_connection(client_socket);
            }

            return;
        }

        else if (pid > 0) // parent process; close the socket and continue
        {
            int status = 0;
            waitpid(pid, &status, 0);
            close(client_socket);
        }

        else
        {
            cerr << "ERROR on fork()" << endl;
            return;
        }
    }
}

void process_connection(int client_socket)
{
    try
    {
        const string &username = read_packet(client_socket);
        cout << "Received username: " << username << endl;

        while (true)
        {
            const string &password = read_packet(client_socket);
            cout << "Received password: " << password << endl;
        }

        close(client_socket);
    }
    catch (connection_closed)
    {
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
}

// Defined redundantly in client and server source files --- you may
// want to refactor it as a common function and use it for both.
string read_packet(int client_socket)
{
    string msg;

    const int size = 8192;
    char buffer[size];

    while (true)
    {
        int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 2, 0);
        // Though extremely unlikely in our setting --- connection from
        // localhost, transmitting a small packet at a time --- this code
        // takes care of fragmentation  (one packet arriving could have
        // just one fragment of the transmitted message)

        if (bytes_read > 0)
        {
            buffer[bytes_read]     = '\0';
            buffer[bytes_read + 1] = '\0';

            const char *packet = buffer;
            while (*packet != '\0')
            {
                msg    += packet;
                packet += strlen(packet) + 1;

                if (msg.length() > 1 && msg[msg.length() - 1] == '\n')
                {
                    istringstream buf(msg);
                    string msg_token;
                    buf >> msg_token;
                    return msg_token;
                }
            }
        }

        else if (bytes_read == 0)
        {
            close(client_socket);
            throw connection_closed();
        }

        else
        {
            cerr << "Error " << errno << endl;
            throw socket_error();
        }
    }

    throw connection_closed();
}
