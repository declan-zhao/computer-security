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
#include <iomanip>

#include "custom_utils.h"

string generate_challenge(const string &RH, const string &PH);
bool verify_response(const string &response, const string &R, const string &PH);
void listen_connections(int port);
void process_connection(int client_socket);

int p_bits = 8;

int main(int argc, char *argv[])
{
    if (argc == 2)
    {
        if (atoi(argv[1]) % 4 != 0)
        {
            cerr << "P bits must be multiple of 4, given: " << argv[1] << endl;
            return 0;
        }

        p_bits = atoi(argv[1]);
    }

    listen_connections(17777);

    return 0;
}

string generate_challenge(const string &RH, const string &PH)
{
    string challenge = RH + "/" + PH + "\n";

    cout << "Challenge: " << challenge << endl;

    return challenge;
}

bool verify_response(const string &response, const string &R, const string &PH)
{
    const string &solution = hex_to_string(response);

    if (solution.length() != 48)
    {
        cerr << "The response is not a 384-bit string!" << endl;
        return false;
    }
    else if (solution.find(R) == solution.npos || solution.find(R) != 0)
    {
        cerr << "The response does not start with R!" << endl;
        return false;
    }
    else if (solution.rfind(R) == solution.npos || solution.rfind(R) == 0)
    {
        cerr << "The response does not end with R!" << endl;
        return false;
    }

    string hash;

    if (!get_sha256(solution, hash))
    {
        cerr << "Cannot generate hash!" << endl;
        return false;
    }
    else if (hash.find(PH) == hash.npos || hash.find(PH) != 0)
    {
        cerr << "The hashed response does not start with PH!" << endl;
        return false;
    }

    cerr << "The solution is correct!" << endl;

    return true;
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
        // generate challenge
        const string &R         = generate_random_string(128);
        const string &P         = generate_random_string(p_bits);
        const string &RH        = string_to_hex(R);
        const string &PH        = string_to_hex(P);
        const string &challenge = generate_challenge(RH, PH);

        // set up connection timeout
        struct timeval tv;
        tv.tv_sec  = get_max_processing_time(p_bits);
        tv.tv_usec = 0;

        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

        // send challenge to client
        send(client_socket, challenge.c_str(), strlen(challenge.c_str()), MSG_NOSIGNAL);

        // start timer
        time_t start, end;
        time(&start);

        // read response
        const string &response = read_packet(client_socket);

        // stop timer
        time(&end);

        double processing_time = difftime(end, start);
        cout << "Processing time: " << processing_time << "s" << endl;

        if (processing_time >= get_min_processing_time())
        {
            if (verify_response(response, R, PH))
            {
                send(client_socket, "welcome\n", 9, MSG_NOSIGNAL);
            }
            else
            {
                close(client_socket);
            }
        }
        else
        {
            cerr << "The response is transmitted too soon!" << endl;
            close(client_socket);
        }
    }
    catch (connection_closed)
    {
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
}
