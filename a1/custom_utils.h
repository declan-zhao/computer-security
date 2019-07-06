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
#include <random>
#include <stdexcept>
#include <iomanip>
#include <cmath>
#include <openssl/evp.h>

class connection_closed
{
};
class socket_error
{
};

// https://stackoverflow.com/a/11990066
string generate_random_string(int bits)
{
    int size = bits / 8;
    char random_string[size];
    FILE *fp   = fopen("/dev/urandom", "r");
    int  count = fread(&random_string, 1, size, fp);
    fclose(fp);

    return string(random_string, size);
}

static const char *const lut = "0123456789abcdef";

// https://stackoverflow.com/a/3382894
string string_to_hex(const string &input)
{
    size_t len = input.length();

    string output;
    output.reserve(2 * len);

    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }

    return output;
}

// https://stackoverflow.com/a/3382894
string hex_to_string(const string &input)
{
    size_t len = input.length();
    if (len & 1)
        throw invalid_argument("odd length");

    string output;
    output.reserve(len / 2);

    for (size_t i = 0; i < len; i += 2)
    {
        char  a       = input[i];
        const char *p = lower_bound(lut, lut + 16, a);
        if (*p != a)
            throw invalid_argument("not a hex digit");

        char  b       = input[i + 1];
        const char *q = lower_bound(lut, lut + 16, b);
        if (*q != b)
            throw invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }

    return output;
}

int get_max_processing_time(int p_bits)
{
    // 8 bits -> 4s
    // 16 bits -> 8s
    return (int)2 * pow(2, p_bits / 8);
}

double get_min_processing_time()
{
    // 1.0s
    return 1.0;
}

// https://stackoverflow.com/a/40155962
bool get_sha256(const string &unhashed, string &hashed)
{
    bool success = false;

    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (context != NULL)
    {
        if (EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
            if (EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
            {
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int lengthOfHash = 0;

                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    std:: stringstream ss;
                    for (unsigned int i = 0; i < lengthOfHash; ++i)
                    {
                        ss << std:: hex << std:: setw(2) << std:: setfill('0') << (int)hash[i];
                    }

                    hashed  = ss.str();
                    success = true;
                }
            }
        }

        EVP_MD_CTX_free(context);
    }

    return success;
}

string read_packet(int socket)
{
    string msg;

    const int size = 8192;
    char buffer[size];

    while (true)
    {
        int bytes_read = recv(socket, buffer, sizeof(buffer) - 2, 0);
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
            close(socket);
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
