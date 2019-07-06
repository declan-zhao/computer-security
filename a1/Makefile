default: server client timing_attack

server: custom_utils.h server.cpp
	rm -f server.out
	g++ -o server.out server.cpp -lcrypto

client: custom_utils.h client.cpp
	rm -f client.out
	g++ -o client.out client.cpp -lcrypto

timing_attack:
	rm -f timing_attack.out
	g++ -o timing_attack.out timing_attack.cpp
