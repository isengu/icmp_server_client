all: clean compiling linking
	./bin/icmp_server

clean:
	rm -f obj/*.o bin/*

compiling:
	gcc -I include -c -o obj/icmp_util.o src/icmp_util.c -lpcap
	gcc -I include -c -o obj/icmp_client.o src/icmp_client.c
	gcc -I include -c -o obj/icmp_server.o src/icmp_server.c

linking:
	gcc -o bin/icmp_client obj/icmp_util.o obj/icmp_client.o -lpcap
	gcc -o bin/icmp_server obj/icmp_util.o obj/icmp_server.o -lpcap