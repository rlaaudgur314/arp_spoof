all : arp_spoofing

arp_spoofing: arp.o main.o
	g++ -o arp_spoofing main.o arp.o -lpcap -pthread

main.o: kmh_header.h main.c
	g++ -c -o main.o main.c

arp.o: kmh_header.h kmh_header.c
	g++ -c -o arp.o kmh_header.c

clean:
	rm *.o arp_spoofing
