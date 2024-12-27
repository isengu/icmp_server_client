#include "icmp_util.h"

void send_icmp_packet(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Retrieve the source MAC address
    unsigned char src_mac[ETH_ALEN];
    get_mac_address(device, src_mac);

    // Retrieve the source IP address
    char src_ip[INET_ADDRSTRLEN];
    get_ip_address(device, src_ip);

    // Construct Ethernet frame
    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    struct ethheader *eth = (struct ethheader *)packet;
    unsigned char dest_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  // Broadcast

    memcpy(eth->dest, dest_mac, ETH_ALEN);
    memcpy(eth->source, src_mac, ETH_ALEN);  // Use dynamic MAC address
    eth->type = htons(ETHERTYPE_IP);

    size_t icmp_len = sizeof(struct icmpheader) + sizeof(unsigned long); // total length of icmp packet (icmp header + data)

    // Construct IP header
    struct ipheader *ip = (struct ipheader *)(eth + 1);
    ip->version = 4;   // IPv4
    ip->ihl = 5;       // Header length
    ip->tos = 0;       // Type of Service
    ip->tot_len = htons(sizeof(struct ipheader) + icmp_len); // Total length
    ip->id = htons(1); // Identification
    ip->frag_off = 0;  // Fragment offset
    ip->ttl = 64;      // Time to live
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(src_ip);  // Source IP
    ip->daddr = inet_addr("192.168.1.1");  // Destination IP
    ip->checksum = 0;
    ip->checksum = calculate_checksum(ip, sizeof(struct ipheader));

    // Construct ICMP header
    struct icmpheader *icmp = (struct icmpheader *)(ip + 1);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(1);
    icmp->sequence = htons(1);

    // Add Timestamp Information
    unsigned long *timestamps = (unsigned long *)(icmp + 1);
    timestamps[0] = time(NULL);

    // Calculate ICMP checksum
    icmp->checksum = calculate_checksum(icmp, icmp_len);

    // Send the packet
    if (pcap_inject(handle, packet, sizeof(struct ethheader) + sizeof(struct ipheader) + icmp_len) == -1) {
        pcap_perror(handle, "pcap_inject");
    } else {
        printf("Packet sent successfully from MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    }

    pcap_close(handle);
}


int main(int argc, char **argv)
{
    char *dev = NULL;
    pcap_t *fp;
    char errbuffer[PCAP_ERRBUF_SIZE];
    u_char packet[50];
    int i;

    pcap_if_t *all_devs;

    if(pcap_findalldevs(&all_devs, errbuffer) == -1){
        fprintf(stderr, "error finding devices");
        return 1;
    }

    dev = all_devs->name;
    printf("address: %s\n", dev);
    
    unsigned char dev_mac[ETH_ALEN];
    get_mac_address(dev, dev_mac);

    send_icmp_packet(dev);

    return 0;
}
