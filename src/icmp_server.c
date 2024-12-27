#include "icmp_util.h"

char *dev = NULL;

// Function to send ICMP reply
void send_icmp_reply(pcap_t *handle, const struct ethheader *eth,
                     const struct ipheader *ip, const struct icmpheader *icmp, size_t icmp_len) {
    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    // Retrieve the source MAC address
    // unsigned char src_mac[ETH_ALEN];
    // get_mac_address(dev, src_mac);

    // Ethernet header
    struct ethheader *reply_eth = (struct ethheader *)packet;
    // memcpy(reply_eth->source, src_mac, ETH_ALEN);  // Use dynamic MAC address
    memcpy(reply_eth->source, eth->dest, ETH_ALEN); // Source MAC is the original dest MAC
    memcpy(reply_eth->dest, eth->source, ETH_ALEN); // Dest MAC is the original source MAC
    reply_eth->type = htons(ETHERTYPE_IP);

    // IP header
    struct ipheader *reply_ip = (struct ipheader *)(reply_eth + 1);
    reply_ip->ihl = 5;
    reply_ip->version = 4;
    reply_ip->tos = 0;
    reply_ip->tot_len = htons(sizeof(struct ipheader) + icmp_len);
    reply_ip->id = htons(1);
    reply_ip->frag_off = 0;
    reply_ip->ttl = 64;
    reply_ip->protocol = IPPROTO_ICMP;
    reply_ip->saddr = ip->daddr; // Source IP becomes original destination
    reply_ip->daddr = ip->saddr; // Destination IP becomes original source
    reply_ip->checksum = 0;
    reply_ip->checksum = calculate_checksum(reply_ip, sizeof(struct ipheader));

    // ICMP header
    struct icmpheader *reply_icmp = (struct icmpheader *)(reply_ip + 1);
    memcpy(reply_icmp, icmp, icmp_len); // Copy original ICMP header and payload
    reply_icmp->type = ICMP_ECHOREPLY; // Change to echo reply
    reply_icmp->checksum = 0;
    reply_icmp->checksum = calculate_checksum(reply_icmp, icmp_len);

    // Send the packet
    size_t packet_len = sizeof(struct ethheader) + sizeof(struct ipheader) + icmp_len;
    if (pcap_inject(handle, packet, packet_len) == -1) {
        pcap_perror(handle, "pcap_inject");
    } else {
        printf("Sent ICMP reply to %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    }
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args; // Unused

    const struct ethheader *eth = (struct ethheader *)packet;

    // Ensure it's an IP packet
    if (ntohs(eth->type) != ETHERTYPE_IP) {
        return;
    }

    const struct ipheader *ip = (struct ipheader *)(eth + 1);

    // Ensure it's an ICMP packet
    if (ip->protocol != IPPROTO_ICMP) {
        return;
    }

    const struct icmpheader *icmp = (struct icmpheader *)((unsigned char *)ip + ip->ihl * 4);
    size_t icmp_len = ntohs(ip->tot_len) - ip->ihl * 4;

    // Check if it's an ICMP Echo Request
    if (icmp->type == ICMP_ECHO) {
        printf("Received ICMP Echo Request from %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));

        // Respond to the Echo Request
        pcap_t *handle = (pcap_t *)args;
        send_icmp_reply(handle, eth, ip, icmp, icmp_len);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs;

    if(pcap_findalldevs(&all_devs, errbuf) == -1){
        fprintf(stderr, "error finding devices");
        return 1;
    }

    dev = all_devs->name;

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Listening for ICMP Echo Requests on %s...\n", dev);

    if (pcap_loop(handle, -1, packet_handler, (unsigned char *)handle) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);
    return 0;
}
