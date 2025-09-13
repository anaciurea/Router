#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "list.h"
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

struct route_table_entry *route_table;
int route_table_len;

struct arp_table_entry *arp_table;
int arp_table_len;

//trie node structure used for fast route
typedef struct trie_node {
    struct trie_node *children[2]; // two children 0 and 1
    struct route_table_entry *route; // NULL  if this is not an end of a prefix
} trie_node;

//function that allocate and initialize a new trie node
trie_node *create_trie_node() {
    trie_node *node = calloc(1, sizeof(trie_node));
    DIE(node == NULL, "trie node allocation");
    return node;
}

//insert a route into the trie based on its prefix
void insert_route(trie_node *root, struct route_table_entry *route) {
    trie_node *node = root;
    uint32_t prefix = ntohl(route->prefix); // convert prefix to host by order
    uint32_t mask = ntohl(route->mask);

    // count the number of 1 bits in the mask
    int prefix_len = 0;
    while (mask) {
        if (mask & 1) //if the least significant bit is 1
            prefix_len++;
        mask >>= 1; //shift the mask right by 1 bit
    }

    for (int i = 31; i >= 32 - prefix_len; i--) {
        int bit = (prefix >> i) & 1;
        if (!node->children[bit]) {
            node->children[bit] = calloc(1, sizeof(trie_node));
        }
        node = node->children[bit];
    }
    node->route = route; // store the route at the end of prefix
}

//longest prefix match using the trie
struct route_table_entry *get_best_route_trie(trie_node *root, uint32_t dest_ip) {
    trie_node *node = root;
    struct route_table_entry *best = NULL;

    dest_ip = ntohl(dest_ip);

    for (int i = 31; i >= 0; i--) {
        int bit = (dest_ip >> i) & 1;
        if (!node) 
            break;
        if (node->route)
            best = node->route;
        node = node->children[bit];
    }

    return best;
}

//looking for ip in the ARP table
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == given_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

//function that is building the header of ethernet setting the mac source, the mac destination and the type
void create_eth_header(struct ether_hdr *eth_hdr, uint8_t *src_mac, uint8_t *dst_mac, uint16_t type) {
    memcpy(eth_hdr->ethr_shost, src_mac, 6); // source mac
    memcpy(eth_hdr->ethr_dhost, dst_mac, 6); // destination mac
    eth_hdr->ethr_type = htons(type); // ether type (ipv4)
} 

//functions that is building the ipv4 header setting the necessary fields such as version, header length,
//source and destination addr, total packet lenth and protocal type.  It also calculates the checksum of the
//header and assigns it.
void create_ip_header(struct ip_hdr *ip_hdr, uint32_t source, uint32_t destination, uint16_t total_length, uint8_t protocol) {
    ip_hdr->ver = 4; //set ip version 4
    ip_hdr->ihl = 5; //set internet header length
    ip_hdr->tos = 0; //type of service field is 0 because we are not using it
    ip_hdr->tot_len = htons(total_length); //set the total length of the packet
    ip_hdr->id = htons(0); //set the identification field 0 because we are not using it
    ip_hdr->frag = 0; //set the fragmentation offset field to 0
    ip_hdr->ttl = 64; 
    ip_hdr->proto = protocol; //set the protocoal field (1 for icmp)
    ip_hdr->source_addr = source; //set the source ip adr
    ip_hdr->dest_addr = destination; //set the dst ip adr
    ip_hdr->checksum = 0; //set the checksum field to 0 before calculating
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len)));
}

//function that is generating an ICMP error (Time Exceeded, Destination Unreachable)
void icmp_error(char *buf, size_t len, int interface, uint8_t type, uint8_t code) {
    struct ether_hdr *old_eth = (struct ether_hdr *)buf;
    struct ip_hdr *old_ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    //a new packet is created, which will hold the new ICMP error message
    //it's initialized to zero to ensure that there are no residual vaues from previos uses
    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN);

    //set the bew ether and ip headers
    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    //get the source mac adr
    uint8_t src_mac[6];
    get_interface_mac(interface, src_mac);
    create_eth_header(eth_hdr, src_mac, old_eth->ethr_shost, 0x0800);

    //fills in the ipv4 header with necessary fields such as source and destination ip,
    //total length, and protocol type.
    create_ip_header(ip_hdr, inet_addr(get_interface_ip(interface)), old_ip->source_addr,                        
        sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8, 1);  //the protocol is set to 1, which is the icmp protocol 
    
    //filling in the imcp header
    icmp_hdr->mtype = type;
    icmp_hdr->mcode = code;
    icmp_hdr->check = 0;
    memset(&icmp_hdr->un_t, 0, sizeof(icmp_hdr->un_t));

    // copies the ip header and first 8 bytes of payload to the icmp message
    memcpy((uint8_t *)icmp_hdr + sizeof(struct icmp_hdr), old_ip, sizeof(struct ip_hdr) + 8);

    int icmp_len = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

    //sending the icmp error packet
    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len, packet, interface);
}

// answering to ping : echo request => echo reply
void icmp_echo_reply(char *buf, size_t len, int interface) {
    //parsing the ehternet header of the incoming packet
    struct ether_hdr *eth_in = (struct ether_hdr *)buf;
    struct ip_hdr *ip_in = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_in = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    //preparing a new buffer for the echo reply packet
    char packet[MAX_PACKET_LEN];
    memset(packet, 0, MAX_PACKET_LEN);

    struct ether_hdr *eth_out = (struct ether_hdr *)packet; //ethernet header for the outgoing echo reply packet
    struct ip_hdr *ip_out = (struct ip_hdr *)(packet + sizeof(struct ether_hdr)); //ip header for the outgoing Echo Reply packet
    struct icmp_hdr *icmp_out = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)); //ICMP header for the outgoing Echo Reply packet

    uint8_t src_mac[6];
    get_interface_mac(interface, src_mac);
    create_eth_header(eth_out, src_mac, eth_in->ethr_shost, 0x0800);

    create_ip_header(ip_out, inet_addr(get_interface_ip(interface)),           
                    ip_in->source_addr, len - sizeof(struct ether_hdr), 1);                                         

    //copies the contets of the incoming ICMP header into the outgoing ICMP header in preparation
    //for sending an IMCP Echo Reply
    memcpy(icmp_out, icmp_in, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr));
    //setting the ICMP type, checksum
    icmp_out->mtype = 0; // Echo Reply
    icmp_out->check = 0;
    icmp_out->check = htons(checksum((uint16_t *)icmp_out,
                                     len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

    //send the ICMP Echo Reply
    send_to_link(len, packet, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	route_table = malloc(sizeof(struct route_table_entry) * 100001);
	DIE(route_table == NULL, "memory failed");

	arp_table = malloc(sizeof(struct arp_table_entry) * 1000);
    DIE(arp_table == NULL, "memory failed");

	route_table_len = read_rtable(argv[1], route_table);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

    trie_node *trie_root = create_trie_node();
    for (int i = 0; i < route_table_len; i++) {
        insert_route(trie_root, &route_table[i]);
    }

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("Packet received\n");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

        //if it's not ipv4, ignores the packet
		if (ntohs(eth_hdr->ethr_type) != 0x0800) {
            printf("Packet ignored\n");
            continue;
        }

		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

        //check ip header checksum
		uint16_t received_checksum = ip_hdr->checksum;
		ip_hdr->checksum = 0;
		uint16_t cal_checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

		if (received_checksum != cal_checksum) {
            printf("Invalid checksum\n");
            continue;
        }

		ip_hdr->checksum = received_checksum;
		
        // respond to ICMP Echo Request
		if (ip_hdr->proto == 1 && ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))) {
			struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
				printf("Received ICMP Echo Request, sending Echo Reply\n");
				icmp_echo_reply(buf, len, interface);
				continue;
			}
		}
        
        // TTL expired => drop packet and send ICMP Error
		if (ip_hdr->ttl <= 1) {
            printf("TTL expired\n");
            //ICMP Time Exceeded
            icmp_error(buf, len, interface, 11, 0); // Type 11 = Time Exceeded, Code 0
            continue;
        }

        //searching for the best route using the trie
        struct route_table_entry *best_route = get_best_route_trie(trie_root, ip_hdr->dest_addr);
        if (!best_route) {
            printf(" No route found\n");
            //ICMP Destination Unreachable
            icmp_error(buf, len, interface, 3, 0); // Type 3 = Destination Unreachable
            continue;
        }

		//update TTL and recalculate checksum
        ip_hdr->ttl--;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
        
		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
		if (!arp_entry) {
            printf("Dropped: MAC address not found for next hop\n");
            // Here you would send an ARP request to discover the MAC
            // Implementation of ARP request would go here
            continue;
        }

		//update ethernet header for forwarding and set destination mac to next hop's mac
        memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
        
        // Set source MAC to the outgoing interface's MAC
        uint8_t interface_mac[6];
        get_interface_mac(best_route->interface, interface_mac);
		memcpy(eth_hdr->ethr_shost, interface_mac, 6);
        
        //send the packet to the appropriate interface
        send_to_link(len, buf, best_route->interface);
    }
	return 0;
}