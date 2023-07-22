#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;		     /* protocol */
};

void print_mac(u_int8_t *m){
	printf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(struct in_addr ip) {
	printf("%s", inet_ntoa(ip));
}

void print_payload(const u_char *payload, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", payload[i]);
    }
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//Ethernet Header의 src mac / dst mac
		printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		print_mac(eth_hdr->ether_shost);
		printf("\n");
		print_mac(eth_hdr->ether_dhost);
		printf("\n");
		
		// IP Header의 src ip / dst ip
		struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct libnet_ethernet_hdr));
		printf("Source IP: ");
		print_ip(ip_hdr->ip_src);
		printf("\n");
		printf("Destination IP: ");
		print_ip(ip_hdr->ip_dst);
		printf("\n");
		
		// TCP Header의 src port / dst port
		struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl << 2));
		printf("Source Port: %d\n", ntohs(tcp_hdr->source));
		printf("Destination Port: %d\n", ntohs(tcp_hdr->dest));
		
		// Payload(Data) 출력 (최대 10바이트까지만)
		int payload_offset = sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl << 2) + (tcp_hdr->doff << 2);
		int payload_len = header->caplen - payload_offset;
		if (payload_len > 10) payload_len = 10; // 최대 10바이트까지만 출력
		if (payload_len > 0) {
			printf("Payload (Data): ");
			print_payload(packet + payload_offset, payload_len);
			printf("\n");
		}
	}
	 
	pcap_close(pcap);
}
