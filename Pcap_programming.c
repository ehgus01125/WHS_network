#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader{
    u_char ether_shost[6]; // src
    u_char ether_dhost[6]; // dst
    u_short ether_type; // 프로토콜 타입
};

/* IP Header */
struct ipheader{
    unsigned char iph_ihl:4, iph_ver:4; //IP 헤더 크기, IPv4 버전
    unsigned char iph_tos; // 서비스 타입
    unsigned short int iph_len; // IP 패킷 길이
    unsigned short int iph_ident; // 식별자
    unsigned short int iph_flag:3, iph_offset:13; //Fragmentation flags, flag offset
    unsigned char iph_ttl; // Time to Live
    unsigned char iph_protocol; //protocol type
    unsigned short int iph_chksum; // checksum
    struct in_addr iph_sourceip; // 출발지 IP
    struct in_addr iph_destip; // 도착지 IP.
};

/* TCP Header */
struct tcpheader{
    u_short tcp_sport; // 출발지 포트 번호
    u_short tcp_dport; // 도착지 포트 번호
    u_int tcp_seq; // seq 번호
    u_int tcp_ack; // ack 번호
    u_char tcp_offx2; // data offset, rsvd
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char tcp_flags; // control flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win; //윈도우 크기
    u_short tcp_sum; // checksum
    u_short tcp_urp; // urg pointer
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet; // 이더넷 헤더

    int ip_header_size = ((struct ipheader*)(packet + sizeof(struct ethheader)))->iph_ihl * 4;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); // IP 헤더
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_size);

    printf("\n[ Ethernet Header ]\n");
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);


    printf("[ IP Header ]\n");
    printf("src ip : %s", inet_ntoa(ip->iph_sourceip));
    printf("dst ip : %s", inet_ntoa(ip->iph_destip));
    printf("\n[ TCP Header ]\n");
    printf("src port : %d", ntohs(tcp->tcp_sport));
    printf("dst port : %d", ntohs(tcp->tcp_dport));
    printf("\n\n");
}


int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // 네트워크 인터페이스 "enp0s1" 열기
  handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
    return 1;
  }

  // 패킷 캡처 시작
  pcap_loop(handle, -1, got_packet, NULL);

  // 핸들 닫기
  pcap_close(handle);

  return 0;
}
