#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <ctype.h>

// 패킷 캡처 시 호출되는 함수
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    // 1. Ethernet Header 해석
    struct ether_header *eth = (struct ether_header *)pkt_data;

    // IP 패킷인지 확인 (ether_type 검사)
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // 2. IP Header 해석
    struct ip *ip_h = (struct ip *)(pkt_data + sizeof(struct ether_header));

    // TCP 프로토콜인지 확인
    if (ip_h->ip_p != IPPROTO_TCP) return;

    // 3. TCP Header 해석
    struct tcphdr *tcp_h = (struct tcphdr *)(pkt_data + sizeof(struct ether_header) + ip_h->ip_hl * 4);

    // MAC 주소 출력
    printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP 주소 출력
    printf("Src IP: %s\n", inet_ntoa(ip_h->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_h->ip_dst));

    // 포트 출력
    printf("Src Port: %d\n", ntohs(tcp_h->th_sport));
    printf("Dst Port: %d\n", ntohs(tcp_h->th_dport));

    // Payload 일부 출력
    const u_char *msg = (u_char *)(tcp_h + 1);
    int msg_len = ntohs(ip_h->ip_len) - (ip_h->ip_hl * 4) - (tcp_h->th_off * 4);
    if (msg_len > 0) {
        printf("Message: ");
        for (int i = 0; i < msg_len && i < 16; i++) {
            printf("%c", isprint(msg[i]) ? msg[i] : '.');
        }
        printf("\n");
    }

    printf("=====================================\n");
}

int main() {
    // 네트워크 인터페이스 이름 (PDF 흐름 기준)
    char *device = "ens33";
    char errbuf[PCAP_ERRBUF_SIZE];

    // 캡처 핸들 열기
    pcap_t *pcap_h = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (pcap_h == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 2;
    }

    // 패킷 10개 캡처
    pcap_loop(pcap_h, 10, handle_packet, NULL);
    pcap_close(pcap_h);
    return 0;
}
