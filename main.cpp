#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

using namespace std;

// 리디렉션 메시지: FIN 패킷에 담을 HTTP 응답
const string kRedirectMsg = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
const int kBufSize = 4096;

// 사용법 출력
void show_usage() {
    cout << "Usage  : ./tcp_block <interface> <pattern>\n";
    cout << "Sample : ./tcp_block eth0 \"Host: blocked.site\"\n";
}

// 체크섬 계산 함수 (IP, TCP 헤더용)
uint16_t calc_checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t *)data;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// TCP 체크섬 계산용 수도 헤더
struct PseudoHeader {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero = 0;
    uint8_t protocol = IPPROTO_TCP;
    uint16_t tcp_length;
};

// 패킷에 포함된 payload가 패턴을 포함하는지 검사
bool match_payload_pattern(const u_char *packet, int pkt_len, const string &pattern) {
    auto *ip_hdr = (struct ip *)(packet + sizeof(ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;

    int ip_len = ip_hdr->ip_hl * 4;
    auto *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_len);
    int tcp_len = tcp_hdr->th_off * 4;

    int data_len = ntohs(ip_hdr->ip_len) - ip_len - tcp_len;
    const u_char *payload = (u_char *)tcp_hdr + tcp_len;

    if (data_len <= 0) return false;

    // Payload 내 패턴 문자열 포함 여부 검사
    string data_str((const char *)payload, data_len);
    return data_str.find(pattern) != string::npos;
}

// RST 또는 FIN 패킷을 RAW 소켓으로 전송
void send_raw_tcp_packet(const ip *ip_orig, const tcphdr *tcp_orig, const char *payload_data, int payload_size, uint8_t flags) {
    char buffer[kBufSize] = {};
    auto *ip_hdr = (struct ip *)buffer;
    auto *tcp_hdr = (struct tcphdr *)(buffer + sizeof(struct ip));
    char *payload = buffer + sizeof(struct ip) + sizeof(struct tcphdr);

    // Payload 데이터 복사
    if (payload_size > 0 && payload_data != nullptr)
        memcpy(payload, payload_data, payload_size);

    // IP 헤더 작성
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_size);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_sum = 0;

    // RST이면 방향 그대로, FIN이면 방향 반전 (src/dst 교체)
    ip_hdr->ip_src = (flags & TH_RST) ? ip_orig->ip_src : ip_orig->ip_dst;
    ip_hdr->ip_dst = (flags & TH_RST) ? ip_orig->ip_dst : ip_orig->ip_src;
    ip_hdr->ip_sum = calc_checksum((uint16_t *)ip_hdr, sizeof(struct ip));

    // TCP 헤더 작성
    tcp_hdr->th_sport = (flags & TH_RST) ? tcp_orig->th_sport : tcp_orig->th_dport;
    tcp_hdr->th_dport = (flags & TH_RST) ? tcp_orig->th_dport : tcp_orig->th_sport;
    tcp_hdr->th_seq = (flags & TH_RST)
                          ? htonl(ntohl(tcp_orig->th_seq) + (ntohs(ip_orig->ip_len) - ip_orig->ip_hl * 4 - tcp_orig->th_off * 4))
                          : tcp_orig->th_ack;
    tcp_hdr->th_ack = (flags & TH_RST) ? 0 : htonl(ntohl(tcp_orig->th_seq) + (ntohs(ip_orig->ip_len) - ip_orig->ip_hl * 4 - tcp_orig->th_off * 4));
    tcp_hdr->th_off = 5;
    tcp_hdr->th_flags = flags;
    tcp_hdr->th_win = htons(1024);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

    // TCP 체크섬 계산용 pseudo header 구성
    PseudoHeader pseudo{};
    pseudo.src_addr = ip_hdr->ip_src.s_addr;
    pseudo.dst_addr = ip_hdr->ip_dst.s_addr;
    pseudo.tcp_length = htons(sizeof(struct tcphdr) + payload_size);

    char pseudo_pkt[kBufSize] = {};
    memcpy(pseudo_pkt, &pseudo, sizeof(PseudoHeader));
    memcpy(pseudo_pkt + sizeof(PseudoHeader), tcp_hdr, sizeof(struct tcphdr) + payload_size);
    tcp_hdr->th_sum = calc_checksum((uint16_t *)pseudo_pkt, sizeof(PseudoHeader) + sizeof(struct tcphdr) + payload_size);

    // RAW 소켓을 통해 패킷 전송
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr = ip_hdr->ip_dst;

    if (sendto(sock, buffer, sizeof(struct ip) + sizeof(struct tcphdr) + payload_size, 0,
               (sockaddr *)&target, sizeof(target)) < 0) {
        perror("sendto");
    }

    close(sock);
}

// 메인 함수: 패킷 캡처 루프
int main(int argc, char *argv[]) {
    if (argc != 3) {
        show_usage();
        return 1;
    }

    const char *dev = argv[1];
    string pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    // NIC에서 실시간 패킷 캡처 시작
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    // 실시간 반응성 향상 (optional)
    pcap_set_immediate_mode(pcap, 1);
    pcap_activate(pcap);

    cout << "[*] Monitoring interface '" << dev << "' for pattern: \"" << pattern << "\"\n";

    // 캡처 루프
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // 조건에 맞는 패킷 발견 시 처리
        if (match_payload_pattern(packet, header->len, pattern)) {
            auto *ip_hdr = (struct ip *)(packet + sizeof(ether_header));
            int ip_len = ip_hdr->ip_hl * 4;
            auto *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_len);

            cout << "[!] Blocked packet matched. Injecting RST and FIN packets.\n";

            // RST: 서버로 연결 종료
            send_raw_tcp_packet(ip_hdr, tcp_hdr, nullptr, 0, TH_RST);

            // FIN+ACK + 리디렉션 메시지: 클라이언트로 HTTP 종료
            send_raw_tcp_packet(ip_hdr, tcp_hdr, kRedirectMsg.c_str(), kRedirectMsg.size(), TH_FIN | TH_ACK);
        }
    }

    pcap_close(pcap);
    return 0;
}
