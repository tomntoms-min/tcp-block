#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

using namespace std;

const string REDIRECT_MSG = "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr\r\n\r\n";
const int BUF_SIZE = 4096;

void usage() {
    cout << "Usage: ./blocker <interface> <pattern>\n";
}

uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

struct PseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP;
    uint16_t len;
};

bool contains_pattern(const u_char *packet, int len, const string &pattern) {
    const ip *ip_hdr = (ip *)(packet + sizeof(ether_header));
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;
    int ip_hlen = ip_hdr->ip_hl * 4;
    const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hlen);
    int tcp_hlen = tcp_hdr->th_off * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hlen - tcp_hlen;
    if (payload_len <= 0) return false;
    const u_char *payload = (u_char *)tcp_hdr + tcp_hlen;
    return string((const char *)payload, payload_len).find(pattern) != string::npos;
}

void inject_tcp(const ip *ip_src, const tcphdr *tcp_src, const char *data, int data_len, uint8_t flags) {
    char buf[BUF_SIZE] = {};
    ip *iph = (ip *)buf;
    tcphdr *tcph = (tcphdr *)(buf + sizeof(ip));
    char *payload = buf + sizeof(ip) + sizeof(tcphdr);
    if (data && data_len > 0)
        memcpy(payload, data, data_len);

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + data_len);
    iph->ip_off = 0;
    iph->ip_id = htons(54321);

    iph->ip_src = (flags & TH_RST) ? ip_src->ip_src : ip_src->ip_dst;
    iph->ip_dst = (flags & TH_RST) ? ip_src->ip_dst : ip_src->ip_src;
    iph->ip_sum = 0;
    iph->ip_sum = checksum((uint16_t *)iph, sizeof(ip));

    tcph->th_sport = (flags & TH_RST) ? tcp_src->th_sport : tcp_src->th_dport;
    tcph->th_dport = (flags & TH_RST) ? tcp_src->th_dport : tcp_src->th_sport;
    uint32_t seq_base = ntohl(tcp_src->th_seq);
    uint32_t ack_base = ntohl(tcp_src->th_ack);
    int ip_len = ip_src->ip_hl * 4;
    int tcp_len = tcp_src->th_off * 4;
    int orig_data_len = ntohs(ip_src->ip_len) - ip_len - tcp_len;
    tcph->th_seq = htonl((flags & TH_RST) ? seq_base + orig_data_len : ack_base);
    tcph->th_ack = (flags & TH_RST) ? 0 : htonl(seq_base + orig_data_len);
    tcph->th_off = 5;
    tcph->th_flags = flags;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;

    PseudoHeader pseudo = {iph->ip_src.s_addr, iph->ip_dst.s_addr, 0, IPPROTO_TCP, htons(sizeof(tcphdr) + data_len)};
    char pseudo_buf[BUF_SIZE] = {};
    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), tcph, sizeof(tcphdr) + data_len);
    tcph->th_sum = checksum((uint16_t *)pseudo_buf, sizeof(pseudo) + sizeof(tcphdr) + data_len);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("raw socket");
        return;
    }

    int on = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr = iph->ip_dst;

    sendto(sock, buf, sizeof(ip) + sizeof(tcphdr) + data_len, 0, (sockaddr *)&to, sizeof(to));
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 10, errbuf);
    if (!handle) {
        cerr << "pcap_open_live error: " << errbuf << endl;
        return 1;
    }

    cout << "[*] Listening on " << argv[1] << " for pattern: " << argv[2] << endl;

    while (true) {
        pcap_pkthdr *hdr;
        const u_char *packet;
        int ret = pcap_next_ex(handle, &hdr, &packet);
        if (ret <= 0) continue;

        if (contains_pattern(packet, hdr->len, argv[2])) {
            const ip *ip_hdr = (ip *)(packet + sizeof(ether_header));
            const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            cout << "[!] Match detected. Sending RST and FIN+Redirect." << endl;
            inject_tcp(ip_hdr, tcp_hdr, nullptr, 0, TH_RST);
            inject_tcp(ip_hdr, tcp_hdr, REDIRECT_MSG.c_str(), REDIRECT_MSG.length(), TH_FIN | TH_ACK);
        }
    }

    pcap_close(handle);
    return 0;
}
