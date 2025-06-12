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
// HTTP 302 Found 응답 메시지 정의: 특정 패턴이 감지되면 이 메시지를 클라이언트에게 전송하여
// warning.or.kr로 리다이렉트 시키는 데 사용됩니다.
const int BUF_SIZE = 4096; // 패킷 버퍼의 최대 크기를 정의합니다.

void usage() { 
    cout << "Usage: ./tcp-block <interface> <pattern>\n"; 
}

uint16_t checksum(uint16_t *buf, int len) { // IP 및 TCP 헤더 체크섬을 계산하는 함수
    uint32_t sum = 0; // 체크섬 계산을 위한 32비트 합계 변수
    while (len > 1) { // 2바이트 단위로 버퍼를 순회하며 합산합니다.
        sum += *buf++; // 현재 16비트 값을 합계에 더하고 다음 16비트 위치로 포인터를 이동합니다.
        len -= 2; // 처리된 바이트 수만큼 길이를 줄입니다.
    }
    if (len == 1) sum += *(uint8_t *)buf; // 남은 바이트가 1바이트인 경우, 해당 바이트를 합계에 더합니다.
    sum = (sum >> 16) + (sum & 0xffff); // 상위 16비트를 하위 16비트에 더하여 오버플로우를 처리합니다.
    sum += (sum >> 16); // 다시 한 번 상위 16비트를 하위 16비트에 더하여 최종 오버플로우를 처리합니다.
    return static_cast<uint16_t>(~sum); // 1의 보수를 취하여 최종 체크섬 값을 반환합니다.
}

struct PseudoHeader { // TCP 체크섬 계산에 사용되는 의사(Pseudo) 헤더 구조체입니다.
    uint32_t src; 
    uint32_t dst; // 목적지 IP 
    uint8_t zero = 0;
    uint8_t proto = IPPROTO_TCP; // 프로토콜 타입 (TCP의 경우 6)
    uint16_t len; // TCP 헤더와 데이터의 총 길이입니다.
};

bool contains_pattern(const u_char *packet, int len, const string &pattern) {
    // 수신된 패킷에서 특정 패턴을 포함하는지 확인하는 함수입니다.
    const ip *ip_hdr = (ip *)(packet + sizeof(ether_header));
    // 이더넷 헤더 크기만큼 건너뛰어 IP 헤더를 가리키는 포인터를 얻습니다.
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;
    // IP 프로토콜이 TCP (6)가 아니면 false를 반환합니다.
    int ip_hlen = ip_hdr->ip_hl * 4; // IP 헤더 길이를 바이트 단위로 계산합니다 (ip_hl은 4바이트 단위).
    const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hlen);
    // IP 헤더 길이만큼 건너뛰어 TCP 헤더를 가리키는 포인터를 얻습니다.
    int tcp_hlen = tcp_hdr->th_off * 4; // TCP 헤더 길이를 바이트 단위로 계산합니다 (th_off는 4바이트 단위).
    int payload_len = ntohs(ip_hdr->ip_len) - ip_hlen - tcp_hlen;
    // IP 패킷의 총 길이에서 IP 헤더와 TCP 헤더 길이를 빼서 페이로드(데이터) 길이를 계산합니다.
    if (payload_len <= 0) return false; // 페이로드 길이가 0 이하이면 false를 반환합니다.
    const u_char *payload = (u_char *)tcp_hdr + tcp_hlen;
    // TCP 헤더 길이만큼 건너뛰어 페이로드 시작 부분을 가리키는 포인터를 얻습니다.
    return string((const char *)payload, payload_len).find(pattern) != string::npos;
    // 페이로드를 std::string으로 변환하여 패턴이 포함되어 있는지 확인하고 결과를 반환합니다.
}

void inject_tcp(const ip *ip_src, const tcphdr *tcp_src, const char *data, int data_len, uint8_t flags) {
  
    char buf[BUF_SIZE] = {};
    ip *iph = (ip *)buf; // 버퍼 시작 부분을 IP 헤더로 캐스팅
    tcphdr *tcph = (tcphdr *)(buf + sizeof(ip)); // IP 헤더 다음 부분을 TCP 헤더로 캐스팅
    char *payload = buf + sizeof(ip) + sizeof(tcphdr); // TCP 헤더 다음 부분을 페이로드 시작 부분으로 캐스팅

    if (data && data_len > 0) // 전송할 데이터가 있고 길이가 0보다 크면
        memcpy(payload, data, data_len); // 페이로드 영역에 데이터를 복사합니다.

    iph->ip_v = 4; 
    iph->ip_hl = 5; // IP 헤더 길이 (5 * 4 = 20 바이트)로 설정
    iph->ip_ttl = 64; // Time To Live (TTL) 값을 64로 설정합니다.
    iph->ip_p = IPPROTO_TCP; // 프로토콜을 TCP로 설정
    iph->ip_len = htons(sizeof(ip) + sizeof(tcphdr) + data_len);
    // IP 패킷의 총 길이를 네트워크 바이트 순서로 설정
    iph->ip_off = 0; 
    iph->ip_id = htons(54321); // IP 식별자 (ID)를 임의의 값으로 설정

    // RST 플래그가 설정된 경우 (클라이언트에게 RST를 보낼 때)
    // 소스 IP는 원래 패킷의 목적지 IP, 목적지 IP는 원래 패킷의 소스 IP
    // 그렇지 않은 경우 (서버에게 FIN/ACK를 보낼 때)
    // 소스 IP는 원래 패킷의 소스 IP, 목적지 IP는 원래 패킷의 목적지 IP
    iph->ip_src = (flags & TH_RST) ? ip_src->ip_dst : ip_src->ip_src;
    iph->ip_dst = (flags & TH_RST) ? ip_src->ip_src : ip_src->ip_dst;
    iph->ip_sum = 0; // 체크섬 계산 전에 0으로 초기화합니다.
    iph->ip_sum = checksum((uint16_t *)iph, sizeof(ip)); // IP 헤더 체크섬을 계산하여 설정합니다.

    // TCP 소스 포트: RST인 경우 원래 패킷의 목적지 포트, FIN/ACK인 경우 원래 패킷의 소스 포트.
    tcph->th_sport = (flags & TH_RST) ? tcp_src->th_dport : tcp_src->th_sport;
    // TCP 목적지 포트: RST인 경우 원래 패킷의 소스 포트, FIN/ACK인 경우 원래 패킷의 목적지 포트.
    tcph->th_dport = (flags & TH_RST) ? tcp_src->th_sport : tcp_src->th_dport;
    uint32_t seq_base = ntohl(tcp_src->th_seq); // 원래 패킷의 시퀀스 번호를 호스트 바이트 순서로 가져옵니다.
    uint32_t ack_base = ntohl(tcp_src->th_ack); // 원래 패킷의 ACK 번호를 호스트 바이트 순서로 가져옵니다.
    int ip_len = ip_src->ip_hl * 4; // 원래 IP 헤더 길이
    int tcp_len = tcp_src->th_off * 4; // 원래 TCP 헤더 길이
    int orig_data_len = ntohs(ip_src->ip_len) - ip_len - tcp_len; // 원래 패킷의 페이로드 길이

    // 시퀀스 번호 설정:
    // RST인 경우, 원래 패킷의 시퀀스 번호 + 페이로드 길이 (상대방이 기대하는 다음 시퀀스 번호).
    // FIN/ACK인 경우, 원래 패킷의 ACK 번호 (상대방이 보낸 데이터에 대한 ACK).
    tcph->th_seq = htonl((flags & TH_RST) ? seq_base + orig_data_len : ack_base);
    // ACK 번호 설정:
    // RST인 경우, 0 (RST는 ACK 번호를 사용하지 않거나 무시).
    // FIN/ACK인 경우, 원래 패킷의 시퀀스 번호 + 페이로드 길이 (상대방이 보낸 데이터에 대한 ACK).
    tcph->th_ack = (flags & TH_RST) ? 0 : htonl(seq_base + orig_data_len);
    tcph->th_off = 5; // TCP 헤더 길이 (5 * 4 = 20 바이트)로 설정합니다.
    tcph->th_flags = flags; // 인자로 받은 TCP 플래그를 설정합니다 (예: TH_RST, TH_FIN | TH_ACK).
    tcph->th_win = htons(65535); // 윈도우 크기를 최대로 설정합니다.
    tcph->th_sum = 0; // 체크섬 계산 전에 0으로 초기화합니다.

    // TCP 체크섬 계산을 위한 의사 헤더를 설정
    PseudoHeader pseudo; // 의사 헤더 구조체
    pseudo.src = iph->ip_src.s_addr; 
    pseudo.dst = iph->ip_dst.s_addr; 
    pseudo.zero = 0; //
    pseudo.proto = IPPROTO_TCP; // 의사 헤더의 프로토콜을 TCP로 설정
    pseudo.len = htons(sizeof(tcphdr) + data_len); // 의사 헤더의 길이를 TCP 헤더 + 데이터 길이로 설정

    char pseudo_buf[BUF_SIZE] = {}; // 의사 헤더와 TCP 헤더+데이터를 합칠 버퍼를 0으로 초기화
    memcpy(pseudo_buf, &pseudo, sizeof(pseudo)); // 의사 헤더를 버퍼에 복사
    memcpy(pseudo_buf + sizeof(pseudo), tcph, sizeof(tcphdr) + data_len);
    // 의사 헤더 다음 위치에 TCP 헤더와 데이터를 복사
    tcph->th_sum = checksum((uint16_t *)pseudo_buf, sizeof(pseudo) + sizeof(tcphdr) + data_len);
    // 의사 헤더와 TCP 헤더+데이터를 포함한 전체에 대해 체크섬을 계산하여 TCP 헤더에 설정

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // RAW 소켓을 생성. IPPROTO_RAW는 IP 헤더를 직접 구성함을 의미
        perror("raw socket"); // errno에 따른 시스템 오류 메시지를 출력
        return;
    }

    int on = 1; // IP_HDRINCL 옵션을 활성화하기 위한 변수입니다.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    // 소켓 옵션을 설정합니다. IP_HDRINCL은 IP 헤더를 직접 포함하여 전송하겠다는 의미
    // (이 옵션이 없으면 커널이 자동으로 IP 헤더를 생성합니다.)

    sockaddr_in to; // 목적지 주소 정보를 저장할 구조체
    memset(&to, 0, sizeof(to)); // 구조체를 0으로 초기화
    to.sin_family = AF_INET; // 주소 체계를 IPv4로 설정
    to.sin_addr = iph->ip_dst; // 목적지 IP 주소를 설정

    sendto(sock, buf, sizeof(ip) + sizeof(tcphdr) + data_len, 0, (sockaddr *)&to, sizeof(to));
    // RAW 소켓을 통해 구성된 패킷을 목적지로 전송
    close(sock); // 소켓을 닫습니다.
}

int main(int argc, char *argv[]) { // 프로그램의 메인 함수입니다.
    if (argc != 3) { // 인자의 개수가 3개가 아니면 (프로그램 이름, 인터페이스, 패턴)
        usage(); // 사용법을 출력하고
        return 1; // 오류 코드를 반환하며 종료합니다.
    }

    char errbuf[PCAP_ERRBUF_SIZE]; // pcap 오류 메시지를 저장할 버퍼입니다.
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 10, errbuf);
    // 네트워크 인터페이스(argv[1])를 열어 라이브 패킷 캡처를 시작
    // BUFSIZ: 스냅샷 길이, 1: 프로미스큐어스 모드 (모든 패킷 캡처), 10: 타임아웃 (밀리초).
    if (!handle) { // pcap_open_live 실패 시
        cerr << "pcap_open_live error: " << errbuf << endl; // 오류 메시지를 출력하고
        return 1; // 오류 코드를 반환하며 종료
    }

    cout << "[*] Listening on " << argv[1] << " for pattern: " << argv[2] << endl;
 

    while (true) {
        pcap_pkthdr *hdr; // 캡처된 패킷의 헤더 정보를 저장할 포인터
        const u_char *packet; // 캡처된 패킷 데이터를 가리킬 포인터
        int ret = pcap_next_ex(handle, &hdr, &packet);
        // 다음 패킷을 캡처합니다. 성공 시 1, 타임아웃 시 0, 오류 시 -1, EOF 시 -2를 반환
        if (ret <= 0) continue; 
        if (contains_pattern(packet, hdr->len, argv[2])) {
            // 캡처된 패킷이 지정된 패턴을 포함하는지 확인
            const ip *ip_hdr = (ip *)(packet + sizeof(ether_header));
            // 캡처된 패킷에서 IP 헤더를 추출
            const tcphdr *tcp_hdr = (tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
            // IP 헤더에서 TCP 헤더를 추출
            cout << "[!] Match detected. Sending RST and FIN+Redirect." << endl;
            // 패턴이 감지되었음을 알리고 RST 및 FIN+Redirect 패킷을 전송할 것임을 출력
            inject_tcp(ip_hdr, tcp_hdr, nullptr, 0, TH_RST);
            // 클라이언트에게 RST (Reset) 패킷을 전송하여 현재 TCP 연결을 강제로 종료
            inject_tcp(ip_hdr, tcp_hdr, REDIRECT_MSG.c_str(), REDIRECT_MSG.length(), TH_FIN | TH_ACK);
            // 서버에게 FIN (Finish) 및 ACK (Acknowledgement) 플래그가 설정된 패킷과 함께 리다이렉트 메시지를 전송하여 연결 종료를 알리고 리다이렉트를 유도
            
        }
    }

    pcap_close(handle); // pcap 핸들을 닫아 리소스를 해제합니다.
    return 0; // 프로그램이 성공적으로 종료되었음을 나타냅니다.
}
