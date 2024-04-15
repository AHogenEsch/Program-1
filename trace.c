#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdlib>
#include <cstdio>
#include <cstdint>

#define PCAP_BUF_SIZE	1024


void printEthernet(){
    /*Dest MAC, Source MAC, Type*/
    char *destMAC;
    char *srcMAC;
    char *type;
    printf("\tEthernet Header\n\t\tDest MAC: %s\n\t\tSource MAC: %s\n\t\tType: %s\n", destMAC, srcMAC, type);
}

void printARP(){
    char *opCode;
    char *sentMAC;
    char *sentIP;
    char *targMAC;
    char *targIP;
    printf("\tRP header\n\t\tOpcode: %s\n\t\tSender MAC: %s\n\t\tSender IP: %s\n\t\tTarget MAC: %s\n\t\tTarget IP: %s\n", opCode, sentMAC, sentIP, targMAC, targIP);
}

void printIP(){
    int ipv; /*IP version*/
    int hedLen;
    int diffServBits;
    int ECNBits;
    int ttl;
    char *protocol;
    char *checkSum;
    char *sendIP;
    char *destIP;
    printf("\tIP Header:\n\t\tIP Version: %d\n\t\tHeader Len (bytes): %d\n\t\tTOS subfields:\n\t\t\tDiffserv bits: %d\n\t\t\tECN bits: 0\n\t\tTTL: %d\n\t\tProtocol: %s\n\t\tChecksum: %s\n\t\tSender IP: %s\n\t\tDest IP: %s\n", ipv, hedLen, diffServBits, ECNBits, ttl, protocol, checkSum, sendIP, destIP);

}

void printICMP(){
    char *type;
    printf("\tICMP Header\n\t\tType: %s", type);
}

void printTCP(){
    int srcPort;
    char *destPort;
    long int seqNum;
    long int ackNum;
    int dataOffset;
    char *synFlag;
    char *rstFlag;
    char *finFlag;
    char *ackFlag;
    int windSize;
    char *checkSum;
    printf("\tTCP Header\n\t\tSource Port: %d\n\t\tDest Port: %s\n\t\tSequence Number: %ld\n\t\tACK Number: %ld\n\t\tData Offset (bytes): %d\n\t\tSYN Flag: %s\n\t\tRST Flag: %s\n\t\tFIN Flag: %s\n\t\tACK Flag: %s\n\t\tWindow Size: %d\n\t\tChecksum: %s", srcPort, destPort, seqNum, ackNum, dataOffset, synFlag, rstFlag, finFlag, ackFlag, windSize, checkSum);
}

void printUDP(){
    char *srcPort;
    char *destPort;
    printf("\tUDP Header\n\t\tSource Port: %s\n\t\tDest Port: %s\n", srcPort, destPort);
    return;
}

// void packHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){

// }
struct ethernetHeader {
    uint8_t  *destMAC[6];
    uint8_t *srcMAC[6];
    uint16_t *type;
} __attribute__ ((__packed__));

struct arpHeader {
    char *opCode[16];
    char *sentMAC[32];
    char *sentIP[32];
    char *targMAC[32];
    char *targIP[32];
};

struct ipHeader {
    int ipv; /*IP version*/
    int hedLen;
    int diffServBits;
    int ECNBits;
    int ttl;
    char *protocol[8];
    char *checkSum[32];
    char *sendIP[32];
    char *destIP[32];
};

struct icmpHeader{
    char *type[16];
};

struct tcpHeader{
    int srcPort;
    char *destPort[32];
    long int seqNum;
    long int ackNum;
    int dataOffset;
    char *synFlag[4];
    char *rstFlag[4];
    char *finFlag[4];
    char *ackFlag[4];
    int windSize;
    char *checkSum[32];
};

struct udpHeader {
    char *srcPort[16];
    char *destPort[16];
};

int main(int argc, char *argv[]){
    /*Needs to process Ethernet Header, ARP Header (both request and Replay), IP, ICMP Hedaer for Echo Request \ reply, TCP, UDP*/
    /*Outputs to STDOUT*/
    /* trace TraceFile.pcacp > anOutputFile.txt*/
    /*For TCP, if the ACK flag is not set, then output 0 for the ACK NUmber*/
    /*For IP protocol field, should be ICMP, TCP, UDP, or "Unknown"*/
    /*For TCP\UDP Port number output, use HTTP, Telnet, FTP, POP3, or SMTP, otherwise use port number*/
    /*Length fild in TCP pseudo header needs to be in network order*/
    int packetNum = 0;
    if(argc != 2){
        print("Invalid Arguments\n");
    }
    else{
        /*Open argv[1] file*/
        char *errbuf[256];
        pcap_t *fp;
        struct pcap_pkthdr *packetHeader;
        struct ethernetHeader *ehdr;
        const u_char *packetData;

        fp = pcap_open_offline(argv[1], errbuf);
        if(fp == NULL){
            perror(errbuf);
            return(-1);
        }

        while(pcap_next_ex(fp, &packetHeader, &packetData)){
            /* First 6 bytes = DEstination, 
             * Second 6 bytes = Source
             * Last 2 bytes = Type */
            char *destMAC[24];
            char *srcMAC[24];
            char *type[8];
            ehdr = (struct ethernetHeader *) packetData;
            strcpy(destMAC, ether_ntoa(ehdr->destMAC));
            strcpy(srcMAC, ether_ntoa(ehdr->srcMAC));
            if(ehdr->type == ETHERTYPE_IP){
                strcpy(type,"IP");
            }
            else if(ehdr->type == ETHERTYPE_ARP){
                strcpy(type, "ARP");
            }
            printf("\tEthernet Header\n\t\tDest MAC: %s\n\t\tSource MAC: %s\n\t\tType: %s\n", destMAC, srcMAC, type);

            if(strcmp(type, "IP") == 0){
                printIP(packetData);
            }
            if(strcmp(type, "ARP") == 0){
                printARP(packetData)
            }
            /*Ethernet Header -> Data,  ~~ IP or ARP ~~*/

        }
        /*Loop through opened file*/
        // if (pcap_loop(fp, 0, packetHandler, NULL) < 0) {
        //     fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        //     return(-1);
        // }


        pcap_close(fp);
    }
}