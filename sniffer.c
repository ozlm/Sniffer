#include <stdint.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<time.h>    // time as you know 
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>


/** PCAP file header */
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

/** PCAP packet header */
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

const int MAX_SIZE = 16384;
int tcp = 0, total = 0;       // count of packet
FILE *outfile;

void ProcessPacket(    pcaprec_hdr_t packet_hdr ,unsigned char* buffer, int size);
void print_tcp_packet( pcaprec_hdr_t packet_hdr ,unsigned char* Buffer, int Size);

int main(int argc, char** argv)
{
    int saddr_size, data_size;
    struct sockaddr saddr;
    char buffer[MAX_SIZE];
    int terminate = 1;
    time_t start, end;
    start = time(NULL);
    float elapsed; // seconds
   
    // Open the file to save data to
    outfile = fopen("output.pcap", "wb");
    if(outfile == NULL)
    {
        perror("Unable to open file: ");
        exit(-1);
    }

    // Set up the PCAP file header (Magic Number, Major Version, Minor Version, UTC Timezone, Accuracy, Snaplen, Link Type Ethernet)
    pcap_hdr_t pcap_hdr = {0xa1b2c3d4, 2, 4, 0, 0, MAX_SIZE, 1};
    fwrite((char*)&pcap_hdr, 1, sizeof(pcap_hdr_t), outfile);

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_raw < 0)
    {
        perror("Socket Error");
        exit(-1);
    }

    while(terminate)
    {
        saddr_size = sizeof(saddr);
        data_size = recvfrom(sock_raw, buffer, MAX_SIZE, 0, &saddr, (socklen_t*)&saddr_size);

        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            exit(-1);
        }

        pcaprec_hdr_t packet_hdr;               // packet header struct
        struct timeval tv;                      // time struct 
        gettimeofday(&tv, NULL);                // read current time of day
        packet_hdr.incl_len = data_size;
        packet_hdr.orig_len = data_size; // FIXME: This could be wrong if packet length was > MAX_SIZE
        packet_hdr.ts_sec = tv.tv_sec;
        packet_hdr.ts_usec = tv.tv_usec;
            
        //Now process the packet
        ProcessPacket(packet_hdr , buffer , data_size);
    
        end = time(NULL);
        elapsed = difftime(end, start);
        if (elapsed >= 90.0 /* seconds */)
            terminate = 0;
         else  // No need to sleep when 90.0 seconds elapsed.
            usleep(50000);      
    }
    
    fclose(outfile);
    close(sock_raw);
    
    printf("Finished\n");
    printf("seconds total time %f\r", elapsed);
    printf("\n");
    printf("TCP : %d   Total : %d\r", tcp , total);   
    printf("\n");
    return 0;
}

void ProcessPacket(pcaprec_hdr_t packet_hdr ,unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;

    if (iph->protocol==6) //Check the TCP Protocol and do accordingly...
    { 
            ++tcp;
            print_tcp_packet(packet_hdr,buffer , size);
    }
}

void print_tcp_packet( pcaprec_hdr_t packet_hdr ,unsigned char* Buffer, int size)
{
    fwrite((char*)&packet_hdr, 1, sizeof(pcaprec_hdr_t), outfile);
    fwrite(Buffer, 1, size, outfile);   
}