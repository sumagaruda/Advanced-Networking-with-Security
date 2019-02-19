#include<pcap.h>
#include<iostream>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<map>
#include<set>
using namespace std;
using namespace std;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* IP header */
struct sniff_ip
{
u_char ip_vhl;		/* version << 4 | header length >> 2 */
u_char ip_tos;		/* type of service */
u_short ip_len;		/* total length */
u_short ip_id;		/* identification */
u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
u_char ip_ttl;		/* time to live */
u_char ip_p;		/* protocol */
u_short ip_sum;		/* checksum */
struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
u_short th_sport;	/* source port */
u_short th_dport;	/* destination port */
tcp_seq th_seq;		/* sequence number */
tcp_seq th_ack;		/* acknowledgement number */
u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
u_short th_win;		/* window */
u_short th_sum;		/* checksum */
u_short th_urp;		/* urgent pointer */
};

map<pair<int,int>,string> session;
map<pair<int,int>,int> msg;

string ip2string(int ip)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    return inet_ntoa(ip_addr);
}

void got_packet(u_char* type, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */
    u_int size_ip;
    u_int size_tcp;

    ethernet = (const struct sniff_ethernet*)(packet);
    ip = (const struct sniff_ip*)(packet + 14);
    size_ip = IP_HL(ip)*4;
 //Invalid IP header length
    if (size_ip < 20)
	return;
    tcp = (const struct sniff_tcp*)(packet + 14 + size_ip);
    size_tcp = TH_OFF(tcp)*4;
//Invalid TCP header length
    if (size_tcp < 20)
	return;
    payload = (u_char *) (packet + 14 + size_ip + size_tcp);


//we keep adding entries to the hash table, which has the key pair {ip,port}
    for (int i=  14 + size_ip + size_tcp; i < pkthdr->len; i++)
    {
		map<pair<int,int>,string>::iterator it;
		int ip_address;
        string s;

		if (( ntohs(tcp->th_sport)== 80 && *type== 1) || ( (ntohs(tcp->th_sport)== 21 || ntohs(tcp->th_sport)== 20) && *type== 2) || ( ntohs(tcp->th_sport)== 23 && *type== 3))
		{
        ip_address =  ip->ip_src.s_addr;
        if ( ! session.count({ip_address,ntohs(tcp->th_dport)})) //if there is a match for the key, then go to find, else insert
        session.insert( { {ip_address,ntohs(tcp->th_dport)},string() }); //insert new elements (dynamically increases container size)- vector
        it = session.find({ip_address,ntohs(tcp->th_dport)}); //iterator to the payload, if key matches
        s.append(it->second); //Appending it->second(value) to s
        if ( i == 14 + size_ip + size_tcp)
        {
        if ( msg.count({ip_address,ntohs(tcp->th_dport)})) //check if there is a match of key
        {
        auto ii =  msg.find({ip_address,ntohs(tcp->th_dport)}); //if yes, returns iterator ii
        if ( ii->second != 1)
        s.append("\nResponse:\n");
        }
        else
        s.append("\nResponse:\n");
        }
        session.erase({ip_address,ntohs(tcp->th_dport)}); //remove this key form map
        if ( isprint(packet[i]) || packet[i] == '\n') //check if character is printable, if yes, push
        s.push_back(packet[i]); //the content of packet[i] is moved into the vector
        else
        {
        char temp[100];
        sprintf(temp," %d ",packet[i]); //copy packet[i] into temp
        s.append(temp); //append temp to s
        }
        session.insert( { {ip_address,ntohs(tcp->th_dport)},s }); //dynamically insert data

        if ( msg.count({ip_address,ntohs(tcp->th_dport)})) //if there is a key match
        msg.erase({ip_address,ntohs(tcp->th_dport)});  //remove this key from the map
        msg.insert({{ip_address,ntohs(tcp->th_dport)},1}); //else insert 1
		}

//the same process is repeated for the other side
else if (( ntohs(tcp->th_dport)== 80 && *type== 1) || ( (ntohs(tcp->th_dport)== 21 || ntohs(tcp->th_dport)== 20) && *type== 2) || ( ntohs(tcp->th_dport)== 23 && *type== 3))
		{
        ip_address =  ip->ip_dst.s_addr;
        if ( !session.count({ip_address,ntohs(tcp->th_sport)}))
        session.insert( { {ip_address,ntohs(tcp->th_sport)},string() });
        it = session.find({ip_address,ntohs(tcp->th_sport)});
        s.append(it->second);
        if ( i == 14 + size_ip + size_tcp )
        {
        if ( msg.count({ip_address,ntohs(tcp->th_sport)}))
        {
        auto ii =  msg.find({ip_address,ntohs(tcp->th_sport)});
        if ( ii->second != 2)
        s.append("\nRequest:\n");
        }
        else
        s.append("\nRequest:\n");
        }
        session.erase({ip_address,ntohs(tcp->th_sport)});
        if (isprint(packet[i]) || packet[i] == '\n')
        s.push_back(packet[i]);
        else
        {
        char temp[100];
        sprintf(temp,"%d",packet[i]);
        s.append(temp);
        }
        session.insert( { {ip_address,ntohs(tcp->th_sport)},s });
        if ( msg.count({ip_address,ntohs(tcp->th_sport)}))
        msg.erase({ip_address,ntohs(tcp->th_sport)});
        msg.insert({{ip_address,ntohs(tcp->th_sport)},2});
		}
     }
   return;
}


int main(int argc,char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* hold compiled program     */
    u_char type;                   /* protocol number*/
    pcap_t *handle;
    u_char *packet;
    struct pcap_pkthdr header;

    /* check for capture device name on command-line */
    if (argc == 3)
    {
    dev = argv[1];
    type = atoi(argv[2]);
    }
            
    else if (argc > 3)
    {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    exit(EXIT_FAILURE);
    }

    handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL)
    {
	fprintf(stderr, "error reading pcap file: %s\n", errbuf);
	exit(EXIT_FAILURE);
    }
      switch(type)
    {
    case 1: cout<<"HTTP Protocol";
    break;
    case 2: cout<<"FTP Protocol";
    break;
    case 3: cout<<"TELNET Protocol";
    break;
    }
    
// process the packet
    pcap_loop(handle, -1, got_packet ,&type);

// Go through the hash map and reassemble the payload for the session

    for(auto it = session.begin(); it != session.end(); it++)
    {
	cout << "Session Details: Server IP:" << ip2string(it->first.first) << ", Client Port:" << it->first.second <<endl;
	cout << it->second << endl;
    }
}

