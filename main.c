
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
///////////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netinet/in.h>
#include <stdio.h>


//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
// Define some constants.
#define ETH_HDRLEN 14         // IPv4 header length
#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data
#define ETH_ALEN        6

//Function Prototypes
void buildnsheader  (void);
int  conv_fqdns2rr(char*, char*);
void build_udp_mac_header (unsigned char*,char *,int , char*, int , int,  char*);
void get_dns_packet(unsigned char*,char*,unsigned short,char*,char*,int*);

//Eth header
struct Ethhdr {
unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
unsigned short h_proto;                /* packet type ID field */
};

//DNS header structure

struct DNS_HEADER
{
    unsigned short id; // identification number
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};


struct ADD_RECORDS
{
    unsigned char  Name:8;//0
    unsigned short Type;//41
	unsigned short payloadsize; //4096
    unsigned short Rcode;//0
    unsigned short Z;//0
    unsigned short length;//0

};
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

const char * arg_query;
const char * arg_dmac;

unsigned short cksum(struct ip *ip, int len){
           long sum = 0;  /* assume 32 bit long, 16 bit short */
           unsigned short* iph= (unsigned short*) ip;
           while(len > 1){
             sum += *iph;
             iph++;
             if(sum & 0x80000000)   /* if high order bit set, fold */
               sum = (sum & 0xFFFF) + (sum >> 16);
             len -= 2;
           }

           if(len)       /* take care of left over byte */
             sum += (unsigned short) *(unsigned char *)ip;

           while(sum>>16)
             sum = (sum & 0xFFFF) + (sum >> 16);

           return ~sum;
         }

void build_udp_mac_header (unsigned char *buff,char *saddr,int sport, char *daddr, int dport, int datalen,  char *udppacket)
{


  struct ip *iphdr_ptr;
  struct udphdr *udphdr_ptr;
  unsigned char *data, *packet;
  unsigned  char  x[1000];     //the buffer

  packet  = x;
  iphdr_ptr =(struct ip *) x     ;

  udphdr_ptr =      (struct udphdr *) (packet + IP4_HDRLEN);
//  UDP data ptr .
  data =  (packet + IP4_HDRLEN + UDP_HDRLEN);
//                                                  UDP data -copy it at the end
  memcpy (data,udppacket,datalen);

  iphdr_ptr->ip_hl =5;
  iphdr_ptr->ip_v = 4;
  iphdr_ptr->ip_tos = 0;
  iphdr_ptr->ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
  iphdr_ptr->ip_id = htons (0);
  iphdr_ptr->ip_off = htons (0);
  iphdr_ptr->ip_ttl = 255;
  iphdr_ptr->ip_p = IPPROTO_UDP;
  iphdr_ptr->ip_dst.s_addr = inet_addr (daddr);
  iphdr_ptr->ip_src.s_addr = inet_addr (saddr);     /* SPOOOOPH di source IP */

  iphdr_ptr->ip_sum = 0;
  iphdr_ptr->ip_sum=cksum(iphdr_ptr,20);

//                                                   UDP header
  udphdr_ptr->source = htons (sport);
  udphdr_ptr->dest = htons (dport);
  udphdr_ptr->len = htons (UDP_HDRLEN + datalen);
  udphdr_ptr->check = 0;


   unsigned  char *send_packet;
   struct Ethhdr *ethhdr_ptr;

   send_packet=buff;
   ethhdr_ptr =(struct Ethhdr *) buff;

   unsigned char *mac = ethhdr_ptr->h_dest;
   sscanf(arg_dmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac, mac+1, mac+2, mac+3, mac+4, mac+5);


     mac = ethhdr_ptr->h_source;
     sscanf("00:0c:29:e0:8e:eb", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac, mac+1, mac+2, mac+3, mac+4, mac+5);
     ethhdr_ptr->h_proto=8;




   memcpy(send_packet+sizeof(struct Ethhdr),packet,IP4_HDRLEN + UDP_HDRLEN + datalen);


}




int conv_fqdns2rr(char *hosta, char *outa)
  {
  char m[1000];
  char c[1000],*cp;
  struct QUESTION *qinfo=NULL;
  int i=0;
  memset (m,0,1000);
  memset (c,0,1000);
  strcpy (c, hosta);                    // protect the origin storable from strings.h
  cp  =strtok(c,".");
  sprintf(m+1,"%s",cp);              // first string
  m[0] = (int) strlen(cp);             //  now put the length in the first byte
  strcat(outa,m) ;
//
  while ((cp=strtok(NULL ,".")) != NULL )
    {
    memset (m, 0,1000) ;
    sprintf(m+1,"%s" , cp);
    m[0] = (int) strlen(cp);
    strcat(outa,m) ;
    }
  i= (int) strlen(outa);
// Append the question structure to the end to show its IPV4 and ADDRESS request
  qinfo =  (struct QUESTION * ) &outa[1 +i]; //   Terminate the string  with "\0" then the questions
  qinfo->qtype = htons(1); //type of the query  A
  qinfo->qclass = htons(1); //its internet (lol)
  i = 1 + i + sizeof(struct QUESTION  ) ;
  return(i);
  }

/*
 * build  a DNS query in global variable buf
 * */
void build_dns_header (unsigned char *dns_payload,unsigned char *rr_data,int rr_len)
  {
  unsigned char *qname;
  struct DNS_HEADER *dns = NULL;

  //Set the DNS structure to standard queries
  dns = (struct DNS_HEADER *)dns_payload;

  dns->id = (unsigned short) htons(getpid());
  dns->qr = 0; //This is a query
  dns->opcode = 0; //This is a standard query
  dns->aa = 0; //Not Authoritative
  dns->tc = 0; //This message is not truncated
//   This is key
  dns->rd = 1; //Recursion Desired    1
  dns->ra = 0; //Recursion not available! stub resolver
  dns->z = 0;
  dns->ad = 1;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1); //we have only 1 question couldnt get multi query working
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = htons(1);

  struct ADD_RECORDS add_records;

   add_records.Name=0;//0
   add_records.Type=41;//41
   add_records.payloadsize=htons(4096); //4096
   add_records.Rcode=0;//0
   add_records.Z=0;//0
   add_records.length=0;//0

 // copy in the fqdns to the query p
  qname =(unsigned char*)&dns_payload[sizeof(struct DNS_HEADER)];

// copy the FQDSN at the end

  memcpy(qname , rr_data, rr_len);  // allowed for two dns in the query but never got working
  qname =(unsigned char*)&dns_payload[sizeof(struct DNS_HEADER)+rr_len+1];
  memcpy(qname-1 , &add_records, sizeof(struct ADD_RECORDS));


  }

void get_dns_packet(unsigned char *buff,char *src,unsigned short port,char *dest,char *question_domain,int *dns_length)
  {

   unsigned char rr_data[1000];
   char *rr_data_temp;
   rr_data_temp=(char *)rr_data;
   memset(rr_data_temp,0,1000);
   printf("query name is %s\n",question_domain);
   printf("query length is %i\n",(int)strlen(question_domain));
   int rr_len=  conv_fqdns2rr(question_domain,rr_data_temp);
  *dns_length = rr_len+12+11;
  printf("rr_len is %d,dnslenght is %d\n",rr_len,*dns_length);
  unsigned char dns_payload[1000];
  build_dns_header(dns_payload,rr_data,rr_len);
  build_udp_mac_header(buff,src ,port, dest, 53 , *dns_length, (char *)dns_payload);



}


////////////////////////////////////////////////////////////////////////////////////////




/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1
#define FATAL_ERROR(fmt, args...)       rte_exit(EXIT_FAILURE, fmt "\n", ##args)
#define PRINT_INFO(fmt, args...)        RTE_LOG(INFO, APP, fmt "\n", ##args)

/* Max ports than can be used (each port is associated with two lcores) */
#define MAX_PORTS               (RTE_MAX_LCORE / 2)

/* Max size of a single packet */
#define MAX_PACKET_SZ (2048)

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 8192

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  128

/* Number of TX ring descriptors */
#define NB_TXD                  512

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */

/* Options for configuring ethernet port */
static const struct rte_eth_conf port_conf = {
  .rxmode = {
    .header_split = 0,      /* Header Split disabled */
    .hw_ip_checksum = 0,    /* IP checksum offload disabled */
    .hw_vlan_filter = 0,    /* VLAN filtering disabled */
    .jumbo_frame = 0,       /* Jumbo Frame Support disabled */
    .hw_strip_crc = 0,      /* CRC stripped by hardware */
  },
  .txmode = {
    .mq_mode = ETH_MQ_TX_NONE,

  },
};

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;

/* Mask of cores that read from NIC and write to tap */


/* Mask of cores that read from tap and write to NIC */
static uint64_t output_cores_mask = 0;


/* Array storing port_id that is associated with each lcore */
static uint8_t port_ids[RTE_MAX_LCORE];

/* Structure type for recording lcore-specific stats */
struct stats {
  uint64_t rx;
  uint64_t tx;
  uint64_t dropped;
};

/* Array of lcore-specific stats */
static struct stats lcore_stats[RTE_MAX_LCORE];

/* Print out statistics on packets handled */
static void
print_stats(void)
{
  unsigned i;

  printf("\n**Exception-Path example application statistics**\n"
         "=======  ======  ============  ============  ===============\n"
         " Lcore    Port            RX            TX    Dropped on TX\n"
         "-------  ------  ------------  ------------  ---------------\n");
  RTE_LCORE_FOREACH(i) {
    printf("%6u %7u %13"PRIu64" %13"PRIu64" %16"PRIu64"\n",
           i, (unsigned)port_ids[i],
           lcore_stats[i].rx, lcore_stats[i].tx,
           lcore_stats[i].dropped);
  }
  printf("=======  ======  ============  ============  ===============\n");
}

/* Custom handling of signals to handle stats */
static void
signal_handler(int signum)
{
  /* When we receive a USR1 signal, print stats */
  if (signum == SIGUSR1) {
	system("clear");
    print_stats();
  }

  /* When we receive a USR2 signal, reset stats */
  if (signum == SIGUSR2) {
    memset(&lcore_stats, 0, sizeof(lcore_stats));
    printf("\n**Statistics have been reset**\n");
    return;
  }
}



/* Main processing loop */
static int main_loop(__attribute__((unused)) void *arg)
{

  const unsigned lcore_id = rte_lcore_id();


  char argv_2[] ="172.16.1.252";
  const char *question=arg_query;
  char argv_1[] ="10.128.10.";

  int dns_len=0;
  char buff[1000];
  char scr_ip[15];

  sprintf((char *)&scr_ip,"%s%d",argv_1,lcore_id+1);
  get_dns_packet((unsigned char*)&buff,(char *)&scr_ip,5555,(char *)&argv_2,(char *)question,&dns_len);
  int total_len =ETH_HDRLEN+IP4_HDRLEN+UDP_HDRLEN+dns_len;
  struct ip *iphdr_ptr=(struct ip *)(buff+ETH_HDRLEN);
  struct udphdr *udphdr_ptr=(struct udphdr *)(buff+ETH_HDRLEN+IP4_HDRLEN);
  uint16_t base_port = htons(1025);
  udphdr_ptr->source= base_port;
  struct rte_mbuf *m = rte_pktmbuf_alloc(pktmbuf_pool);
  printf("lcord id : %i using port id: %i\n",lcore_id,port_ids[lcore_id]);

    for (;;) {
      int ret;

      if (unlikely(udphdr_ptr->source>=65534))
      {
    	  iphdr_ptr->ip_src.s_addr++;
    	  iphdr_ptr->ip_sum=0;
    	  iphdr_ptr->ip_sum=cksum(iphdr_ptr,20);
    	  udphdr_ptr->source= base_port;

      }else
      {
    	  udphdr_ptr->source++;
       }



      memcpy(rte_pktmbuf_mtod(m, void *),(unsigned char*)buff,total_len);


      m->nb_segs = 1;
      m->next = NULL;
      m->pkt_len = total_len;
      m->data_len = total_len;
      m->l2_len=14;
      m->l3_len=20;
      m->ol_flags |= PKT_TX_IP_CKSUM;
      ret = rte_eth_tx_burst(port_ids[lcore_id], 0, &m, 1);
      if (unlikely(ret < 1)) {
       // rte_pktmbuf_free(m);
        lcore_stats[lcore_id].dropped++;
      }
      else {
        lcore_stats[lcore_id].tx++;
      }
     }

 return 0;
}

/* Display usage instructions */
static void
print_usage(const char *prgname)
{
  PRINT_INFO("\nUsage: %s [EAL options] -- -p PORTMASK -i IN_CORES -o OUT_CORES\n"
             "    -p PORTMASK: hex bitmask of ports to use\n"
             "    -o OUT_CORES: hex bitmask of cores which write to NIC",
             prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint64_t
parse_unsigned(const char *portmask)
{
  char *end = NULL;
  uint64_t num;

  num = strtoull(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return 0;

  return (uint64_t)num;
}

/* Record affinities between ports and lcores in global port_ids[] array */
static void setup_port_lcore_affinities(void)
{
  unsigned long i;
  uint8_t tx_port = 0;


  /* Setup port_ids[] array, and check masks were ok */
  RTE_LCORE_FOREACH(i) {
         printf("setup port lcord affinities core %lu\n",i);
     if (output_cores_mask & (1ULL << i)) {
      /* Skip ports that are not enabled */
      while ((ports_mask & (1 << tx_port)) == 0) {
        tx_port++;
        if (tx_port > (sizeof(ports_mask) * 8))
          goto fail; /* not enough ports */
      }

      port_ids[i] = tx_port++;
    }
  }



  return;
fail:
  FATAL_ERROR("Invalid core/port masks specified on command line");
}

/* Parse the arguments given in the command line of the application */
static void parse_args(int argc, char **argv)
{
  int opt;
  const char *prgname = argv[0];

  /* Disable printing messages within getopt() */
  opterr = 0;

  /* Parse command line */
  while ((opt = getopt(argc, argv, "o:p:q:d:")) != EOF) {
    switch (opt) {

    case 'o':
      output_cores_mask = parse_unsigned(optarg);
      break;
    case 'p':
      ports_mask = parse_unsigned(optarg);
      break;
    case 'q':
          arg_query = optarg;
          break;
    case 'd':
          arg_dmac = optarg;
          break;
    default:
      print_usage(prgname);
      FATAL_ERROR("Invalid option specified");
    }
  }

  /* Check that options were parsed ok */

  if (output_cores_mask == 0) {
    print_usage(prgname);
    FATAL_ERROR("OUT_CORES not specified correctly");
  }
  if (ports_mask == 0) {
    print_usage(prgname);
    FATAL_ERROR("PORTMASK not specified correctly");
  }

  setup_port_lcore_affinities();
}

/* Initialise a single port on an Ethernet device */
static void init_port(int8_t port)
{
  int ret;
  struct rte_eth_txconf *txconf;
  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(port,&dev_info);
  /* Initialise device and RX/TX queues */
  PRINT_INFO("Initialising port %u ...", (unsigned)port);
  fflush(stdout);
  ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
  if (ret < 0)
    FATAL_ERROR("Could not configure port%u (%d)",
                (unsigned)port, ret);

  ret = rte_eth_rx_queue_setup(port, 0, NB_RXD, rte_eth_dev_socket_id(port),
        NULL,
        pktmbuf_pool);
  if (ret < 0)
    FATAL_ERROR("Could not setup up RX queue for port%u (%d)",
                (unsigned)port, ret);
    txconf = &dev_info.default_txconf;
    txconf->txq_flags=0;
  ret = rte_eth_tx_queue_setup(port, 0, NB_TXD, rte_eth_dev_socket_id(port),
        0);
  if (ret < 0)
    FATAL_ERROR("Could not setup up TX queue for port%u (%d)",
                (unsigned)port, ret);

  ret = rte_eth_dev_start(port);
  if (ret < 0)
    FATAL_ERROR("Could not start port%u (%d)", (unsigned)port, ret);

  //rte_eth_promiscuous_enable(port);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
  uint8_t portid, count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;

  printf("\nChecking link status");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    all_ports_up = 1;
    for (portid = 0; portid < port_num; portid++) {
      if ((port_mask & (1 << portid)) == 0)
        continue;
      memset(&link, 0, sizeof(link));
      rte_eth_link_get_nowait(portid, &link);
      /* print link status if flag set */
      if (print_flag == 1) {
        if (link.link_status)
          printf("Port %d Link Up - speed %u "
            "Mbps - %s\n", (uint8_t)portid,
            (unsigned)link.link_speed,
        (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
          ("full-duplex") : ("half-duplex\n"));
        else
          printf("Port %d Link Down\n",
            (uint8_t)portid);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == 0) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1)
      break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

/* Initialise ports/queues etc. and start main loop on each core */
int main(int argc, char** argv)
{
  int ret;
  unsigned i,high_port;
  uint8_t nb_sys_ports, port;

    /* Associate signal_hanlder function with USR signals */
  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);

  /* Initialise EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    FATAL_ERROR("Could not initialise EAL (%d)", ret);
  argc -= ret;
  argv += ret;

  /* Parse application arguments (after the EAL ones) */
  parse_args(argc, argv);
  /* Create the mbuf pool */
  pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
      MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
  if (pktmbuf_pool == NULL) {
    FATAL_ERROR("Could not initialise mbuf pool");
    return -1;
  }

  /* Get number of ports found in scan */
  nb_sys_ports = rte_eth_dev_count();
  if (nb_sys_ports == 0)
    FATAL_ERROR("No supported Ethernet device found");
  /* Find highest port set in portmask */
  for (high_port = (sizeof(ports_mask) * 8) - 1;
      (high_port != 0) && !(ports_mask & (1 << high_port));
      high_port--)
    ; /* empty body */
  if (high_port > nb_sys_ports)
    FATAL_ERROR("Port mask requires more ports than available");

  /* Initialise each port */
  for (port = 0; port < nb_sys_ports; port++) {
    /* Skip ports that are not enabled */
    if ((ports_mask & (1 << port)) == 0) {
      continue;
    }
    init_port(port);
  }
  check_all_ports_link_status(nb_sys_ports, ports_mask);

  /* Launch per-lcore function on every lcore */
  rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
  RTE_LCORE_FOREACH_SLAVE(i) {
    if (rte_eal_wait_lcore(i) < 0)
      return -1;
  }

  return 0;
}







