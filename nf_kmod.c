//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

#define CASSANDRA_SERVER_PORT    9042
#define CASSANDRA_HEADER_OFFSET  66

#if 0 // struct field for reference
/*
  #define NF_DROP 0
  #define NF_ACCEPT 1
  #define NF_STOLEN 2
  #define NF_QUEUE 3
  #define NF_REPEAT 4
  #define NF_STOP 5
  #define NF_MAX_VERDICT NF_STOP
*/

/*
 *      This is an Ethernet frame header.
 */

struct ethhdr {
        unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
        unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
        __be16          h_proto;                /* packet type ID field */
} __attribute__((packed));


struct iphdr {
 #if defined(__LITTLE_ENDIAN_BITFIELD)
         __u8    ihl:4,
                 version:4;
 #elif defined (__BIG_ENDIAN_BITFIELD)
         __u8    version:4,
                 ihl:4;
 #else
 #error  "Please fix <asm/byteorder.h>"
 #endif
         __u8    tos;
         __be16  tot_len;
         __be16  id;
         __be16  frag_off;
         __u8    ttl;
         __u8    protocol;
         __sum16 check;
         __be32  saddr;
         __be32  daddr;
         /*The options start here. */
 };
 
udphdr/tcphdr   check ip->protocol
#endif

/***************************************************************
 * Cassandra header for reference
 *
 *      0         8        16        24        32         40
 *     +---------+---------+---------+---------+---------+
 *     | version |  flags  |      stream       | opcode  |
 *     +---------+---------+---------+---------+---------+
 *     |                length                 |
 *     +---------+---------+---------+---------+
 *     |                                       |
 *     .            ...  body ...              .
 *     .                                       .
 *     .                                       .
 *     +----------------------------------------
 *
 * The protocol is big-endian (network byte order).

 ***************************************************************/

// Cassandra header, header is not packed, packed here
// TODO Check my endianess!!
struct cassandra_hdr {
   __u8    version;
   __u8    flags;
   __be16  stream;
   __u8    opcode;
   __be32  length;
   __u8    padding[3];
};


//struct holding set of hook function options
static struct nf_hook_ops nfho;

//function to be called by hook
unsigned int hook_in_packet(unsigned int hooknum, struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
   struct iphdr *ip_header;
   struct ethhdr *eth_header;
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct cassandra_hdr *ca_header;
   unsigned int src_ip;
   unsigned int dest_ip;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   unsigned char * data = 0;

   ip_header = (struct iphdr *)skb_network_header(skb);   
   eth_header = (struct ethhdr *)skb_mac_header(skb);

   src_ip = ntohl((unsigned int)ip_header->saddr);
   dest_ip = ntohl((unsigned int)ip_header->daddr);

   if (ip_header->protocol==17) 
   {
       // UDP
      udp_header = (struct udphdr *)skb_transport_header(skb);
      src_port = (unsigned int)ntohs(udp_header->source);
      dest_port = (unsigned int)ntohs(udp_header->dest);
   }
   else if (ip_header->protocol == 6) 
   {
      // TCP
      tcp_header = (struct tcphdr *)skb_transport_header(skb);
      src_port = (unsigned int)ntohs(tcp_header->source);
      dest_port = (unsigned int)ntohs(tcp_header->dest);
   }

#ifdef MORE_DEBUG
   printk( KERN_INFO "Received packet from\n\tsrc_ip = 0x%x\n\tsrc_port = %u\n\tdest_port = %u\n\tprotocol = %d \n\th_proto (eth_hdr) = %u\n",
          src_ip, src_port, dest_port, (unsigned int)ntohs(ip_header->protocol), (unsigned int)ntohs(eth_header->h_proto));
#endif

   if ( CASSANDRA_SERVER_PORT == dest_port )
   {
      // TODO Explore cassandra header and insert tagging mechinism here
      printk( KERN_INFO "# Received CASSANDRA REQUEST!\n");
      //ca_header = (struct cassandra_hdr *) skb->data;
      // try magic number 66
      ca_header = ((unsigned char*)skb_mac_header(skb)) + CASSANDRA_HEADER_OFFSET;

      // printk(KERN_INFO "MAC: 0x%p          ca_hdr: 0x%p\n", eth_header, ca_header);
      printk( KERN_INFO "Cassandra header: version: 0x%x   flags: 0x%x   stream: 0x%x    opcode: 0x%x    length: 0x%x\n",
              (unsigned short)(ca_header->version), (unsigned short)(ca_header->flags),
              (unsigned short)(ca_header->stream), (unsigned short)(ca_header->opcode),
              (unsigned int)(ca_header->length));

      data = ((unsigned char*)skb_mac_header(skb)) + 66;
/*
      printk( KERN_INFO "Hex dumping first 9 bytes:\n");
      printk( KERN_INFO " :0\t%2x %2x  %2x %2x\n", (unsigned char)data[0], (unsigned char)data[1], (unsigned char)data[2], (unsigned char)data[3]);
      printk( KERN_INFO " :4\t%2x %2x  %2x %2x\n", (unsigned char)data[4], (unsigned char)data[5], (unsigned char)data[6], (unsigned char)data[7]);
      printk( KERN_INFO " :8\t%2x %2x  %2x %2x\n", (unsigned char)data[8], (unsigned char)data[9], (unsigned char)data[10], (unsigned char)data[11]);
*/
   }
   else if ( CASSANDRA_SERVER_PORT == src_port )
   {
      // TODO Explore cassandra header and insert tagging mechinism here
      printk( KERN_INFO "# Received CASSANDRA RSP~~~~~~~~~~~~~~\n");
      // ca_header = (struct cassandra_hdr *) skb->data;
      ca_header = ((unsigned char*)skb_mac_header(skb)) + CASSANDRA_HEADER_OFFSET;

      printk( KERN_INFO "Cassandra header: version: 0x%x   flags: 0x%x   stream: 0x%x    opcode: 0x%x    length: 0x%x\n",
              (unsigned short)(ca_header->version), (unsigned short)(ca_header->flags),
              (unsigned short)(ca_header->stream), (unsigned short)(ca_header->opcode),
              (unsigned int)(ca_header->length));



      data = ((unsigned char*)skb_mac_header(skb)) + 66;
/*
      printk( KERN_INFO "Hex dumping first 9 bytes:\n");
      printk( KERN_INFO " :0\t%2x %2x  %2x %2x\n", (unsigned char)data[0], (unsigned char)data[1], (unsigned char)data[2], (unsigned char)data[3]);
      printk( KERN_INFO " :4\t%2x %2x  %2x %2x\n", (unsigned char)data[4], (unsigned char)data[5], (unsigned char)data[6], (unsigned char)data[7]);
      printk( KERN_INFO " :8\t%2x %2x  %2x %2x\n", (unsigned char)data[8], (unsigned char)data[9], (unsigned char)data[10], (unsigned char)data[11]);
*/

   }
   else { /* can add other application port here to check */ }

#ifdef MORE_DEBUG
   printk( KERN_INFO "\n");
#endif 

   // Accept everything
   return NF_ACCEPT;
}


//Called when module loaded using 'insmod'
int init_module()
{
   nfho.hook = hook_in_packet;
   //called right after packet recieved, first hook in Netfilter
   nfho.hooknum = NF_INET_PRE_ROUTING;
   nfho.pf = PF_INET;
   //set to highest priority over all other hook functions
   nfho.priority = NF_IP_PRI_FIRST;
   nf_register_hook(&nfho);

   printk( KERN_INFO "Registering PRE_ROUTING Netfilter hook!\n");
   return 0;
}


//Called when module unloaded using 'rmmod'
void cleanup_module()
{
   printk( KERN_INFO "Unregistering PRE_ROUTING Netfilter hook!\n");
   //cleanup – unregister hook
   nf_unregister_hook(&nfho); 
}

