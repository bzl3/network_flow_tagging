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
   unsigned int src_ip;
   unsigned int dest_ip;
   unsigned int src_port = 0;
   unsigned int dest_port = 0;

   printk(KERN_INFO "packet Received!!!!!!!!\n");

   ip_header = (struct iphdr *)skb_network_header(skb);   
   eth_header = (struct ethhdr *)skb_mac_header(skb);

   src_ip = (unsigned int)ip_header->saddr;
   dest_ip = (unsigned int)ip_header->daddr;

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


   printk(KERN_INFO "src_ip = 0x%x   src_port = %u    dest_port = %u    protocol = %d \n", src_ip, src_port, dest_port, ip_header->protocol);


   return NF_ACCEPT;                                   //drops the packet
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

   return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
   //cleanup – unregister hook
   nf_unregister_hook(&nfho); 
}

