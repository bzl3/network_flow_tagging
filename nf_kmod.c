//'Hello World' netfilter hooks example
//For any packet, we drop it, and log fact to /var/log/messages

//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>

#if 0
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

static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
   struct iphdr * ip_header;
   struct ethhdr * eth_header;
   unsigned int src_ip;
   unsigned int dest_ip;

   printk(KERN_INFO "packet Received!!!!!!!!\n");      //log to var/log/messages

   ip_header = (struct iphdr *)skb_network_header(skb);   
//   eth_header = (struct ethhdr *)skb_mac_header(skb);
//                   skb_transport_header(skb);

   src_ip = (unsigned int)ip_header->saddr;
   dest_ip = (unsigned int)ip_header->daddr;

   printk(KERN_INFO "src_ip = 0x%x     protocol = %d \n", src_ip, ip_header->protocol);



   return NF_ACCEPT;                                   //drops the packet
}

//Called when module loaded using 'insmod'
int init_module()
{
   nfho.hook = hook_func;                       //function to call when conditions below met
//  nfho.hooknum = NF_IP_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
   nfho.hooknum = NF_INET_PRE_ROUTING;
   nfho.pf = PF_INET;                           //IPV4 packets
   nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
   nf_register_hook(&nfho);                     //register hook

   return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
   nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}

