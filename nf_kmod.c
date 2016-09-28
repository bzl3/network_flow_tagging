//'Hello World' netfilter hooks example
//For any packet, we drop it, and log fact to /var/log/messages

//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
/*
  #define NF_DROP 0
  #define NF_ACCEPT 1
  #define NF_STOLEN 2
  #define NF_QUEUE 3
  #define NF_REPEAT 4
  #define NF_STOP 5
  #define NF_MAX_VERDICT NF_STOP
*/

static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
                       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  printk(KERN_INFO "packet Received!!!!!!!!\n");      //log to var/log/messages
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

