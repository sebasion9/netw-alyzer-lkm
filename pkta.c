#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h> // netfilter hooks
#include <linux/netfilter_ipv4.h> // netfilter for ipv4
#include <linux/ip.h>
#include <linux/tcp.h>

#define PACKETS_LEN 500

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops nfho;

// create second hook for NF_INET_LOCAL_OUT?
static struct nf_hook_ops nfho = {
    .hook = hook_func,
    //.hooknum = NF_INET_PRE_ROUTING;
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,                           //IPV4 packets
    .priority = NF_IP_PRI_FIRST,             //set to highest priority over all other hook functions
};

static unsigned char* dev_mem[PACKETS_LEN];
static unsigned int dev_mem_len;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    unsigned char *data;
    unsigned int data_len;

    // handle other protocols too
    if(ip_header->protocol == IPPROTO_TCP) {
        pr_info("TCP Packet\n");
        tcp_header = tcp_hdr(skb);
        pr_info("source port: %u\n", tcp_header->source);
        pr_info("dest port: %u\n", tcp_header->dest);
        data = skb->data;
        data_len = skb->len;
        pr_info("PACKET LEN: %d\n", data_len);

        if(dev_mem_len >= PACKETS_LEN) {
            for(int i = 0; i < PACKETS_LEN - 1; i++) { // -1 for skipping last packet
                dev_mem[i] = dev_mem[i + 1];
            }
            dev_mem[PACKETS_LEN - 1] = data;

        }
        if(dev_mem_len < PACKETS_LEN) {
            dev_mem[dev_mem_len] = data;
        }
        dev_mem_len++;
        pr_info("device memory array length: %d", dev_mem_len);

        // then when read called on char device defined, somehow retrieve the packets
        // take in consideration data races?
        //
        // drops packet
        //return NF_DROP;

    }
    return NF_ACCEPT;
}


static int __init kmod_init(void)
{
    dev_mem_len = 0;
    pr_info("NF module loaded, NF hook registered");
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

static void __exit kmod_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("NF module unloaded");
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sebasion9");
MODULE_DESCRIPTION("packet analyzer");
MODULE_VERSION("0.1");


