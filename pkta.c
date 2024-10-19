#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h> // netfilter hooks
#include <linux/netfilter_ipv4.h> // netfilter for ipv4
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define PACKETS_LEN 500 * 1024
#define ROWSIZE 16

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static struct nf_hook_ops nfho_in = {
    .hook = hook_func,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,                           //IPV4 packets
    .priority = NF_IP_PRI_FIRST,             //set to highest priority over all other hook functions
};


static struct nf_hook_ops nfho_out = {
    .hook = hook_func,
    .hooknum = NF_INET_POST_ROUTING,
    .pf = PF_INET,                           //IPV4 packets
    .priority = NF_IP_PRI_FIRST,             //set to highest priority over all other hook functions
};

//static unsigned char packets_buff[PACKETS_LEN];
static unsigned int tcp_packets_len;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    unsigned char* tail;
    int len;
    u16 sport, dport;
    u32 saddr, daddr;

    // packet is empty, some problem occured, skip the packet
    if(!skb) {
        return NF_ACCEPT;
    }

    iphdr = ip_hdr(skb);

    if(iphdr->protocol == IPPROTO_TCP) {
        tcphdr = tcp_hdr(skb);
        // convert network endiannes to host endiannes
        saddr = iphdr->saddr;
        daddr = iphdr->daddr;
        sport = tcphdr->source;
        dport = tcphdr->dest;

        tail = skb_tail_pointer(skb);

        printk(KERN_INFO "tcp packet route: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr, dport);
        printk(KERN_INFO "skb fields:\n");
        printk(KERN_CONT "len: %d\t", skb->len);
        printk(KERN_CONT "len: %d\t", skb->data_len);
        printk(KERN_CONT "mac_len: %d\t", skb->mac_len);
        printk(KERN_CONT "hdr_len: %d\t", skb->hdr_len);
        printk(KERN_CONT "\n\n");
        printk(KERN_CONT "tail: %p\t", tail);
        printk(KERN_CONT "head: %p\t", skb->head);
        printk(KERN_CONT "data: %p\t", skb->data);
        printk(KERN_CONT "tail no pointer: %d\t", skb->tail);
        printk(KERN_CONT "end: %d\t", skb->end);

        printk(KERN_CONT "\n\n");
        printk(KERN_CONT "attempt to read data\n");


        len = skb->len;
        for(int i = 0; i < len; i++) {
            printk(KERN_CONT "%02x\t", skb->data[i]);
            if(i != 0 && i % ROWSIZE == 0)
                printk(KERN_CONT "\n");
        }
        printk(KERN_CONT "\n\n");
        for(int i = 0; i < len; i++) {
            printk(KERN_CONT "%c\t", skb->data[i]);
            if(i != 0 && i % ROWSIZE == 0)
                printk(KERN_CONT "\n");
        }


        return NF_ACCEPT;
    }
    if(iphdr->protocol == IPPROTO_UDP) {
        udphdr = udp_hdr(skb);
        // convert network endiannes to host endiannes
        saddr = iphdr->saddr;
        daddr = iphdr->daddr;
        sport = udphdr->source;
        dport = udphdr->dest;

        tail = skb_tail_pointer(skb);

        printk(KERN_INFO "tcp packet route: %pI4h:%d -> %pI4h:%d\n", &saddr, sport, &daddr, dport);
        printk(KERN_INFO "skb fields:\n");
        printk(KERN_CONT "len: %d\t", skb->len);
        printk(KERN_CONT "len: %d\t", skb->data_len);
        printk(KERN_CONT "mac_len: %d\t", skb->mac_len);
        printk(KERN_CONT "hdr_len: %d\t", skb->hdr_len);
        printk(KERN_CONT "\n\n");
        printk(KERN_CONT "tail: %p\t", tail);
        printk(KERN_CONT "head: %p\t", skb->head);
        printk(KERN_CONT "data: %p\t", skb->data);
        printk(KERN_CONT "tail no pointer: %d\t", skb->tail);
        printk(KERN_CONT "end: %d\t", skb->end);

        printk(KERN_CONT "\n\n");
        printk(KERN_CONT "attempt to read data\n");


        len = skb->len;
        for(int i = 0; i < len; i++) {
            printk(KERN_CONT "%02x\t", skb->data[i]);
            if(i != 0 && i % ROWSIZE == 0)
                printk(KERN_CONT "\n");
        }
        printk(KERN_CONT "\n\n");
        for(int i = 0; i < len; i++) {
            printk(KERN_CONT "%c\t", skb->data[i]);
            if(i != 0 && i % ROWSIZE == 0)
                printk(KERN_CONT "\n");
        }


        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}


static int __init kmod_init(void)
{
    tcp_packets_len = 0;
    pr_info("NF module loaded, NF hooks registered");
    nf_register_net_hook(&init_net, &nfho_in);
    nf_register_net_hook(&init_net, &nfho_out);
    return 0;
}

static void __exit kmod_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_in);
    nf_unregister_net_hook(&init_net, &nfho_out);
    pr_info("NF module unloaded");
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sebasion9");
MODULE_DESCRIPTION("packet analyzer");
MODULE_VERSION("0.1");


