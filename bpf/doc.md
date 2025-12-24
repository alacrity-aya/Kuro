```
txt

 [TC Gress Entry (skb)]
                |
                v
     +-----------------------+
     |     check_limit()     | <--- 1. Token Bucket Rate Limiting
     +----------+------------+
                |
         +------+------+
         |             |
      [Drop]       [Accept]
         |             |
         v             v
    TC_ACT_SHOT   +---------------------------+
                  | Parse Ethernet Header     |
                  +-------------+-------------+
                                |
                     Branch by eth->h_proto
                 +--------------+--------------+
                 |                             |
           [ETH_P_ARP]                    [ETH_P_IP]
                 |                             |
                 v                             v
       +-------------------+         +-----------------------+
       |   handle_arp()    |         |  Parse IP Header      |
       +---------+---------+         +-----------+-----------+
                 |                             |
       Extract arp->ar_tip           Extract ip->daddr
       (Target IPv4)                 (Destination IPv4)
                 |                             |
                 +--------------+--------------+
                                |
                                v
                 +------------------------------+
                 | lookup(redirect_map, IP)     | <--- 2. Routing Lookup
                 +--------------+---------------+
                                |
                       +--------+--------+
                       |                 |
                   [Not Found]        [Found]
                       |                 |
                       v                 v
                  TC_ACT_OK      bpf_redirect_peer(ifindex)
               (Pass to stack)      (Redirect to Peer)


```
