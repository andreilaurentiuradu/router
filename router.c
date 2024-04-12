#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib.h"
#include "protocols.h"
#include "queue.h"
#define nr_entries 100000
#define ether_header_size 6

typedef struct TrieNode {
    struct route_table_entry *data;
    struct TrieNode *children[2];
    bool is_terminal;
} TrieNode;

// functie pentru crearea unui nod
struct TrieNode *create_node() {
    struct TrieNode *node = (struct TrieNode *)malloc(sizeof(struct TrieNode));
    node->data = NULL;
    node->children[0] = NULL;
    node->children[1] = NULL;
    node->is_terminal = false;
    return node;
}

// functie pentru adaugarea unui nod in trie
void insert_node(struct TrieNode *root, int bits[32], int mask_bits,
                 struct route_table_entry *entry) {
    struct TrieNode *current = root;

    for (int i = 0; i < mask_bits; i++) {
        if (!current->children[bits[i]]) {
            current->children[bits[i]] = create_node();
        }
        current = current->children[bits[i]];
    }

    current->data = entry;
    current->is_terminal = true;
}
// interschimbarea a doua valori
void swap(void *a, void *b, size_t size) {
    void *aux = malloc(size);
    memcpy(aux, a, size);
    memcpy(a, b, size);
    memcpy(b, aux, size);
    free(aux);
}

// transformarea unui numar din int intr-un vector de biti
void int2bits(uint32_t source, int dest[]) {
    int poz = 0;
    do {
        dest[poz++] = source % 2;
        source >>= 1;
    } while (source);

    for (poz = 0; poz < 16; poz++) {
        swap(&dest[poz], &dest[31 - poz], sizeof(int));
    }
}

// gasim intrarea din tabela de rutare cu masca cea mai mare
struct route_table_entry *longest_prefix_match(struct TrieNode *r,
                                               int destination[32]) {
    struct route_table_entry *ans = NULL;
    struct TrieNode *curr = r;

    for (int i = 0; i < 32; i++) {
        if (curr->is_terminal) {
            ans = curr->data;
        }

        curr = curr->children[destination[i]];

        if (!curr) {
            return ans;
        }
    }

    return ans;
}

// TODO
void send_ICMP(struct TrieNode *root, uint32_t router_ipaddr, char *buf,
               uint8_t given_type, uint8_t given_code, uint8_t given_ttl,
               struct iphdr *ip_hdr, struct ether_header *eth_hdr) {
    char icmp_package[MAX_PACKET_LEN];
    struct ether_header *ETH_HDR = (struct ether_header *)icmp_package;
    memcpy(ETH_HDR, eth_hdr, sizeof(struct ether_header));
    memcpy(ETH_HDR->ether_dhost, eth_hdr->ether_shost, ether_header_size);
    memcpy(ETH_HDR->ether_shost, eth_hdr->ether_dhost, ether_header_size);
    // swap(&(eth_hdr->ether_shost), &(eth_hdr->ether_dhost),
    // ether_header_size);

    struct iphdr *IP_HDR =
        (struct iphdr *)(icmp_package + sizeof(struct ether_header));
    memcpy(IP_HDR, ip_hdr, sizeof(struct iphdr));
    IP_HDR->protocol = IPPROTO_ICMP;
    IP_HDR->saddr = router_ipaddr;
    IP_HDR->daddr = ip_hdr->saddr;
    IP_HDR->check = 0;
    IP_HDR->ttl = given_ttl;

    struct icmphdr *ICMP_HDR =
        (struct icmphdr *)(icmp_package + sizeof(struct ether_header) +
                           sizeof(struct iphdr));
    ICMP_HDR->type = given_type;
    ICMP_HDR->code = given_code;
    ICMP_HDR->checksum = 0;

    memcpy(icmp_package + sizeof(struct ether_header) + sizeof(struct iphdr) +
               sizeof(struct icmphdr),
           ip_hdr, sizeof(struct iphdr));
    memcpy(icmp_package + sizeof(struct ether_header) + sizeof(struct iphdr) +
               sizeof(struct icmphdr) + sizeof(struct iphdr),
           buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

    IP_HDR->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) +
                      sizeof(struct iphdr) + 8;

    ICMP_HDR->checksum =
        htons(checksum((uint16_t *)ICMP_HDR,
                       sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

    IP_HDR->check = htons(checksum(
        (uint16_t *)IP_HDR, sizeof(struct iphdr) + sizeof(struct icmphdr) +
                                sizeof(struct iphdr) + 8));

    int Destination[32] = {0};
    int2bits(ntohl(IP_HDR->daddr), Destination);

    struct route_table_entry *pack_source =
        longest_prefix_match(root, Destination);

    send_to_link(pack_source->interface, icmp_package,
                 sizeof(struct ether_header) + 2 * sizeof(struct iphdr) +
                     sizeof(struct icmphdr) + 8);
}

int main(int argc, char *argv[]) {
    // initializam bufferul de stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    // bufferul
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // tabela de rutare
    struct route_table_entry *rt_tbl =
        malloc(sizeof(struct route_table_entry) * nr_entries);
    int rtable_len = read_rtable(argv[1], rt_tbl);

    // tabela arp statica, luata din fisier
    struct arp_table_entry *arp_tbl =
        malloc(sizeof(struct arp_table_entry) * nr_entries);
    int arp_tbl_leng = parse_arp_table("arp_table.txt", arp_tbl);

    // vectorii ce vor contine prefixul si masca transformate in biti
    int prefix_bits[32] = {0};
    int mask_bits[32] = {0};

    // trie-ul in care se va face cautarea
    struct TrieNode *root = create_node();

    // cream trie-ul
    for (int i = 0; i < rtable_len; i++) {
        /*
        Datele sunt initial in Network Order
        Facem castul la Host Order
        Transformam datele din intregi in vectori de biti
        */
        int2bits(ntohl(rt_tbl[i].prefix), prefix_bits);
        int2bits(ntohl(rt_tbl[i].mask), mask_bits);

        // calculam nr de biti de 1 al mastii
        int mask_ones = 0;
        for (int i = 0; i < 32; ++i) {
            if (mask_bits[i] == 1) {
                mask_ones++;
            }
        }

        // adaugam un nodul corespunzator intrarii din tabelul de rutare in trie
        insert_node(root, prefix_bits, mask_ones, &rt_tbl[i]);
    }

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is
       needed when sending a packet on the link, */

        printf("Pachet primit\n");

        // facem cast buferului
        struct ether_header *eth_hdr = (struct ether_header *)buf;

        // verificam daca este un pachet de tip IPv4
        if (ntohs(eth_hdr->ether_type) == 0x0800) {
            // extragem headerul IPv4
            struct iphdr *ip_hdr =
                (struct iphdr *)(buf + sizeof(struct ether_header));

            uint32_t router_ipaddr = inet_addr(get_interface_ip(interface));

            // 1 verificam daca routerul este destinatia
            if (router_ipaddr == ip_hdr->daddr) {
                send_ICMP(root, router_ipaddr, buf, 0, 0, 0, ip_hdr, eth_hdr);
                // send_ICMP_echo_reply(interface, buf, eth_hdr, ip_hdr);
                continue;
            } else {
                printf("Pachetul are alta destinatie\n");
            }

            // 2 verificam checksum-ul
            // pastram checksum-ul vechi
            int old_check = ip_hdr->check;

            // resetam checksum-ul
            ip_hdr->check = 0;

            // recalculam checksum-ul
            int new_check =
                htons(checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len)));

            if (old_check != new_check) {
                printf("Pachet corupt\n");
                continue;
            }

            // 3.1 verificare TTL
            if (ip_hdr->ttl == 1 || ip_hdr->ttl == 0) {
                send_ICMP(root, router_ipaddr, buf, 11, 0, 64, ip_hdr, eth_hdr);
                continue;
            }

            // 3.2 actualizare TTL
            ip_hdr->ttl--;

            // 4 cautam destinatia pachetului
            // destinatia pachetului
            int destination[32] = {0};

            // facem conversia adresei din nr intreg in biti
            int2bits(ntohl(ip_hdr->daddr), destination);

            // gasim intrarea din tabela de routare cu masca cea mai mare
            struct route_table_entry *entry =
                longest_prefix_match(root, destination);

            // 5 actualizare checksum
            ip_hdr->check = 0;
            ip_hdr->check =
                htons(checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len)));

            // daca nu exista
            if (entry == NULL) {
                send_ICMP(root, router_ipaddr, buf, 3, 0, 0, ip_hdr, eth_hdr);
                continue;
            }

            // 6 rescriere adrese L2
            // gasim adresa mac
            get_interface_mac(interface, eth_hdr->ether_shost);

            // actualizam adresele L2 pe baza urmatorului hop
            for (int i = 0; i < arp_tbl_leng; i++) {
                if (arp_tbl[i].ip == entry->next_hop) {
                    memcpy(eth_hdr->ether_dhost, arp_tbl[i].mac,
                           ether_header_size);
                    break;
                }
            }

            // 7 trimitem pachetul
            send_to_link(entry->interface, buf, len);
        }
        // pachetele care nu sunt de tip IPv4 sunt ignorate(TODO pentru ARP)
    }
}
