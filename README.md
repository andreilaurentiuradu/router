# Radu Andrei-Laurentiu - 322CC

# Am rezolvat urmatoarele cerinte:

# Procesul de dirijare
- initializam bufferul de stdout
- parsam tabela de rutare si tabela static ARP folosind apiurile existente
- cream trie-ul pe care se va face cautarea LCM castand in binar masca si prefixul si facand transformarile din network to host
- verificam daca pachetul este de tip IPv4 comparand type-ul headerului ethernet cu 0x0800
- in caz afirmativ incepem sa facem verificari
- daca routerul este destinatia routerul nu trebuie sa trimita mai departe pachetul
- verificam checksum-ul facand conversiile din host in network si TTL-ul
- actualizam TTL-ul(il decrementam)
- cautam destinatia in tabela de routare pe baza algoritmului LCM
- actualizam checksum-ul facand conversiile din host in network 
- rescriem adresele L2 pe baza tabelei ARP statice
- trimitem pachetul

# Longest Prefix Match eficient
- cream un trie pe baza tabelei de routare, utilizand functiile de creare nod, respectiv de adaugare in trie a nodului 
- parcurgem trie-ul pana gasim LCM-ul

# Protocolul ICMP 
Utilizam functia send_ICMP in cazul in care routerul este destinatia, TTL-ul este 0 sau 1, nu am gasit o intrare potrivita in tabela de routare folosind LCM
Functia construieste bufferul mesajului stocand datele necesare si urmeaza urmatorii pasi:
- interschimba adresele MAC sursa si destinatie
- seteaza type-ul si codul in headerul pachetului ICMP
- setam noile adrese, TTL-ul, actualizam lungimea totala si recalculam checksum-ul
- calculam LCM-ul si trimitem mesajul

