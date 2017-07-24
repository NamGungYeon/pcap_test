void* print_eht(void* vP)
{
	struct ether_header* ehP = (struct ether_header *)vP;
	printf("eth.smac : %02x:%02x:%02x:%02x:%02x:%02x\n", ehP->ether_shost[0],ehP->ether_shost[1],ehP->ether_shost[2],ehP->ether_shost[3],ehP->ether_shost[4],ehP->ether_shost[5]);
	printf("eth.dmac : %02x:%02x:%02x:%02x:%02x:%02x\n", ehP->ether_dhost[0],ehP->ether_dhost[1],ehP->ether_dhost[2],ehP->ether_dhost[3],ehP->ether_dhost[4],ehP->ether_dhost[5]);
	
	//printf("ip.dip :%s\n",inet_ntoa(iph->daddr));

}
void* print_ip(void* vP)
{
	struct iphdr *iph = (struct iphdr *)vP;
	char buf[20];
	printf("idp.sip : %s\n", inet_ntop(AF_INET, &iph->saddr, buf, sizeof(buf)));
	printf("idp.dip : %s\n", inet_ntop(AF_INET, &iph->daddr, buf, sizeof(buf)));
	
	
}


void* print_tcp(void* vP)
{
	struct tcphdr *tph = (struct tcphdr *)vP;
	printf("tcp size : %d\n", sizeof(struct tcphdr));
	printf("tcp.sport : %d\n", ntohs(tph->th_sport));
	printf("tcp.dport : %d\n", ntohs(tph->th_dport));	
}

void* print_data(void* vP)
{
	struct iphdr * iph = (struct iphdr *)vP;
	char buf[40];
	

}
