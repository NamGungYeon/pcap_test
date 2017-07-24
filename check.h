int check(void* vP)
{
	struct ether_header* ehP=(struct ether_header *)vP;
	struct iphdr *iph = (struct iphdr *)(vP+sizeof(struct ether_header));
	if((ehP->ether_type==8)&&(iph->protocol==6))
		{
			printf("check\n");
			return 0;
	}
	else
		return -1;

}

