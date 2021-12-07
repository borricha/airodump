#include "headers.h"

void usage();
Mac mymac;
//void get_mymac(char *dev);
std::map <Mac, int> beacon_num;
std::map <Mac, std::string> essid_map;


int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];

    // get_mymac(dev);
    // printf("My Mac: %s\n", std::string(mymac).data());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    struct pcap_pkthdr *header;
    const u_char *Packet;

    while(true)
    {
        int res = pcap_next_ex(handle, &header, &Packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
         
        radiotap_header *rt_hdr = (struct radiotap_header*)Packet;
        beacon_header * bc_hdr = (struct beacon_header*)(Packet + rt_hdr->it_len);
        
        //Beacon frame check
        if(bc_hdr->frame_control != 0x80)
            continue;
        //printf("Beacon check\n");
        //printf("BSSID: %s\n",std::string(bc_hdr->bssid).data());

        std::string SSID(bc_hdr->ssid, bc_hdr->len);
        //std::cout << "ESSID: " << SSID;



        //BSSID map
        if(beacon_num.find(bc_hdr->bssid) == beacon_num.end())
        {
            int num = 1;
            beacon_num.insert({bc_hdr->bssid, num});
            essid_map.insert({bc_hdr->bssid, SSID});
        }
        else
        {
            beacon_num[bc_hdr->bssid] += 1;
        }
        
        for (auto itr = beacon_num.begin(); itr != beacon_num.end(); itr++)
        {
            printf("BSSID: %s  ", std::string(itr->first).data());
            printf("beacon: %d  ", itr->second);
            std::cout << "ESSID: " << essid_map[itr->first];
            printf("\n");
        }
        printf("\n\n\n");



    }
    pcap_close(handle);
    return 0;

    
}


void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\"\n");
}


void get_mymac(char *dev)
{
    int fd;
    struct ifreq ifr;
    const char *iface = dev;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        mymac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }


    close(fd);
    return;
}