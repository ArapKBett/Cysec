#include <pcap.h>
#include <iostream>
#include <string>

void packet_handler(u_char* /* args */, const struct pcap_pkthdr *header, const u_char* /* packet */) {
    std::cout << "Packet captured: " << header->len << " bytes at "
              << header->ts.tv_sec << "s\n";
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string device = "wlan0"; // Default device, override with arg if provided
    if (argc > 1) {
        device = argv[1];
    }

    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device " << device << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Starting packet capture on " << device << "...\n";
    pcap_loop(handle, 10, packet_handler, nullptr); // Capture 10 packets
    pcap_close(handle);
    std::cout << "Packet capture completed\n";
    return 0;
}
