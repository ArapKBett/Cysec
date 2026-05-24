#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>
#include <csignal>
#include <algorithm>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <iphlpapi.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
    #define usleep(x) Sleep((x)/1000)
#elif defined(__APPLE__)
    #include <sys/socket.h>
    #include <ifaddrs.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/if_ether.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <net/if.h>
#else // Linux
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/if_ether.h>
    #include <arpa/inet.h>
    #include <ifaddrs.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <net/if.h>
#endif

struct PacketStats {
    int total_packets = 0;
    int tcp_packets = 0;
    int udp_packets = 0;
    int icmp_packets = 0;
    int other_packets = 0;
    std::map<std::string, int> ip_sources;
    std::map<std::string, int> ip_destinations;
    std::map<int, int> ports;
    int total_bytes = 0;
};

struct NetworkInterface {
    std::string name;
    std::string ip;
    std::string netmask;
    bool is_active;
};

static bool running = true;
static PacketStats stats;

void signal_handler(int /* sig */) {
    running = false;
}

void packet_handler(u_char* /* user_data */, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    stats.total_packets++;
    stats.total_bytes += pkthdr->len;

    // Basic ethernet header size (14 bytes)
    if (pkthdr->len < 14) return;

    // Skip ethernet header and get to IP header
    const u_char* ip_packet = packet + 14;

    // Basic IP header check
    if (pkthdr->len < 34) return; // Min size for IP + TCP/UDP header

    // Simple IP header parsing (compatible across platforms)
    struct simple_ip_header {
        uint8_t version_ihl;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };

    const struct simple_ip_header* ip_header = (struct simple_ip_header*)ip_packet;

    // Check if it's IPv4
    if ((ip_header->version_ihl >> 4) == 4) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;

        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

        stats.ip_sources[std::string(src_ip)]++;
        stats.ip_destinations[std::string(dst_ip)]++;

        int header_length = (ip_header->version_ihl & 0x0F) * 4;
        const u_char* transport_header = ip_packet + header_length;

        if (ip_header->protocol == 6) { // TCP
            stats.tcp_packets++;
            if (pkthdr->len >= 14 + header_length + 4) {
                uint16_t src_port = ntohs(*(uint16_t*)transport_header);
                uint16_t dst_port = ntohs(*(uint16_t*)(transport_header + 2));
                stats.ports[src_port]++;
                stats.ports[dst_port]++;
            }
        } else if (ip_header->protocol == 17) { // UDP
            stats.udp_packets++;
            if (pkthdr->len >= 14 + header_length + 4) {
                uint16_t src_port = ntohs(*(uint16_t*)transport_header);
                uint16_t dst_port = ntohs(*(uint16_t*)(transport_header + 2));
                stats.ports[src_port]++;
                stats.ports[dst_port]++;
            }
        } else if (ip_header->protocol == 1) { // ICMP
            stats.icmp_packets++;
        } else {
            stats.other_packets++;
        }
    }
}

std::vector<NetworkInterface> get_network_interfaces() {
    std::vector<NetworkInterface> interfaces;

#ifdef _WIN32
    // Windows implementation
    ULONG ulOutBufLen = 0;
    if (GetAdaptersInfo(NULL, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                if (pAdapter->Type == MIB_IF_TYPE_ETHERNET || pAdapter->Type == IF_TYPE_IEEE80211) {
                    NetworkInterface iface;
                    iface.name = pAdapter->AdapterName;
                    iface.ip = pAdapter->IpAddressList.IpAddress.String;
                    iface.netmask = pAdapter->IpAddressList.IpMask.String;
                    iface.is_active = (strcmp(iface.ip.c_str(), "0.0.0.0") != 0);

                    if (iface.ip != "0.0.0.0" && iface.ip != "127.0.0.1") {
                        interfaces.push_back(iface);
                    }
                }
                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
    }
#else
    // Unix/Linux/macOS implementation
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return interfaces;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            NetworkInterface iface;
            iface.name = ifa->ifa_name;

#ifdef __APPLE__
            iface.is_active = (ifa->ifa_flags & IFF_RUNNING) && (ifa->ifa_flags & IFF_UP);
#else
            iface.is_active = (ifa->ifa_flags & IFF_RUNNING) && (ifa->ifa_flags & IFF_UP);
#endif

            char ip[INET_ADDRSTRLEN];
            char netmask[INET_ADDRSTRLEN];

            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            struct sockaddr_in* mask = (struct sockaddr_in*)ifa->ifa_netmask;

            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            if (mask != NULL) {
                inet_ntop(AF_INET, &mask->sin_addr, netmask, INET_ADDRSTRLEN);
            } else {
                strcpy(netmask, "255.255.255.0");
            }

            iface.ip = ip;
            iface.netmask = netmask;

            // Skip loopback interface
            if (iface.name != "lo" && iface.ip != "127.0.0.1") {
                interfaces.push_back(iface);
            }
        }
    }

    freeifaddrs(ifaddr);
#endif

    return interfaces;
}

std::string get_best_interface() {
    std::vector<NetworkInterface> interfaces = get_network_interfaces();

    // Prefer active interfaces with non-loopback IPs
    for (const auto& iface : interfaces) {
        if (iface.is_active && iface.ip != "127.0.0.1") {
            return iface.name;
        }
    }

    // Fallback to any interface
    if (!interfaces.empty()) {
        return interfaces[0].name;
    }

    return "eth0"; // Last resort fallback
}

void print_json_results(const std::string& device, int duration) {
    time_t now = time(0);

    std::cout << "{\n";
    std::cout << "  \"success\": true,\n";
    std::cout << "  \"timestamp\": " << now << ",\n";
    std::cout << "  \"device\": \"" << device << "\",\n";
    std::cout << "  \"duration\": " << duration << ",\n";
    std::cout << "  \"network_analysis\": {\n";

    // Interface information
    std::cout << "    \"interfaces\": [\n";
    std::vector<NetworkInterface> interfaces = get_network_interfaces();
    for (size_t i = 0; i < interfaces.size(); ++i) {
        const auto& iface = interfaces[i];
        std::cout << "      {\n";
        std::cout << "        \"name\": \"" << iface.name << "\",\n";
        std::cout << "        \"ip\": \"" << iface.ip << "\",\n";
        std::cout << "        \"netmask\": \"" << iface.netmask << "\",\n";
        std::cout << "        \"active\": " << (iface.is_active ? "true" : "false") << "\n";
        std::cout << "      }";
        if (i < interfaces.size() - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "    ],\n";

    // Packet statistics
    std::cout << "    \"packet_stats\": {\n";
    std::cout << "      \"total_packets\": " << stats.total_packets << ",\n";
    std::cout << "      \"total_bytes\": " << stats.total_bytes << ",\n";
    std::cout << "      \"tcp_packets\": " << stats.tcp_packets << ",\n";
    std::cout << "      \"udp_packets\": " << stats.udp_packets << ",\n";
    std::cout << "      \"icmp_packets\": " << stats.icmp_packets << ",\n";
    std::cout << "      \"other_packets\": " << stats.other_packets << "\n";
    std::cout << "    },\n";

    // Top source IPs
    std::cout << "    \"top_sources\": [\n";
    std::vector<std::pair<std::string, int>> sorted_sources(stats.ip_sources.begin(), stats.ip_sources.end());
    std::sort(sorted_sources.begin(), sorted_sources.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (size_t i = 0; i < std::min(size_t(5), sorted_sources.size()); ++i) {
        std::cout << "      {\"ip\": \"" << sorted_sources[i].first
                  << "\", \"packets\": " << sorted_sources[i].second << "}";
        if (i < std::min(size_t(5), sorted_sources.size()) - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "    ],\n";

    // Top destination IPs
    std::cout << "    \"top_destinations\": [\n";
    std::vector<std::pair<std::string, int>> sorted_dests(stats.ip_destinations.begin(), stats.ip_destinations.end());
    std::sort(sorted_dests.begin(), sorted_dests.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (size_t i = 0; i < std::min(size_t(5), sorted_dests.size()); ++i) {
        std::cout << "      {\"ip\": \"" << sorted_dests[i].first
                  << "\", \"packets\": " << sorted_dests[i].second << "}";
        if (i < std::min(size_t(5), sorted_dests.size()) - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "    ],\n";

    // Top ports
    std::cout << "    \"top_ports\": [\n";
    std::vector<std::pair<int, int>> sorted_ports(stats.ports.begin(), stats.ports.end());
    std::sort(sorted_ports.begin(), sorted_ports.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    for (size_t i = 0; i < std::min(size_t(5), sorted_ports.size()); ++i) {
        std::cout << "      {\"port\": " << sorted_ports[i].first
                  << ", \"packets\": " << sorted_ports[i].second << "}";
        if (i < std::min(size_t(5), sorted_ports.size()) - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "    ]\n";

    std::cout << "  }\n";
    std::cout << "}\n";
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string device;
    int duration = 10;

    // Parse arguments
    if (argc > 1) {
        device = argv[1];
    }
    if (argc > 2) {
        duration = std::atoi(argv[2]);
        if (duration < 1 || duration > 60) {
            duration = 10;
        }
    }

    // Auto-detect best interface if not specified
    if (device.empty()) {
        device = get_best_interface();
    }

    // Set up signal handler for clean shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Open packet capture
    pcap_t *handle = pcap_open_live(device.c_str(), 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cout << "{\n";
        std::cout << "  \"success\": false,\n";
        std::cout << "  \"error\": \"Cannot open device " << device << ": " << errbuf << "\",\n";
        std::cout << "  \"available_interfaces\": [\n";

        std::vector<NetworkInterface> interfaces = get_network_interfaces();
        for (size_t i = 0; i < interfaces.size(); ++i) {
            std::cout << "    \"" << interfaces[i].name << "\"";
            if (i < interfaces.size() - 1) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "  ]\n";
        std::cout << "}\n";
        return 1;
    }

    // Start packet capture for specified duration
    time_t start_time = time(NULL);
    time_t end_time = start_time + duration;

    while (running && time(NULL) < end_time) {
        pcap_dispatch(handle, 10, packet_handler, NULL);
        usleep(100000); // 100ms delay
    }

    pcap_close(handle);

    // Output results as JSON
    print_json_results(device, duration);

    return 0;
}
