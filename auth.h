#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static inline bool sendAuthFrame(int sock, const uint8_t* apMac, const uint8_t* stationMac) {
    // Radiotap header
    uint8_t radiotap_header[] = {
        0x00, 0x00, // Radiotap version
        0x0c, 0x00, // Radiotap header length
        0x04, 0x80, 0x00, 0x00, // Radiotap present flags
        0x00, 0x00, // Radiotap flags
        0x18, 0x00  // Radiotap data rate (24 Mbps)
    };

    // Authentication frame
    uint8_t frame[30] = {0};

    // Frame Control: Authentication (0xB0 for Management frame, subtype Authentication)
    frame[0] = 0xB0;
    frame[1] = 0x00;

    // Duration: 314 microseconds (typical value for authentication frames)
    frame[2] = 0x00;
    frame[3] = 0x00;

    // Address 1: Destination Address (AP MAC)
    memcpy(frame + 4, apMac, 6);

    // Address 2: Source Address (Station MAC)
    memcpy(frame + 10, stationMac, 6);

    // Address 3: BSSID (AP MAC)
    memcpy(frame + 16, apMac, 6);

    // Sequence Control: 0
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Authentication Algorithm Number: Open System (0)
    frame[24] = 0x00;
    frame[25] = 0x00;

    // Authentication Transaction Sequence Number: 1 (Request)
    frame[26] = 0x01;
    frame[27] = 0x00;

    // Status Code: 0 (Success)
    frame[28] = 0x00;
    frame[29] = 0x00;

    // Combine Radiotap header and authentication frame
    uint8_t packet[sizeof(radiotap_header) + sizeof(frame)];
    memcpy(packet, radiotap_header, sizeof(radiotap_header));
    memcpy(packet + sizeof(radiotap_header), frame, sizeof(frame));

    return send(sock, packet, sizeof(packet), 0) != -1;
}