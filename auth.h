#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static inline bool sendAuthFrame(int sock, const uint8_t* ifaceMac, const uint8_t* apMac, const uint8_t* stMac) {
    // Radiotap header
    uint8_t radiotap_header[] = {
        0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <-- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
        0x00, 0x00, // <-- radiotap flags
        0x18, 0x00  // <-- radiotap data rate (24 Mbps)
    };

    // Authentication frame
    uint8_t frame[30] = {0};

    // Frame Control: Authentication (0xB0 - Incorrect, should be 0x00 0x00 for Open System Auth Request)
    frame[0] = 0x00;
    frame[1] = 0x00;

    // Duration: 0
    frame[2] = 0x00;
    frame[3] = 0x00;

    // Address 1: Destination Address (AP MAC)
    memcpy(frame + 4, apMac, 6);

    // Address 2: Source Address (Interface MAC - important to use your interface MAC)
    memcpy(frame + 10, ifaceMac, 6);

    // Address 3: BSSID (AP MAC)
    memcpy(frame + 16, apMac, 6);

    // Sequence Control: 0
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Authentication Algorithm Number: Open System (0)
    frame[24] = 0x00;
    frame[25] = 0x00; // Corrected to 0x0000 - two bytes for Algorithm Number

    // Authentication Transaction Sequence Number: 1 (Request)
    frame[26] = 0x01;
    frame[27] = 0x00; // Corrected to 0x0001 - two bytes for Sequence Number

    // Status Code: 0 (Success - for request, it's always 0 in request)
    frame[28] = 0x00;
    frame[29] = 0x00; // Corrected to 0x0000 - two bytes for Status Code

    // Combine Radiotap header and authentication frame
    uint8_t packet[sizeof(radiotap_header) + sizeof(frame)];
    memcpy(packet, radiotap_header, sizeof(radiotap_header));
    memcpy(packet + sizeof(radiotap_header), frame, sizeof(frame));

    return send(sock, packet, sizeof(packet), 0) != -1;
}