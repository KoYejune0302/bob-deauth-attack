// auth.h
#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static inline bool sendAuthFrame(int sock, const uint8_t* ifaceMac, const uint8_t* apMac, const uint8_t* stMac) {
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

    return send(sock, frame, sizeof(frame), 0) != -1;
}