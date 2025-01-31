#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static inline bool sendAuthFrame(int sock, const uint8_t* apMac, const uint8_t* stMac) {
    uint8_t frame[30] = {0};

    frame[0] = 0xb0; // Auth subtype
    frame[1] = 0x00;

    memset(frame + 4, stMac ? *stMac : 0xFF, 6);
    memcpy(frame + 10, apMac, 6);
    memcpy(frame + 16, apMac, 6);

    frame[24] = 0x00; // Auth Algorithm
    frame[26] = 0x01; // Auth Sequence
    frame[28] = 0x00; // Status Code

    return send(sock, frame, sizeof(frame), 0) != -1;
}
