#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static inline bool sendDeauthFrame(int sock, const uint8_t* apMac, const uint8_t* stMac) {
    uint8_t frame[26] = {0};

    frame[0] = 0xc0; // Deauth
    frame[1] = 0x00;

    memset(frame + 4, stMac ? *stMac : 0xFF, 6);
    memcpy(frame + 10, apMac, 6);
    memcpy(frame + 16, apMac, 6);

    frame[24] = 0x07; // Reason Code
    frame[25] = 0x00;

    return send(sock, frame, sizeof(frame), 0) != -1;
}
