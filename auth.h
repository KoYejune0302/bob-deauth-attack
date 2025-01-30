#pragma once

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

/**
 * 802.11 Auth 프레임 구조(간소화):
 *  - Frame Control: 2바이트
 *  - Duration: 2바이트
 *  - DA(수신 MAC): 6바이트
 *  - SA(송신 MAC): 6바이트
 *  - BSSID: 6바이트
 *  - Sequence Control: 2바이트
 *  - Auth Algorithm: 2바이트
 *  - Auth Sequence: 2바이트
 *  - Status Code: 2바이트
 */

static inline void sendAuthFrame(int sock, const uint8_t* apMac, const uint8_t* stMac) {
    // 간단히 802.11 Header + Auth 데이터(6바이트) = 24 + 6 = 30바이트
    uint8_t frame[30];
    memset(frame, 0, sizeof(frame));

    // Frame Control: Type(Management=0), Subtype(Authentication=1011 -> 0xB0)
    frame[0] = 0xb0; // Auth subtype
    frame[1] = 0x00; // Flags

    // Duration
    frame[2] = 0x00;
    frame[3] = 0x00;

    // DA (수신 MAC)
    // - station MAC이 없으면 Broadcast
    if (stMac) {
        memcpy(frame + 4, stMac, 6);
    } else {
        memset(frame + 4, 0xFF, 6);
    }

    // SA (송신 MAC) = AP MAC
    memcpy(frame + 10, apMac, 6);
    // BSSID = AP MAC
    memcpy(frame + 16, apMac, 6);

    // Sequence Control
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Auth Algorithm (Open System = 0x0000)
    frame[24] = 0x00;
    frame[25] = 0x00;

    // Auth Sequence (1=요청, 2=응답 ...)
    frame[26] = 0x01;
    frame[27] = 0x00;

    // Status Code (0=Successful, 1=Unspecified failure ...)
    frame[28] = 0x00;
    frame[29] = 0x00;

    // 전송
    ssize_t res = send(sock, frame, sizeof(frame), 0);
    if (res == -1) {
        perror("[-] auth failed");
    }
}
