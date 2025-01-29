#pragma once

#define PIPE_NAME "\\\\.\\pipe\\ioq3_sgx_bridge"

// Anticheat command codes
enum AntiCheatCommand {
    CMD_HEALTH = 1,
    CMD_INVENTORY = 2, // for later
};

// Health payload structure
typedef struct {
    int cmd;        // CMD_HEALTH
    int current;
    int damage;
    int max;
} HealthRequest;

typedef struct {
    int new_health;
    int status;     // 0 = OK, -1 = error
} HealthResponse;
