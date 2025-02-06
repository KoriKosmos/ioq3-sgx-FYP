#include "AntiCheatEnclave_t.h"
#include <cstdio>
#include <cstring>
#include "../shared/shared_structs.h"

void ecall_validate_shot(
    int attacker_id,
    int target_id,
    int weapon_type,
    int hit_location,
    float distance,
    int damage,
    int* is_valid
) {
    char log_msg[128];

    // Simulated cheat check: sniper shots shouldn't hit from > 100m
    if (weapon_type == 10 /* e.g. railgun */ && distance > 100.0f) {
        snprintf(log_msg, sizeof(log_msg),
            "CHEAT DETECTED: %d → %d with weapon %d at %.2fm",
            attacker_id, target_id, weapon_type, distance);
        *is_valid = 0;
    }
    else {
        snprintf(log_msg, sizeof(log_msg),
            "Shot OK: %d → %d | Weapon: %d | Location: %d | Distance: %.2fm | Damage: %d",
            attacker_id, target_id, weapon_type, hit_location, distance, damage);
        *is_valid = 1;
    }

    ocall_log_message(log_msg);
}

