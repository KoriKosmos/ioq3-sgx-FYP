#include "AntiCheatEnclave_t.h"
#include <cstdio>
#include <cstring>

void ecall_validate_damage(int attacker_id, int target_id, int weapon_type, int hit_location, float distance, int* damage, int* is_valid) {
    const int base_damage = 100;
    char log_message[128];

    // Simple anti-cheat check: if distance is too large, deny shot
    if (distance > 100.0f) {
        snprintf(log_message, sizeof(log_message), "Cheat detected: attacker %d tried to hit from %.2fm", attacker_id, distance);
        ocall_log_message(log_message);
        *damage = 0;
        *is_valid = false;
        return;
    }

    // Damage multipliers
    int multiplier = 1;
    switch (hit_location) {
    case 0: multiplier = 2; break;  // head
    case 1: multiplier = 1; break;  // torso
    case 2: multiplier = 0.75f; break; // legs
    default: multiplier = 1; break;
    }

    // Weapon type modifier (0 = rifle, 1 = pistol, etc.)
    int weapon_modifier = 0;
    switch (weapon_type) {
    case 0: weapon_modifier = 25; break;  // rifle
    case 1: weapon_modifier = 10; break;  // pistol
    default: weapon_modifier = 0; break;
    }

    *damage = (int)((base_damage + weapon_modifier) * multiplier);
    *is_valid = 1;

    snprintf(log_message, sizeof(log_message), "Hit OK: %d → %d | Weapon: %d | Location: %d | Damage: %d", attacker_id, target_id, weapon_type, hit_location, *damage);
    ocall_log_message(log_message);
}
