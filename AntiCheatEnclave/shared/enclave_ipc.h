#pragma once
#include <stdint.h>

struct EncryptedMessage {
    uint8_t iv[12];
    uint8_t ciphertext[128];
    uint8_t tag[16];
    uint32_t length;
};

struct DamageInput {
    int attacker_health;
    int attacker_armor;
    int target_health;
    int target_armor;
    int weapon_damage;
    int dflags;
};

struct DamageOutput {
    int damage_taken;
    int armor_absorbed;
    int knockback_applied;
};
