#pragma once

typedef struct {
    int attacker_id;
    int target_id;
    int weapon_type;
    int hit_location;
    float distance;
    int damage;
    int armor;
    int dflags;
} DamageInput;

typedef struct {
    int damage_taken;
    int armor_absorbed;
    int knockback_applied;
} DamageOutput;

typedef struct {
    uint8_t ciphertext[256];  // Adjust based on max expected size
    uint8_t iv[12];
    uint8_t tag[16];
    uint32_t length;
} EncryptedMessage;
