#pragma once
#include <stdint.h>

// Structure for transferring encrypted messages via IPC over a named pipe.
typedef struct EncryptedMessage {
    uint8_t iv[12];          // Initialization vector (should be random per message)
    uint8_t ciphertext[128]; // Buffer for the encrypted data (adjust size as needed)
    uint8_t tag[16];         // Authentication tag (MAC) produced by AES-GCM
    uint32_t length;         // Length of the plaintext data
} EncryptedMessage;

// Structure for sending damage calculation input from the game engine to the enclave.
typedef struct DamageInput {
    int attacker_health;  // Health of the attacking player
    int attacker_armor;   // Armor value of the attacking player
    int target_health;    // Health of the target (player being damaged)
    int target_armor;     // Armor value of the target
    int weapon_damage;    // The base damage value from the attack
    int dflags;           // Damage flags that influence calculations (e.g., knockback modifiers)
} DamageInput;

// Structure for receiving secure damage calculation results from the enclave.
typedef struct DamageOutput {
    int damage_taken;       // Final damage that should be applied after secure calculation
    int armor_absorbed;     // Amount of damage absorbed by the target's armor
    int knockback_applied;  // Final knockback value computed securely
} DamageOutput;
