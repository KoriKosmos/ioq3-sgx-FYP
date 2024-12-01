#include "TestEnclave_t.h"
#include "sgx_trts.h"
#include <cstring>

// Damage calculation based on body part
void ecall_calculate_damage(int body_part, int* damage) {
    int base_damage = 100;
    unsigned int modifier = 0; // Ensure random value is always positive

    switch (body_part) {
    case 0: // Head
        sgx_read_rand((unsigned char*)&modifier, sizeof(unsigned int));
        modifier = (modifier % 51); // Random number between 0-50
        *damage = base_damage + (int)modifier;
        break;

    case 1: // Torso
        sgx_read_rand((unsigned char*)&modifier, sizeof(unsigned int));
        modifier = (modifier % 26); // Random number between 0-25
        *damage = base_damage + (int)modifier;
        break;

    case 2: // Legs
        *damage = base_damage; // Flat 100 damage
        break;

    default:
        *damage = -1; // Error case
        break;
    }
}

// Potion effects
void ecall_consume_potion(int potion_type, int* health) {
    switch (potion_type) {
    case 0: // Potion of Health
        *health += 50;
        break;

    case 1: // Potion of Damage
        *health -= 50;
        break;

    case 2: // Potion of Berserkers
        *health *= 2;
        break;

    case 3: // Potion of Weakness
        *health /= 2;
        break;

    case 4: // Potion of Normalcy
        *health = 100;
        break;

    default:
        // No change for invalid potion
        break;
    }

    // Health boundaries
    if (*health <= 0) {
        *health = 0;
    }
    else if (*health > 1000) {
        *health = 1000;
    }
}
