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
