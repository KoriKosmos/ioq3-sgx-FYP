#include "TestEnclave_t.h"
#include "sgx_trts.h"
#include <cstdio>
#include <cstring>

// Damage calculation based on body part
void ecall_calculate_damage(int body_part, int* damage) {
    int base_damage = 100;
    unsigned int modifier = 0; // Ensure random value is always positive
    char log_message[128];

    switch (body_part) {
    case 0: // Head
        sgx_read_rand((unsigned char*)&modifier, sizeof(unsigned int));
        modifier = (modifier % 51); // Random number between 0-50
        *damage = base_damage + (int)modifier;
        snprintf(log_message, sizeof(log_message), "Damage calculated for head: %d", *damage);
        ocall_log_message(log_message);
        break;

    case 1: // Torso
        sgx_read_rand((unsigned char*)&modifier, sizeof(unsigned int));
        modifier = (modifier % 26); // Random number between 0-25
        *damage = base_damage + (int)modifier;
        snprintf(log_message, sizeof(log_message), "Damage calculated for torso: %d", *damage);
        ocall_log_message(log_message);
        break;

    case 2: // Legs
        *damage = base_damage; // Flat 100 damage
        snprintf(log_message, sizeof(log_message), "Damage calculated for legs: %d", *damage);
        ocall_log_message(log_message);
        break;

    default:
        *damage = -1; // Error case
        snprintf(log_message, sizeof(log_message), "Invalid body part provided.");
        ocall_log_message(log_message);
        break;
    }
}

// Potion effects
void ecall_consume_potion(int potion_type, int* health) {
    char log_message[128];

    switch (potion_type) {
    case 0: // Potion of Health
        *health += 50;
        snprintf(log_message, sizeof(log_message), "Potion of Health consumed. New health: %d", *health);
        break;

    case 1: // Potion of Damage
        *health -= 50;
        snprintf(log_message, sizeof(log_message), "Potion of Damage consumed. New health: %d", *health);
        break;

    case 2: // Potion of Berserkers
        *health *= 2;
        snprintf(log_message, sizeof(log_message), "Potion of Berserkers consumed. New health: %d", *health);
        break;

    case 3: // Potion of Weakness
        *health /= 2;
        snprintf(log_message, sizeof(log_message), "Potion of Weakness consumed. New health: %d", *health);
        break;

    case 4: // Potion of Normalcy
        *health = 100;
        snprintf(log_message, sizeof(log_message), "Potion of Normalcy consumed. Health reset to: %d", *health);
        break;

    default:
        snprintf(log_message, sizeof(log_message), "Invalid potion type provided.");
        break;
    }

    ocall_log_message(log_message);

    // Health boundaries
    if (*health <= 0) {
        *health = 0;
    }
    else if (*health > 1000) {
        *health = 1000;
    }
}
