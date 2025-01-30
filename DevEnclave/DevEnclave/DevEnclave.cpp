#include "sgx_trts.h"
#include "DevEnclave_t.h"  // Generated header from your edger8r

// Implementation for the ecall_update_health ECALL.
// This function updates the player's health by adding deltaHealth.
// In production code, you would add extra checks, validation, and business logic.
void ecall_update_health(int playerId, int deltaHealth, const char* sourceType, int* newHealth) {
    // Optional: validate parameters (e.g., ensure newHealth is valid)
    if (newHealth == NULL) {
        return;
    }

    // For demonstration, simply add deltaHealth to the existing health value.
    *newHealth = *newHealth + deltaHealth;

    // Optionally, call ocall_log to log the update.
    ocall_log("ecall_update_health executed.");
}