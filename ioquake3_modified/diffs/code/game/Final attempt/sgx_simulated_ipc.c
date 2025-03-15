#include "sgx_simulated_ipc.h"
#include <stdio.h>

// Simulates calling the enclave to validate damage
int SGX_SimulateDamageValidation(DamageInput* input, DamageOutput* output) {
    // Simulate logic from your enclave
    int take = input->damage;
    int asave = 0;
    int kb = input->damage;

    if (kb > 200) kb = 200;
    if (input->dflags & 0x4) kb = 0; // DAMAGE_NO_KNOCKBACK

    if (!(input->dflags & 0x2)) { // not DAMAGE_NO_ARMOR
        asave = (input->armor < take / 2) ? input->armor : take / 2;
        take -= asave;
    }

    if (take < 1) take = 1;

    output->final_damage = take;
    output->final_armor = asave;
    output->knockback = kb;

    return 1; // success
}
