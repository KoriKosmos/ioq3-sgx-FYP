#pragma once

typedef struct {
    int damage;
    int armor;
    int dflags;
} DamageInput;

typedef struct {
    int final_damage;
    int final_armor;
    int knockback;
} DamageOutput;

// Simulated function for IPC -> Enclave
int SGX_SimulateDamageValidation(DamageInput* input, DamageOutput* output);
