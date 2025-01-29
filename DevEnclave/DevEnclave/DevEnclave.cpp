#include "DevEnclave_t.h"

#include "sgx_trts.h"

int update_health(int current, int damage, int max) {
    int new_health = current - damage;
    if (new_health < 0) new_health = 0;
    if (new_health > max) new_health = max;
    return new_health;
}