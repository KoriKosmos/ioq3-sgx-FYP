#include "DevEnclave_t.h"

#include "sgx_trts.h"

int g_player_health = 100;

int update_health(int current_health, int damage, int max_health) {
    if (current_health < 0 || current_health > max_health) return -1;
    if (damage < 0) return -2;

    g_player_health = current_health - damage;
    if (g_player_health < 0) g_player_health = 0;

    return g_player_health;
}