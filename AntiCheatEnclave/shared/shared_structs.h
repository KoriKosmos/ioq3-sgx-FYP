// shared_structs.h — shared by ioquake3 and enclave host app
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        int attacker_id;
        int target_id;
        int weapon_type;     // maps to modNames[MOD_*]
        int hit_location;    // placeholder (you can extend later)
        float distance;      // precomputed in ioquake3
        int damage;          // expected game-side damage
    } ShotData;

#ifdef __cplusplus
}
#endif
