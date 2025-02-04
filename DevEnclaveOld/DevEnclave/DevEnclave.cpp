#include "sgx_trts.h"
#include "DevEnclave_t.h"  // Generated header from your EDL

// Ensure matching signature as per your EDL file.
extern "C" void ecall_update_health(int playerId,
                                      int deltaHealth,
                                      const char* sourceType,
                                      int* newHealth) {
    if (newHealth == nullptr) {
        return;
    }
    
    // Example: Update health logic.
    *newHealth += deltaHealth;
    
    // Log the event via OCALL.
    ocall_log("ecall_update_health executed.");
}
