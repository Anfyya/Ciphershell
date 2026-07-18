#include "control_ids.h"

namespace CipherShellGui {

int NextControlId() {
    static int next = IDC_FIRST_DYNAMIC;
    return next++;
}

} // namespace CipherShellGui
