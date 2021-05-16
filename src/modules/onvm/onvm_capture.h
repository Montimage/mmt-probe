#ifndef SRC_MODULES_ONVM_ONVM_CAPTURE_H_
#define SRC_MODULES_ONVM_ONVM_CAPTURE_H_

#include "../../context.h"

struct onvm_nf_local_ctx*
onvm_capture_init(probe_context_t *context);

void
onvm_capture_start(probe_context_t *context, struct onvm_nf_local_ctx* nf_local_ctx);

void
onvm_capture_stop(struct onvm_nf_local_ctx* nf_local_ctx);

#endif /* SRC_MODULES_ONVM_ONVM_CAPTURE_H_ */
