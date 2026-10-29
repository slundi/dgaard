/*
 * Minimal C consumer of the dgaard engine.
 *
 *   just ffi-demo
 *
 * or by hand:
 *   cargo build -p dgaard-ffi
 *   cc -I dgaard-ffi/include dgaard-ffi/examples/demo.c \
 *      -L target/debug -ldgaard -o /tmp/dgaard-demo
 *   LD_LIBRARY_PATH=target/debug /tmp/dgaard-demo example.com 0000000000000000001.com
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "dgaard.h"

static void die(const char *context) {
    char message[512];
    dgaard_last_error(message, sizeof message);
    fprintf(stderr, "dgaard: %s: %s\n", context, message);
}

/* Print the payload a reason carries, whichever of the two channels it uses. */
static void print_payload(double number, const char *text) {
    if (number == number) { /* NaN compares unequal to itself */
        printf(" payload=%g", number);
    }
    if (text[0] != '\0') {
        printf(" payload=\"%s\"", text);
    }
}

static void report(const dgaard_engine *engine, const char *domain) {
    dgaard_verdict *verdict = dgaard_classify(engine, domain);
    if (verdict == NULL) {
        /* NULL is the only failure signal — it can never be a real verdict. */
        die(domain);
        return;
    }

    printf("%-28s action=%d score=%u\n", domain, dgaard_verdict_action(verdict),
           dgaard_verdict_score(verdict));

    if (dgaard_verdict_action(verdict) == DGAARD_ACTION_BLOCK) {
        char text[256];
        dgaard_verdict_block_text(verdict, text, sizeof text);
        printf("    blocked: reason=%d", dgaard_verdict_block_reason(verdict));
        print_payload(dgaard_verdict_block_number(verdict), text);
        printf("\n");
    }

    /* The count is exact: every index below it is populated. */
    size_t count = dgaard_verdict_reason_count(verdict);
    for (size_t index = 0; index < count; index++) {
        char text[256];
        dgaard_verdict_reason_text_at(verdict, index, text, sizeof text);
        printf("    score reason %zu: tag=%d", index, dgaard_verdict_reason_at(verdict, index));
        print_payload(dgaard_verdict_reason_number_at(verdict, index), text);
        printf("\n");
    }

    char address[64];
    if (dgaard_verdict_address(verdict, address, sizeof address) > 0) {
        printf("    address: %s\n", address);
    }

    dgaard_verdict_free(verdict);
}

int main(int argc, char **argv) {
    if (dgaard_abi_version() != DGAARD_ABI_VERSION) {
        fprintf(stderr, "dgaard: header is ABI v%d, library is v%u\n", DGAARD_ABI_VERSION,
                dgaard_abi_version());
        return 1;
    }

    char version[32];
    dgaard_version(version, sizeof version);
    printf("dgaard %s (ABI v%u)\n\n", version, dgaard_abi_version());

    /*
     * Heuristics only: no list files, no filesystem access. Swap in
     * dgaard_engine_new_from_file("/etc/dgaard/config.toml") for the full
     * pipeline with blocklists.
     */
    dgaard_engine *engine = dgaard_engine_new_heuristics();
    if (engine == NULL) {
        die("engine");
        return 1;
    }

    if (argc > 1) {
        for (int index = 1; index < argc; index++) {
            report(engine, argv[index]);
        }
    } else {
        report(engine, "example.com");
        report(engine, "0000000000000000001.com");
        report(engine, "kq3v9z7x1j4m2p8w.biz");
        report(engine, "xn--pple-43d.com");
    }

    printf("\nANY queries blocked by policy: %s\n",
           dgaard_check_qtype(engine, 255) == DGAARD_REASON_FORBIDDEN_QTYPE ? "yes" : "no");

    dgaard_engine_free(engine);
    return 0;
}
