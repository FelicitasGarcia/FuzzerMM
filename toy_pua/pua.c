/* Program Under Analysis (PUA) — new version with a regression.
 *
 * REGRESSION: the boundary in classify() was changed from 128 to 127
 * (off-by-one).  For input n=127, OP returns 1 but PUA returns 2,
 * so MM will emit verdict IV for that input.
 *
 * All other seeds (0, 1, -1, 255, 256, INT_MIN, INT_MAX) behave
 * identically to the OP, so the fuzzer must mutate to discover 127.
 *
 * Usage: ./pua <integer>
 */
#include <stdio.h>
#include <stdlib.h>

int classify(int n) {
    if (n < 0)    return -1;
    if (n == 0)   return  0;
    if (n < 127)  return  1;  /* BUG: should be 128 — off-by-one regression */
    return 2;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <integer>\n", argv[0]);
        return 1;
    }
    int n = atoi(argv[1]);
    printf("%d\n", classify(n));
    return 0;
}