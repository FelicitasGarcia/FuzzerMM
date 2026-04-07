/* Oracle Program (OP) — original, correct version.
 * Classifies an integer into four categories.
 *
 * Usage: ./op <integer>
 */
#include <stdio.h>
#include <stdlib.h>

int classify(int n) {
    if (n < 0)    return -1;  /* negative              */
    if (n == 0)   return  0;  /* zero                  */
    if (n < 128)  return  1;  /* small positive [1,127] */
    return 2;                 /* large positive [128,∞) */
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