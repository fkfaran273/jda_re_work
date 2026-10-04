/* AOSP bionic rand():
 *   int rand() { return lrand48(); }
 *   void srand(unsigned s) { srand48(s); }
 * srand48: X = (seed << 16) | 0x330E
 * lrand48: X = (a*X + c) mod 2^48 ; return X >> 17  (31 bits)
 */
