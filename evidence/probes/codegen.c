/* Compiler behavior probes, not accepted game source. No SDK headers required. */
extern int external_function(int);
extern void *memcpy(void *, const void *, unsigned);
extern void *memset(void *, int, unsigned);
int initialized_word = 0x1234;
int common_word;
static int static_word = 7;
struct pair { int x; int y; };

int leaf(int x) { return x + 1; }
int signed_compare(int x, int y) { return x < y; }
int unsigned_compare(unsigned x, unsigned y) { return x < y; }
int external_call(int x) { return external_function(x) + 1; }
int global_access(int x) { common_word = x; return initialized_word + static_word + common_word; }
int select_case(int x) { switch (x) { case 0: return 7; case 1: return 3; case 2: return 11; case 5: return -9; default: return x; } }
long multiply_long(long x, long y) { return x * y; }
long divide_long(long x, long y) { return x / y; }
unsigned long shifts(unsigned long x, unsigned n) { return (x << n) ^ (x >> n); }
unsigned far_pointer(unsigned far *p) { return *p; }
int near near_leaf(int x) { return x + 3; }
int far far_leaf(int x) { return near_leaf(x); }
struct pair structure_return(int x) { struct pair r; r.x = x; r.y = x + 1; return r; }
void memory_operations(void *p, void *q, unsigned n) { memcpy(p, q, n); memset(p, 0, n); }
int registers(int *p, unsigned n) { unsigned i; int total = 0; for (i = 0; i < n; ++i) total += p[i]; return total; }
