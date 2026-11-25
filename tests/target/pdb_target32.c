/* pdb_target32 — the 32-bit counterpart of pdb_target.c (spec §13.6, ticket
 * P41). The reader is machine-agnostic; this image exists so the same
 * find/symbols/structs path is exercised against a PE32 PDB.
 *
 * The layout contract is the x64 sample's, do not "tidy" it: `Point` is
 * exactly two ints (size 8, x@0, y@4), `Bits` keeps the three-bitfield shape
 * (0/3, 3/5, 8/1), and `Grid` gives an array field a record type.
 *
 * Two deliberate differences from pdb_target.c:
 *
 * - `add_numbers` is __stdcall, so the linker publishes the `_name@N` spelling
 *   too and the test can prove the x86 decoration survives the reader.
 * - `PointerHolder` is new. A `void *` member is the only way a PDB can say how
 *   wide pointers are on the image's machine; `Point` has no pointer member in
 *   either build, so the pointer-width assertion needs a type of its own.
 *
 * main touches every global so /OPT:REF cannot drop a data symbol, and its
 * return value is 0.
 */

struct Point {
    int x;
    int y;
};

struct Bits {
    unsigned a : 3;
    unsigned b : 5;
    unsigned c : 1;
};

struct Grid {
    struct Point origin;
    int cells[4];
};

struct PointerHolder {
    void *owner;
};

struct Point g_pt = {1, 2};
int g_arr[4] = {3, 4, 5, 6};
struct Bits g_bits = {1, 2, 1};
struct Grid g_grid = {{0, 0}, {7, 8, 9, 10}};
struct PointerHolder g_holder = {0};

/* A static function that must survive /O2: its symbol is part of the test. */
__declspec(noinline) static int helper(int value);

__declspec(dllexport) int __stdcall add_numbers(int a, int b) {
    return a + b + helper(b);
}

static int helper(int value) {
    return value * 2;
}

int main(void) {
    g_pt.x = add_numbers(g_arr[0], g_bits.b);
    g_pt.y = g_grid.cells[3];
    g_bits.c = (unsigned)g_pt.y;
    g_holder.owner = &g_pt;
    return g_pt.x == 0;
}
