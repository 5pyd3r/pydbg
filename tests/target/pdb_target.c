/* pdb_target — the C artefacts Phase 5's PDB reader is tested against.
 *
 * The layout is the contract, so do not "tidy" it: `Point` is exactly two ints
 * (size 8, x@0, y@4), `Bits` is the three-bitfield shape whose offsets tests
 * assert (0/3, 3/5, 8/1), and `Grid` exists only to give an array field a
 * record type — `int[4]` is what a PDB spells for `cells`, and none of the
 * other two structs contains an array.
 *
 * The functions exist to put names in the PDB, not to compute anything:
 * `add_numbers` is exported (and so is in the export table too), `helper` is
 * static and would be inlined away by the release build without noinline.
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

struct Point g_pt = {1, 2};
int g_arr[4] = {3, 4, 5, 6};
struct Bits g_bits = {1, 2, 1};
struct Grid g_grid = {{0, 0}, {7, 8, 9, 10}};

/* A static function that must survive /O2: ticket P18 checks its symbol. */
__declspec(noinline) static int helper(int value);

__declspec(dllexport) int add_numbers(int a, int b) {
    return a + b + helper(b);
}

static int helper(int value) {
    return value * 2;
}

int main(void) {
    g_pt.x = add_numbers(g_arr[0], g_bits.b);
    g_pt.y = g_grid.cells[3];
    g_bits.c = (unsigned)g_pt.y;
    return g_pt.x == 0;
}
