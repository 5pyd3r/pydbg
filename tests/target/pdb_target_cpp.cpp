/* pdb_target_cpp — the C++ artefact for the Phase 5 PDB type tests.
 *
 * The C target covers structs, bitfields and an array field; this one adds the
 * shapes only C++ puts in a PDB: a vftable, a base class, and decorated method
 * names. `Shape` is a global object so its own vftable is emitted (a vftable
 * can be dropped when no object of that exact class exists), while `Square`
 * gives the derived-class layout with a base to walk.
 *
 * A static function is here for the same reason as in the C target: the
 * symbol must exist in the PDB, so it must not be inlined into main under /O2.
 */

class Shape {
public:
    virtual int area();
    int sides;
};

class Square : public Shape {
public:
    explicit Square(int side);
    int area() override;

private:
    int side_len;
};

int Shape::area() {
    return 0;
}

Square::Square(int side) : side_len(side) {
    sides = 4;
}

int Square::area() {
    return side_len * side_len;
}

Square g_square(3);
Shape g_shape;
Shape *g_current = &g_square;

static __declspec(noinline) int scale(int value) {
    return value * 2;
}

int main() {
    g_shape.sides = scale(g_current->sides);
    return g_current->area() == 9 ? 0 : 1;
}
