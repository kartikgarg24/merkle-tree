#include "merkle_tree.hpp"

using namespace std;

void basic_demo_example() {
    cout << "\n--- Basic demo (converted example inputs) ---\n";
    vector<string> elems = {"A", "B", "Computer", "Science", "P", "F", "G"};
    cout << "Inputs (" << elems.size() << "): ";
    for (size_t i = 0; i < elems.size(); ++i) {
        if (i) cout << " | ";
        cout << elems[i];
    }
    cout << "\n";

    MerkleTree mt(elems);
    cout << "Leaf count: " << mt.leaf_count() << "\n";
    cout << "Merkle root (hex): " << mt.get_root_hash() << "\n";
    cout << "\nPrinting full tree (this will show padding nodes if present):\n";
    mt.print_tree();
}

void edge_cases_demo() {
    cout << "\n--- Edge cases demo ---\n";

    cout << "\n1) Empty tree\n";
    MerkleTree t0;
    t0.build_tree();
    cout << "  leaf_count=" << t0.leaf_count() << ", root='" << t0.get_root_hash() << "'\n";

    cout << "\n2) Single-leaf tree\n";
    MerkleTree t1;
    t1.add_leaf("single-leaf");
    t1.build_tree();
    cout << "  leaf_count=" << t1.leaf_count() << ", root=" << t1.get_root_hash() << "\n";
    cout << "  tree print:\n";
    t1.print_tree();

    cout << "\n3) Even number of leaves\n";
    MerkleTree t2;
    t2.add_leaf("L1"); t2.add_leaf("L2"); t2.add_leaf("L3"); t2.add_leaf("L4");
    t2.build_tree();
    cout << "  leaf_count=" << t2.leaf_count() << ", root=" << t2.get_root_hash() << "\n";
    cout << "  tree print (top levels):\n";
    t2.print_tree();

    cout << "\n4) Odd number of leaves (shows padding)\n";
    MerkleTree t3;
    t3.add_leaf("alpha"); t3.add_leaf("beta"); t3.add_leaf("gamma");
    t3.build_tree();
    cout << "  leaf_count=" << t3.leaf_count() << ", root=" << t3.get_root_hash() << "\n";
    t3.print_tree();
}

void large_scale_demo(size_t n) {
    cout << "\n--- Large-scale build demo ---\n";
    cout << "Building Merkle tree with " << n << " leaves (auto-generated values)...\n";
    vector<string> vals;
    vals.reserve(n);
    std::mt19937_64 rng(2025);
    for (size_t i = 0; i < n; ++i) {
        uint64_t v = rng();
        vals.push_back("item-" + to_string(i) + "-" + to_string(v));
    }

    auto t0 = chrono::high_resolution_clock::now();
    MerkleTree mt(vals);
    auto t1 = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = t1 - t0;
    cout << "  build time: " << fixed << setprecision(6) << elapsed.count() << "s\n";
    cout << "  leaf_count=" << mt.leaf_count() << "\n";
    cout << "  root (hex, first 64 chars): " << mt.get_root_hash().substr(0, 64) << "...\n";

    cout << "\n  (printing top levels only) \n";
    mt.print_tree();
}

void stress_builds_demo() {
    cout << "\n--- Stress builds demo (multiple sizes) ---\n";
    vector<size_t> sizes = {1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256};
    for (size_t s : sizes) {
        vector<string> vals;
        vals.reserve(s);
        for (size_t i = 0; i < s; ++i) vals.push_back("v-" + to_string(i));
        auto t0 = chrono::high_resolution_clock::now();
        MerkleTree mt(vals);
        auto t1 = chrono::high_resolution_clock::now();
        chrono::duration<double, milli> ms = t1 - t0;
        cout << "  size=" << setw(3) << s << " -> root(8)=\"" << mt.get_root_hash().substr(0,8)
             << "\" build_ms=" << fixed << setprecision(3) << ms.count() << " ms\n";
    }
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    cout << "Merkle Tree (expanded C++ version) - SHA-256 embedded\n";
    cout << "This build duplicates the last leaf when there's an odd number of leaves.\n";

    basic_demo_example();
    edge_cases_demo();
    large_scale_demo(16);   
    stress_builds_demo();

    cout << "\nAll demos complete.\n";
    return 0;
}