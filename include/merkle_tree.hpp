#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

namespace tinysha256 {
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    inline std::vector<uint8_t> sha256_bytes(const std::string &msg) {
        uint32_t h0 = 0x6a09e667u, h1 = 0xbb67ae85u, h2 = 0x3c6ef372u, h3 = 0xa54ff53au;
        uint32_t h4 = 0x510e527fu, h5 = 0x9b05688cu, h6 = 0x1f83d9abu, h7 = 0x5be0cd19u;

        uint64_t ml = static_cast<uint64_t>(msg.size()) * 8;
        std::vector<uint8_t> data(msg.begin(), msg.end());
        data.push_back(0x80);
        while ((data.size() % 64) != 56) data.push_back(0x00);
        for (int i = 7; i >= 0; --i) data.push_back(static_cast<uint8_t>((ml >> (i * 8)) & 0xFF));

        for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
            std::array<uint32_t, 64> w{};
            for (int t = 0; t < 16; ++t) {
                size_t j = chunk + t * 4;
                w[t] = (uint32_t(data[j]) << 24) | (uint32_t(data[j+1]) << 16)
                     | (uint32_t(data[j+2]) << 8)  | uint32_t(data[j+3]);
            }
            for (int t = 16; t < 64; ++t) {
                uint32_t s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >> 3);
                uint32_t s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >> 10);
                w[t] = w[t-16] + s0 + w[t-7] + s1;
            }

            uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (int t = 0; t < 64; ++t) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + S1 + ch + K[t] + w[t];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                h = g; g = f; f = e;
                e = d + temp1;
                d = c; c = b; b = a;
                a = temp1 + temp2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
        }

        std::vector<uint8_t> digest(32);
        auto put_be = [&](uint32_t x, int off) {
            digest[off+0] = static_cast<uint8_t>((x >> 24) & 0xFF);
            digest[off+1] = static_cast<uint8_t>((x >> 16) & 0xFF);
            digest[off+2] = static_cast<uint8_t>((x >> 8) & 0xFF);
            digest[off+3] = static_cast<uint8_t>((x >> 0) & 0xFF);
        };
        put_be(h0,0); put_be(h1,4); put_be(h2,8); put_be(h3,12);
        put_be(h4,16); put_be(h5,20); put_be(h6,24); put_be(h7,28);
        return digest;
    }

    inline std::string to_hex(const std::vector<uint8_t> &v) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto x : v) ss << std::setw(2) << static_cast<int>(x);
        return ss.str();
    }

    inline std::string sha256_hex(const std::string &msg) {
        return to_hex(sha256_bytes(msg));
    }
} 

struct Node {
    std::shared_ptr<Node> left;
    std::shared_ptr<Node> right;
    std::string hash_hex;  
    std::string content;   
    bool is_copied;

    Node(std::shared_ptr<Node> L, std::shared_ptr<Node> R, const std::string &h, const std::string &c, bool copied=false)
        : left(L), right(R), hash_hex(h), content(c), is_copied(copied) {}

    std::shared_ptr<Node> clone_as_copy() const {
        return std::make_shared<Node>(left, right, hash_hex, content, true);
    }
};

static inline std::string bytes_with_prefix(char prefix, const std::string &payload) {
    std::string out;
    out.reserve(1 + payload.size());
    out.push_back(prefix);
    out += payload;
    return out;
}

static inline std::string hex_to_bytes(const std::string &hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    auto dec = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = dec(hex[i]);
        int lo = dec(hex[i+1]);
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

class MerkleTree {
public:
    MerkleTree() = default;

    explicit MerkleTree(const std::vector<std::string> &values) {
        for (const auto &v : values) add_leaf(v);
        build_tree();
    }

    void clear() {
        leaves_raw.clear();
        root.reset();
        layers.clear();
    }

    void add_leaf(const std::string &data) {
        leaves_raw.push_back(data);
    }

    void build_tree() {
        layers.clear();
        if (leaves_raw.empty()) {
            root.reset();
            return;
        }

        std::vector<std::shared_ptr<Node>> cur;
        cur.reserve(leaves_raw.size());
        for (const auto &d : leaves_raw) {
            std::string pref = bytes_with_prefix(0x00, d);
            std::string hhex = tinysha256::sha256_hex(pref);
            cur.push_back(std::make_shared<Node>(nullptr, nullptr, hhex, d, false));
        }
        if (cur.size() % 2 == 1) cur.push_back(cur.back()->clone_as_copy());
        layers.push_back(cur);

        while (layers.back().size() > 1) {
            const auto &bottom = layers.back();
            std::vector<std::shared_ptr<Node>> next;
            next.reserve((bottom.size() + 1) / 2);
            for (size_t i = 0; i < bottom.size(); i += 2) {
                auto L = bottom[i];
                auto R = (i + 1 < bottom.size()) ? bottom[i+1] : bottom[i];
                std::string left_raw = hex_to_bytes(L->hash_hex);
                std::string right_raw = hex_to_bytes(R->hash_hex);
                std::string pref = bytes_with_prefix(0x01, left_raw + right_raw);
                std::string hhex = tinysha256::sha256_hex(pref);
                std::string content = L->content + "+" + R->content;
                bool copied = L->is_copied && R->is_copied;
                next.push_back(std::make_shared<Node>(L, R, hhex, content, copied));
            }
            if (next.size() % 2 == 1 && next.size() > 1) next.push_back(next.back()->clone_as_copy());
            layers.push_back(next);
        }

        root = layers.back().front();
    }

    std::string get_root_hash() const {
        if (!root) return std::string();
        return root->hash_hex;
    }

    size_t leaf_count() const { return leaves_raw.size(); }

    void print_tree() const {
        if (!root) {
            std::cout << "(empty tree)\n";
            return;
        }
        std::cout << "=== Merkle Tree (preorder) ===\n";
        print_node(root, 0);
        std::cout << "=== End tree ===\n";
    }

    std::vector<std::pair<std::string,bool>> get_proof(size_t leaf_index) const {
        std::vector<std::pair<std::string,bool>> proof;
        if (layers.empty() || leaf_index >= leaf_count()) return proof;
        size_t idx = leaf_index;
        for (size_t level = 0; level + 1 < layers.size(); ++level) {
            const auto &layer = layers[level];
            size_t sibling;
            bool sibling_is_left;
            if (idx % 2 == 0) {
                if (idx + 1 < layer.size()) { sibling = idx + 1; sibling_is_left = false; }
                else { sibling = idx; sibling_is_left = false; }
            } else {
                sibling = idx - 1; sibling_is_left = true;
            }
            proof.emplace_back(layer[sibling]->hash_hex, sibling_is_left);
            idx /= 2;
        }
        return proof;
    }

private:
    std::vector<std::string> leaves_raw;
    std::shared_ptr<Node> root;
    std::vector<std::vector<std::shared_ptr<Node>>> layers;

    static void print_node(const std::shared_ptr<Node> &n, int depth) {
        if (!n) return;
        std::string indent(depth * 2, ' ');
        std::cout << indent << "- hash: " << n->hash_hex;
        if (n->is_copied) std::cout << " (padding)";
        std::cout << "\n";
        std::cout << indent << "  content: " << n->content << "\n";
        if (n->left || n->right) {
            if (n->left) {
                std::cout << indent << "  L:\n";
                print_node(n->left, depth + 2);
            }
            if (n->right) {
                std::cout << indent << "  R:\n";
                print_node(n->right, depth + 2);
            }
        }
    }
};

#endif // MERKLE_TREE_HPP