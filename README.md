# Tiny Merkle Tree (C++17)

A header-only, zero-dependency, lightweight C++17 implementation of a **Merkle Tree**, complete with an embedded custom byte-level **SHA-256 hashing engine**.

## ✨ Features
* 🔒 **Zero Dependencies:** No need for OpenSSL or external library tracking.
* 🛡️ **Domain Separation Prefixing:** Utilizes `0x00` prefixes for leaves and `0x01` prefixes for internal nodes to prevent second-preimage attacks.
* 📦 **Automatic Padding:** Safely duplicates the last active node if an odd number of leaves are registered.
* ⏱️ **Performant Hashing:** Includes benchmarking/stress demos tracking execution times down to the millisecond.

---

## 🚀 Quick Start & Compilation

This project uses **CMake** for uniform platform support. Follow these steps to build and run the demo executable:

```bash
# 1. Clone the repository
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
cd YOUR_REPO_NAME

# 2. Create and enter a build directory
mkdir build && cd build

# 3. Generate build files and build the executable
cmake ..
cmake --build .

# 4. Run the executable
./merkle_demo