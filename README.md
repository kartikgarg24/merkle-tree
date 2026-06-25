# Tiny Merkle Tree

A header-only, zero-dependency, lightweight C++17 implementation of a Merkle Tree, featuring an embedded custom byte-level SHA-256 hashing engine.

## Overview

This library provides a self-contained implementation of a Merkle Tree designed for applications requiring data integrity verification without external dependencies. It includes a built-in SHA-256 implementation, eliminating the need to link against heavy cryptographic libraries like OpenSSL.

### Key Features

* **Zero External Dependencies:** Fully self-contained, easing integration and cross-compilation tracking.
* **Domain Separation Prefixing:** Utilizes a `0x00` prefix for leaf nodes and a `0x01` prefix for internal nodes to mitigate second-preimage attacks.
* **Automatic Tree Balancing:** Automatically duplicates the last active node when handling an odd number of leaves to ensure structural integrity during tree construction.
* **Performance Benchmarking:** Includes execution-time tracking configurations to benchmark tree building speeds at a millisecond scale.

---

## Getting Started

### Prerequisites

* A C++17 compliant compiler (GCC 7+, Clang 5+, or MSVC 2017+)
* CMake 3.15 or higher

### Building the Project

This project utilizes CMake for cross-platform build automation. Follow these steps to clone, configure, and build the demo executable:

```bash
# 1. Clone the repository
git clone [https://github.com/kartikgarg24/merkle-tree.git](https://github.com/kartikgarg24/merkle-tree.git)
cd merkle-tree

# 2. Create and enter the build directory
mkdir build && cd build

# 3. Configure the project and compile the executable
cmake ..
cmake --build .

# 4. Run the demo application
./merkle_demo
