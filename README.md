# Coldsnap-rust - Rust Snapshot Fuzzer Example

Welcome to coldsnap! This example was inspired by @gamozolabs love for snapshot fuzzing and based on @h0mbre_ blog [Fuzzing Like A Caveman 4](https://h0mbre.github.io/Fuzzing-Like-A-Caveman-4/)

This example is a 1-to-1 port of https://github.com/defparam/Coldsnap into Rustlang, Please read the README.md of the original Coldsnap repo to get an idea of what this example does.

## Python3 vs Rust
These benchmark compared Coldsnap-python to Coldsnap-rust both running on an AWS T2.micro instance (single thread/core) against the same target.

Python3:
```
Total Fuzz Cases:               275708
Duration:                       25.715138 seconds
Instructions Covered:           200 / 255 (78.4%)
Fuzz Cases per Second:          10721.622416
```
Rust:
```
Total Fuzz Cases:               457561
Duration:                       18.29 seconds
Instructions Covered:           200 / 255 (78.43%)
Fuzz Cases per Second:          25015.572
```
## How to install and run (Ubuntu)
### Install
1) clone this repo and change directory into it
2) sudo apt update
3) sudo apt install build-essential cargo
### Run
1) make

