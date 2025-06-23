# binary-protocol-tcp-c
A simple prototype TCP server in C implementing a custom binary protocol with versioned packet headers. It supports login authentication with fixed credentials (no database), designed purely for learning and understanding how binary TCP communication, packet routing by numeric IDs, and session management work.

```c
void xor_cipher(uint8_t *data, size_t len, uint16_t packet_id) {
    uint32_t seed = packet_id | (packet_id << 16);
    for (size_t i = 0; i < len; i++) {
        seed ^= (seed >> 13);
        seed ^= (seed << 17);
        seed ^= (seed >> 5);
        data[i] ^= (uint8_t)(seed & 0xFF);
    }
}
```
