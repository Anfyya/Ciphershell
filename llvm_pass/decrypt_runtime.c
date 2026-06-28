/**
 * CipherShell 字符串解密运行时
 * 链接到被保护的程序中
 */

#include <stdint.h>

/**
 * 解密字符串（就地解密）
 * @param data 加密的数据
 * @param len 数据长度
 * @param key 解密密钥
 */
void __cs_decrypt_string(uint8_t* data, uint64_t len, uint8_t key) {
    for (uint64_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
