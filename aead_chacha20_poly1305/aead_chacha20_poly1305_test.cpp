// aead_chacha20_poly1305_test.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

#include <iostream>

#include "../chacha20/chacha20.h"
#include "../poly1305/poly1305.h"
#include "./aead_chacha20_poly1305.h"

int main()
{
    struct aead_chacha20_poly1305_test
    {
        std::string name;
        std::vector<uint8_t> plain_text, aad, key, nonce, cipher_text, tag;
    };

    const aead_chacha20_poly1305_test test_vectors[] =
    {
        aead_chacha20_poly1305_test{
            "Example and Test Vector for AEAD_CHACHA20_POLY1305:",
            // ==============
            /* Plaintext: */ {
                /* 000 */ 0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, //  Ladies and Gentl
                /* 016 */ 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, //  emen of the clas
                /* 032 */ 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, //  s of '99: If I c
                /* 048 */ 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, //  ould offer you o
                /* 064 */ 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, //  nly one tip for
                /* 080 */ 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, //  the future, suns
                /* 096 */ 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, //  creen would be i
                /* 112 */ 0x74, 0x2e,                                                                                     //  t.
            },
            /* AAD: */ {
                /* 000 */ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, //  PQRS........
            },
            /* Key: */ {
                /* 000 */ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, //  ................
                /* 016 */ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, //  ................
            },
            /* constant-part + IV: */ {
                /* 000 */ 0x07, 0x00, 0x00, 0x00,                         //  ....
                /* 000 */ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, //  @ABCDEFG
            },
            /* Ciphertext: */ {
                /* 000 */ 0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, //  ...4d.`.{...S.~.
                /* 016 */ 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, //  ...Q)n......6.b.
                /* 032 */ 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, //  =..^..g....i..r.
                /* 048 */ 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, //  .q.....)....~.;6
                /* 064 */ 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, //  ....-w......(..X
                /* 080 */ 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, //  ..$...u.U...H1..
                /* 096 */ 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, //  ?....Kz..v.e...K
                /* 112 */ 0x61, 0x16                                                                                      //  a.
            },
            /* Tag: */ {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91}
        },

        {
            "A.5.  ChaCha20-Poly1305 AEAD Decryption:",
            // ==============
            /* Plaintext: */ {
                /* 000 */ 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20, //  Internet-Drafts
                /* 016 */ 0x61, 0x72, 0x65, 0x20, 0x64, 0x72, 0x61, 0x66, 0x74, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, //  are draft docume
                /* 032 */ 0x6e, 0x74, 0x73, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20, //  nts valid for a
                /* 048 */ 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x69, 0x78, 0x20, 0x6d, //  maximum of six m
                /* 064 */ 0x6f, 0x6e, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x79, 0x20, 0x62, 0x65, //  onths and may be
                /* 080 */ 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x2c, 0x20, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, //   updated, replac
                /* 096 */ 0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64, //  ed, or obsoleted
                /* 112 */ 0x20, 0x62, 0x79, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, //   by other docume
                /* 128 */ 0x6e, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x2e, //  nts at any time.
                /* 144 */ 0x20, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x61, 0x70, 0x70, 0x72, 0x6f, 0x70, 0x72, //   It is inappropr
                /* 160 */ 0x69, 0x61, 0x74, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x73, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, //  iate to use Inte
                /* 176 */ 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x73, 0x20, 0x61, 0x73, 0x20, 0x72, //  rnet-Drafts as r
                /* 192 */ 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, //  eference materia
                /* 208 */ 0x6c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x69, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65, //  l or to cite the
                /* 224 */ 0x6d, 0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x61, 0x73, 0x20, //  m other than as
                /* 240 */ 0x2f, 0xe2, 0x80, 0x9c, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x72, 0x6f, 0x67, //  /...work in prog
                /* 256 */ 0x72, 0x65, 0x73, 0x73, 0x2e, 0x2f, 0xe2, 0x80, 0x9d,                                           //  ress./...
            },
            /* AAD: */ {
                /* 000 */ 0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91, //  .3........N.
            },
            /* Key: */ {
                /* 000 */0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, //  ..@..U...3......
                /* 016 */0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0, //  G9..@+....\. pu.
            },
            /* The nonce: */ {
                /* 000 */ 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //  ............
            },
            /* Ciphertext: */ {
                /* 000 */ 0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd, //  d...u...`.b...C.
                /* 016 */ 0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2, //  ^.\.4\....g..l..
                /* 032 */ 0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0, //  Ll..u]C....N8-&.
                /* 048 */ 0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf, //  ...<2.....;.5X..
                /* 064 */ 0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81, //  3/..q......J....
                /* 080 */ 0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55, //  ...n..3.`....7.U
                /* 096 */ 0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38, //  ...n...a..2N+5.8
                /* 112 */ 0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4, //  6..{j|.....{S.g.
                /* 128 */ 0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9, //  ..lv{.MF..R.....
                /* 144 */ 0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e, //  .@...3"^.....lR>
                /* 160 */ 0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a, //  .E4..?..[.Gq..Tj
                /* 176 */ 0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a, //  ..+..VN..B"s.H'.
                /* 192 */ 0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e, //  ..1`S.v..U..1YCN
                /* 208 */ 0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10, //  ..NFm.Z.s.rv'.z.
                /* 224 */ 0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30, //  I....6...h..w.q0
                /* 240 */ 0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29, //  0[.......{qMlo,)
                /* 256 */ 0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b,                                           //  ..\..+.p.
            },
            /* Tag: */ {0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38}
        },
    };

    bool all_test_is_passed = true;
    for (auto&& tv : test_vectors)
    {
        // encrypt
        {
            auto buffer = std::vector<unsigned char>(tv.cipher_text.size(), 0);
            auto context = aead_chacha20_poly1305::prepare_aead_chacha20_poly1305_context(
                tv.aad.data(), tv.aad.size(),
                reinterpret_cast<const chacha20::key*>(tv.key.data()),
                reinterpret_cast<const chacha20::nonce*>(tv.nonce.data()));
            aead_chacha20_poly1305::encrypt_bytes(context, tv.plain_text.data(), buffer.data(), buffer.size());
            auto tag = aead_chacha20_poly1305::finalize_and_calculate_tag(context);

            if (!std::equal(buffer.begin(), buffer.end(), tv.cipher_text.begin(), tv.cipher_text.end()))
            {
                std::cerr << "TEST Encrypt [" << tv.name << "] data FAILED" << "\n";
                all_test_is_passed = false;
            }

            if (!std::equal(tag.begin(), tag.end(), tv.tag.begin(), tv.tag.end()))
            {
                std::cerr << "TEST Encrypt [" << tv.name << "] tag FAILED" << "\n";
                all_test_is_passed = false;
            }
        }

        // decrypt
        {
            auto buffer = std::vector<unsigned char>(tv.plain_text.size(), 0);
            auto context = aead_chacha20_poly1305::prepare_aead_chacha20_poly1305_context(
                tv.aad.data(), tv.aad.size(),
                reinterpret_cast<const chacha20::key*>(tv.key.data()),
                reinterpret_cast<const chacha20::nonce*>(tv.nonce.data()));
            aead_chacha20_poly1305::decrypt_bytes(context, tv.cipher_text.data(), buffer.data(), buffer.size());
            auto tag = aead_chacha20_poly1305::finalize_and_calculate_tag(context);

            if (!std::equal(buffer.begin(), buffer.end(), tv.plain_text.begin(), tv.plain_text.end()))
            {
                std::cerr << "TEST Decrypt [" << tv.name << "] data FAILED" << "\n";
                all_test_is_passed = false;
            }

            if (!std::equal(tag.begin(), tag.end(), tv.tag.begin(), tv.tag.end()))
            {
                std::cerr << "TEST Decrypt [" << tv.name << "] tag FAILED" << "\n";
                all_test_is_passed = false;
            }
        }
    }

    return all_test_is_passed ? 0 : 1;
}
