/// @file
/// @brief  chacha20.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <array>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#ifdef __AVX2__
#include "./xmm.h"
#endif

namespace chacha20
{
    using byte = uint8_t;
    using key = std::array<byte, 32>;
    using nonce = std::array<byte, 12>;

    namespace impl
    {
        namespace intrinsics
        {
#if defined(_MSC_VER)
            static inline uint32_t rotl(uint32_t v, int i) noexcept { return ::_rotl(v, i); }
#elif defined(__clang__)
            static inline uint32_t rotl(uint32_t v, int i) noexcept { return ::__builtin_rotateleft32(v, static_cast<unsigned char>(i)); }
#elif defined(__GNUC__)
            static inline uint32_t rotl(uint32_t v, int i) noexcept { return ::__rold(v, i); }
#else
            static inline constexpr uint16_t rotl(uint16_t v, int i) noexcept { return static_cast<uint16_t>(v << (i & 15) | v >> (-i & 15)); }
#endif
        }

        template <class uint32_t>
        static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
        {
            using intrinsics::rotl;
            a += b;
            d ^= a;
            d = rotl(d, 16);
            c += d;
            b ^= c;
            b = rotl(b, 12);
            a += b;
            d ^= a;
            d = rotl(d, 8);
            c += d;
            b ^= c;
            b = rotl(b, 7);
        }

        template <class context_t, class block_t>
        static void process_stream(context_t& ctx, const void* input, void* output, size_t position, size_t length)
        {
            constexpr size_t block_size = sizeof(block_t);

            uint32_t bi = static_cast<uint32_t>(position / block_size);
            if (size_t pad = position % block_size)
            {
                size_t len = std::min(length, block_size - pad);
                block_t b{};
                std::memcpy(reinterpret_cast<byte*>(&b) + pad, input, len);
                process_block(ctx, bi++, &b, &b);
                std::memcpy(reinterpret_cast<byte*>(output), reinterpret_cast<byte*>(&b) + pad, len);
                position += len;
                input = reinterpret_cast<const byte*>(input) + len;
                output = reinterpret_cast<byte*>(output) + len;
                length -= len;
            }

            while (length >= block_size)
            {
                process_block(ctx, bi++, reinterpret_cast<const block_t*>(input), reinterpret_cast<block_t*>(output));
                position += block_size;
                input = reinterpret_cast<const byte*>(input) + block_size;
                output = reinterpret_cast<byte*>(output) + block_size;
                length -= block_size;
            }

            if (size_t len = length)
            {
                block_t b{};
                std::memcpy(reinterpret_cast<byte*>(&b), input, len);
                process_block(ctx, bi++, &b, &b);
                std::memcpy(reinterpret_cast<byte*>(output), reinterpret_cast<byte*>(&b), len);
                position += len;
                input = reinterpret_cast<const byte*>(input) + len;
                output = reinterpret_cast<byte*>(output) + len;
                length -= len;
            }
        }
    }

    namespace ref
    {
        using chacha_state = std::array<uint32_t, 16>;

        using block_t = chacha_state;

        struct context_t
        {
            chacha_state zero;
        };

        static context_t prepare_context(const key* key, const nonce* nonce, uint32_t initial_counter = 0)
        {
            context_t ctx{};
            constexpr std::array<uint32_t, 4> k = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,};
            std::memcpy(ctx.zero.data() + 0, &k, sizeof(uint32_t) * 4);                // 0..3
            std::memcpy(ctx.zero.data() + 4, key, sizeof(uint32_t) * 8);               // 4..11
            std::memcpy(ctx.zero.data() + 12, &initial_counter, sizeof(uint32_t) * 1); // 12..12
            std::memcpy(ctx.zero.data() + 13, nonce, sizeof(uint32_t) * 3);            // 13..16
            return ctx;
        }

        static void process_block(const context_t& ctx, uint32_t counter, const block_t* input, block_t* output)
        {
            auto w = ctx.zero;
            w[12] += counter;

            for (int j = 0; j < 10; ++j)
            {
                impl::quarter_round(w[0], w[4], w[8], w[12]);
                impl::quarter_round(w[1], w[5], w[9], w[13]);
                impl::quarter_round(w[2], w[6], w[10], w[14]);
                impl::quarter_round(w[3], w[7], w[11], w[15]);
                impl::quarter_round(w[0], w[5], w[10], w[15]);
                impl::quarter_round(w[1], w[6], w[11], w[12]);
                impl::quarter_round(w[2], w[7], w[8], w[13]);
                impl::quarter_round(w[3], w[4], w[9], w[14]);
            }

            for (int j = 0; j < 16; ++j)
                w[j] += ctx.zero[j];

            w[12] += counter;

            for (int i = 0; i < 16; i++)
                output->operator[](i) = input->operator[](i) ^ w[i];
        }

        static void process_stream(const context_t& ctx, const void* input, void* output, size_t position, size_t length)
        {
            return impl::process_stream<const context_t, block_t>(ctx, input, output, position, length);
        }
    }

#ifdef __AVX2__
    namespace avx2
    {
        struct chacha_state2x
        {
            arkxmm::vu32x8 r0;
            arkxmm::vu32x8 r1;
            arkxmm::vu32x8 r2;
            arkxmm::vu32x8 r3;
        };

        struct chacha_state4x
        {
            chacha_state2x state0, state1;
        };

        using block_t = chacha_state4x;

        struct context_t
        {
            chacha_state2x zero;
        };

        static context_t prepare_context(const key* key, const nonce* nonce, uint32_t initial_counter = 0)
        {
            arkxmm::vu32x4 r0 = arkxmm::u32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);
            arkxmm::vu32x4 r1 = arkxmm::load_u<arkxmm::vu32x4>(key->data() + 0);
            arkxmm::vu32x4 r2 = arkxmm::load_u<arkxmm::vu32x4>(key->data() + 16);
            arkxmm::vu32x4 r3 = arkxmm::u32x4(
                initial_counter,
                reinterpret_cast<const uint32_t*>(nonce)[0],
                reinterpret_cast<const uint32_t*>(nonce)[1],
                reinterpret_cast<const uint32_t*>(nonce)[2]);

            return context_t{
                {
                    arkxmm::u32x8(r0),
                    arkxmm::u32x8(r1),
                    arkxmm::u32x8(r2),
                    arkxmm::u32x8(r3),
                }
            };
        }

        ARKXMM_API process_block(const context_t& ctx, uint32_t counter, const block_t* input, block_t* output)
        {
            block_t w = {ctx.zero, ctx.zero};
            auto k = arkxmm::u32x8(counter * 4, 0, 0, 0);
            auto k1 = k + arkxmm::u32x8(0, 0, 0, 0, 1, 0, 0, 0);
            auto k2 = k + arkxmm::u32x8(2, 0, 0, 0, 3, 0, 0, 0);
            w.state0.r3 += k1;
            w.state1.r3 += k2;

            for (int j = 0; j < 10; ++j)
            {
                impl::quarter_round(w.state0.r0, w.state0.r1, w.state0.r2, w.state0.r3);
                impl::quarter_round(w.state1.r0, w.state1.r1, w.state1.r2, w.state1.r3);
                w.state0.r1 = arkxmm::shuffle<1, 2, 3, 0>(w.state0.r1);
                w.state0.r2 = arkxmm::shuffle<2, 3, 0, 1>(w.state0.r2);
                w.state0.r3 = arkxmm::shuffle<3, 0, 1, 2>(w.state0.r3);
                w.state1.r1 = arkxmm::shuffle<1, 2, 3, 0>(w.state1.r1);
                w.state1.r2 = arkxmm::shuffle<2, 3, 0, 1>(w.state1.r2);
                w.state1.r3 = arkxmm::shuffle<3, 0, 1, 2>(w.state1.r3);
                impl::quarter_round(w.state0.r0, w.state0.r1, w.state0.r2, w.state0.r3);
                impl::quarter_round(w.state1.r0, w.state1.r1, w.state1.r2, w.state1.r3);
                w.state0.r1 = arkxmm::shuffle<3, 0, 1, 2>(w.state0.r1);
                w.state0.r2 = arkxmm::shuffle<2, 3, 0, 1>(w.state0.r2);
                w.state0.r3 = arkxmm::shuffle<1, 2, 3, 0>(w.state0.r3);
                w.state1.r1 = arkxmm::shuffle<3, 0, 1, 2>(w.state1.r1);
                w.state1.r2 = arkxmm::shuffle<2, 3, 0, 1>(w.state1.r2);
                w.state1.r3 = arkxmm::shuffle<1, 2, 3, 0>(w.state1.r3);
            }

            w.state0.r0 += ctx.zero.r0;
            w.state0.r1 += ctx.zero.r1;
            w.state0.r2 += ctx.zero.r2;
            w.state0.r3 += ctx.zero.r3;
            w.state1.r0 += ctx.zero.r0;
            w.state1.r1 += ctx.zero.r1;
            w.state1.r2 += ctx.zero.r2;
            w.state1.r3 += ctx.zero.r3;
            w.state0.r3 += k1;
            w.state1.r3 += k2;

            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r0, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r0) ^ arkxmm::permute128<0, 2>(w.state0.r0, w.state0.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r1, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r1) ^ arkxmm::permute128<0, 2>(w.state0.r2, w.state0.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r2, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r2) ^ arkxmm::permute128<1, 3>(w.state0.r0, w.state0.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r3, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r3) ^ arkxmm::permute128<1, 3>(w.state0.r2, w.state0.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r0, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r0) ^ arkxmm::permute128<0, 2>(w.state1.r0, w.state1.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r1, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r1) ^ arkxmm::permute128<0, 2>(w.state1.r2, w.state1.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r2, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r2) ^ arkxmm::permute128<1, 3>(w.state1.r0, w.state1.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r3, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r3) ^ arkxmm::permute128<1, 3>(w.state1.r2, w.state1.r3));
        }

        static void process_stream(const context_t& ctx, const void* input, void* output, size_t position, size_t length)
        {
            static_assert(sizeof block_t == 256);
            return impl::process_stream<const context_t, block_t>(ctx, input, output, position, length);
        }
    }
#endif

#ifndef __AVX2__
    using ref::context_t;
    using ref::prepare_context;
    using ref::process_stream;
#else
    using avx2::context_t;
    using avx2::prepare_context;
    using avx2::process_stream;
#endif
}
