/// @file
/// @brief  chacha20.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <array>

#ifdef __RESHARPER__
#define __AVX2__
#endif

#include "../ark/intrinsics.h"
#include "../ark/ctr_cipher_stream_helper.h"

#ifdef __AVX2__
#include "../ark/xmm.h"
#endif

namespace chacha20
{
    using byte = uint8_t;
    using key = std::array<byte, 32>;
    using nonce = std::array<byte, 12>;
    using position_t = uint64_t; // max 256 GiB
    using counter_t = uint32_t;

    // private impl
    namespace common::impl
    {
        template <class uint32_t>
        static ARKANA_FORCEINLINE void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
        {
            using arkintr::rotl;
            d = rotl(d ^= a += b, 16);
            b = rotl(b ^= c += d, 12);
            d = rotl(d ^= a += b, 8);
            b = rotl(b ^= c += d, 7);
        }

        template <class context_t, class block_t>
        static void process_stream(const context_t& ctx, const void* input, void* output, position_t position, size_t length)
        {
            return arkana::ctr_cipher_stream_helper::process_stream_with_ctr<block_t, counter_t, position_t>(
                [](const context_t& ctx, const block_t* input, block_t* output, counter_t counter, size_t block_count)
                {
                    for (size_t i = 0; i < block_count; ++i, ++counter, ++input, ++output)
                        process_block(ctx, counter, input, output); // ADL
                },
                ctx,
                static_cast<const std::byte*>(input),
                static_cast<std::byte*>(output),
                position, length);
        }
    }

    // private impl
    namespace ref::impl
    {
        using chacha_state = std::array<uint32_t, 16>;

        using block_t = chacha_state;

        struct context_t
        {
            chacha_state zero;
        };

        static context_t prepare_context(const key* key, const nonce* nonce, counter_t initial_counter = 0)
        {
            context_t ctx{};
            constexpr std::array<uint32_t, 4> k = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,};
            std::memcpy(ctx.zero.data() + 0, &k, sizeof(uint32_t) * 4);                // 0..3
            std::memcpy(ctx.zero.data() + 4, key, sizeof(uint32_t) * 8);               // 4..11
            std::memcpy(ctx.zero.data() + 12, &initial_counter, sizeof(uint32_t) * 1); // 12..12
            std::memcpy(ctx.zero.data() + 13, nonce, sizeof(uint32_t) * 3);            // 13..16
            return ctx;
        }

        static ARKANA_FORCEINLINE void process_block(const context_t& ctx, counter_t counter, const block_t* input, block_t* output)
        {
            auto w = ctx.zero;
            w[12] += counter;

            for (int j = 0; j < 10; ++j)
            {
                using common::impl::quarter_round;
                quarter_round(w[0], w[4], w[8], w[12]);
                quarter_round(w[1], w[5], w[9], w[13]);
                quarter_round(w[2], w[6], w[10], w[14]);
                quarter_round(w[3], w[7], w[11], w[15]);
                quarter_round(w[0], w[5], w[10], w[15]);
                quarter_round(w[1], w[6], w[11], w[12]);
                quarter_round(w[2], w[7], w[8], w[13]);
                quarter_round(w[3], w[4], w[9], w[14]);
            }

            for (int j = 0; j < 16; ++j)
                w[j] += ctx.zero[j];

            w[12] += counter;

            for (int i = 0; i < 16; i++)
                output->operator[](i) = input->operator[](i) ^ w[i];
        }

        static void process_stream(const context_t& ctx, const void* input, void* output, position_t position, size_t length)
        {
            return common::impl::process_stream<const context_t, block_t>(ctx, input, output, position, length);
        }
    }

#ifdef __AVX2__
    // private impl
    namespace avx2::impl
    {
        struct chacha_state
        {
            // sse
            arkxmm::vu32x4 r0;
            arkxmm::vu32x4 r1;
            arkxmm::vu32x4 r2;
            arkxmm::vu32x4 r3;
        };

        template <class chacha_state> ARKXMM_API chacha_single_round(chacha_state s) noexcept -> chacha_state
        {
            s.r3 = byte_rotr2(s.r3 ^= s.r0 += s.r1);
            s.r1 = rotl(s.r1 ^= s.r2 += s.r3, 12);
            s.r3 = byte_rotr3(s.r3 ^= s.r0 += s.r1);
            s.r1 = rotl(s.r1 ^= s.r2 += s.r3, 7);
            return s;
        }

        template <class chacha_state> ARKXMM_API chacha_shuffle_a(chacha_state s) noexcept -> chacha_state
        {
            s.r1 = arkxmm::shuffle<1, 2, 3, 0>(s.r1);
            s.r2 = arkxmm::shuffle<2, 3, 0, 1>(s.r2);
            s.r3 = arkxmm::shuffle<3, 0, 1, 2>(s.r3);
            return s;
        }

        template <class chacha_state> ARKXMM_API chacha_shuffle_b(chacha_state s) noexcept -> chacha_state
        {
            s.r1 = arkxmm::shuffle<3, 0, 1, 2>(s.r1);
            s.r2 = arkxmm::shuffle<2, 3, 0, 1>(s.r2);
            s.r3 = arkxmm::shuffle<1, 2, 3, 0>(s.r3);
            return s;
        }

        template <class chacha_state> ARKXMM_API chacha_double_round(chacha_state& s) noexcept
        {
            s = chacha_single_round(s);
            s = chacha_shuffle_a(s);
            s = chacha_single_round(s);
            s = chacha_shuffle_b(s);
        }

        template <class chacha_state> ARKXMM_API chacha_double_round_parallel(chacha_state& s0, chacha_state& s1) noexcept
        {
            s0 = chacha_single_round(s0);
            s1 = chacha_single_round(s1);
            s0 = chacha_shuffle_a(s0);
            s1 = chacha_shuffle_a(s1);

            s0 = chacha_single_round(s0);
            s1 = chacha_single_round(s1);
            s0 = chacha_shuffle_b(s0);
            s1 = chacha_shuffle_b(s1);
        }

        struct chacha_state2x
        {
            // avx
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

        static context_t prepare_context(const key* key, const nonce* nonce, counter_t initial_counter = 0)
        {
            chacha_state state = {
                arkxmm::u32x4(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574),
                arkxmm::load_u<arkxmm::vu32x4>(key->data() + 0),
                arkxmm::load_u<arkxmm::vu32x4>(key->data() + 16),
                arkxmm::u32x4(
                    initial_counter,
                    reinterpret_cast<const uint32_t*>(nonce)[0],
                    reinterpret_cast<const uint32_t*>(nonce)[1],
                    reinterpret_cast<const uint32_t*>(nonce)[2]),
            };

            chacha_state2x state2x{u32x8(state.r0), u32x8(state.r1), u32x8(state.r2), u32x8(state.r3)};
            return context_t{state2x};
        }

        ARKXMM_API process_block(const context_t& ctx, uint32_t counter, const block_t* input, block_t* output) noexcept
        {
            auto s0 = ctx.zero;
            auto s1 = ctx.zero;

            auto k = arkxmm::u32x8(counter * 4, 0, 0, 0);
            auto init_s0r3 = s0.r3 += k + arkxmm::u32x8(0, 0, 0, 0, 1, 0, 0, 0);
            auto init_s1r3 = s1.r3 += k + arkxmm::u32x8(2, 0, 0, 0, 3, 0, 0, 0);

            // manual unrolling for msvc x86
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);
            chacha_double_round_parallel(s0, s1);

            s0.r0 += ctx.zero.r0;
            s0.r1 += ctx.zero.r1;
            s0.r2 += ctx.zero.r2;
            s0.r3 += init_s0r3;

            s1.r0 += ctx.zero.r0;
            s1.r1 += ctx.zero.r1;
            s1.r2 += ctx.zero.r2;
            s1.r3 += init_s1r3;

            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r0, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r0) ^ arkxmm::permute128<0, 2>(s0.r0, s0.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r1, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r1) ^ arkxmm::permute128<0, 2>(s0.r2, s0.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r2, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r2) ^ arkxmm::permute128<1, 3>(s0.r0, s0.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state0.r3, arkxmm::load_u<arkxmm::vu32x8>(&input->state0.r3) ^ arkxmm::permute128<1, 3>(s0.r2, s0.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r0, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r0) ^ arkxmm::permute128<0, 2>(s1.r0, s1.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r1, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r1) ^ arkxmm::permute128<0, 2>(s1.r2, s1.r3));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r2, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r2) ^ arkxmm::permute128<1, 3>(s1.r0, s1.r1));
            arkxmm::store_u<arkxmm::vu32x8>(&output->state1.r3, arkxmm::load_u<arkxmm::vu32x8>(&input->state1.r3) ^ arkxmm::permute128<1, 3>(s1.r2, s1.r3));
        }

        static void process_stream(const context_t& ctx, const void* input, void* output, position_t position, size_t length)
        {
            return common::impl::process_stream<const context_t, block_t>(ctx, input, output, position, length);
        }
    }
#endif

    namespace ref
    {
        using impl::context_t;
        using impl::prepare_context;
        using impl::process_stream;
    }

#ifdef __AVX2__
    namespace avx2
    {
        using impl::context_t;
        using impl::prepare_context;
        using impl::process_stream;
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
