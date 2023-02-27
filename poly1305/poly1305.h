/// @file
/// @brief  poly1305.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "./intrinsics.h"

namespace message_digest_helper
{
    template <size_t input_block_size>
    struct digest_input_state_t
    {
        static constexpr inline size_t block_size = input_block_size;
        std::array<std::byte, block_size> buffer{};
        size_t buffer_remains{};
    };

    template <class process_block_function, class digest_context, size_t input_block_size>
    static ARKANA_FORCEINLINE void process_bytes(
        digest_input_state_t<input_block_size>& input_state,
        process_block_function&& process_blocks,
        digest_context& context,
        const void* message, size_t length)
    {
        const std::byte* src = static_cast<const std::byte*>(message);
        const std::byte* end = src + length;

        if (size_t offset = input_state.buffer_remains)
        {
            size_t bytes = std::min<size_t>(input_block_size - offset, end - src);
            memcpy(input_state.buffer.data() + offset, src, bytes);
            src += bytes;
            if (input_state.buffer_remains += bytes; input_state.buffer_remains == input_block_size)
            {
                process_blocks(context, input_state.buffer.data(), input_block_size);
                input_state.buffer_remains = 0;
            }
        }

        if (size_t bytes = (end - src) & ~(input_block_size - 1))
        {
            process_blocks(context, src, bytes);
            src += bytes;
        }

        if (size_t remains = end - src)
        {
            memcpy(input_state.buffer.data(), src, remains);
            input_state.buffer_remains = remains;
            src += remains;
        }
    }

    template <class process_block_function, class get_digest_function, class digest_context, size_t input_block_size>
    static ARKANA_FORCEINLINE auto finalize(
        digest_input_state_t<input_block_size>& input_state,
        process_block_function&& process_final_block,
        get_digest_function&& get_digest,
        digest_context& context)
    {
        process_final_block(context, input_state.buffer.data(), input_state.buffer_remains); // may be calling with 0 bytes
        return get_digest(context);
    }
}

namespace poly1305
{
    using byte = uint8_t;
    using key_r = std::array<byte, 16>;
    using key_s = std::array<byte, 16>;
    using mac = std::array<byte, 16>;

    namespace x86
    {
        namespace impl
        {
            using uint128_t = std::array<uint32_t, 4>;
            using uint130_t = std::array<uint32_t, 5>;

            static ARKANA_FORCEINLINE void process_chunk(uint130_t& h, uint128_t in, uint32_t pad, uint128_t r)
            {
                using namespace arkintr;

                // h += in
                adc(adc(adc(adc(adc(0, h[0], in[0]), h[1], in[1]), h[2], in[2]), h[3], in[3]), h[4], pad);

                // e = h * r
                std::array<uint32_t, 8> e{};
                {
                    std::array<uint64_t, 8> d{};
                    d[0] += muld(h[0], r[0]);
                    d[1] += muld(h[0], r[1]);
                    d[2] += muld(h[0], r[2]);
                    d[3] += muld(h[0], r[3]);
                    d[1] += muld(h[1], r[0]);
                    d[2] += muld(h[1], r[1]);
                    d[3] += muld(h[1], r[2]);
                    d[4] += muld(h[1], r[3]);
                    d[2] += muld(h[2], r[0]);
                    d[3] += muld(h[2], r[1]);
                    d[4] += muld(h[2], r[2]);
                    d[5] += muld(h[2], r[3]);
                    d[3] += muld(h[3], r[0]);
                    d[4] += muld(h[3], r[1]);
                    d[5] += muld(h[3], r[2]);
                    d[6] += muld(h[3], r[3]);
                    d[4] += muld(h[4], r[0]);
                    d[5] += muld(h[4], r[1]);
                    d[6] += muld(h[4], r[2]);
                    d[7] += muld(h[4], r[3]);

                    e[0] = static_cast<uint32_t>(d[0]);
                    e[1] = static_cast<uint32_t>(d[1] += (d[0] >> 32));
                    e[2] = static_cast<uint32_t>(d[2] += (d[1] >> 32));
                    e[3] = static_cast<uint32_t>(d[3] += (d[2] >> 32));
                    e[4] = static_cast<uint32_t>(d[4] += (d[3] >> 32));
                    e[5] = static_cast<uint32_t>(d[5] += (d[4] >> 32));
                    e[6] = static_cast<uint32_t>(d[6] += (d[5] >> 32));
                    e[7] = static_cast<uint32_t>(d[7] += (d[6] >> 32));
                }

                // h = e & (1<<130)-1
                h[0] = e[0];
                h[1] = e[1];
                h[2] = e[2];
                h[3] = e[3];
                h[4] = e[4] & 3;

                // h += (1+4) * (e>>130)
                adc(adc(adc(adc(adc(0, h[0], e[4] >> 2 | e[5] << 30), h[1], e[5] >> 2 | e[6] << 30), h[2], e[6] >> 2 | e[7] << 30), h[3], e[7] >> 2), h[4], 0u);
                adc(adc(adc(adc(adc(0, h[0], e[4] & ~3), h[1], e[5]), h[2], e[6]), h[3], e[7]), h[4], 0u);
            }

            static ARKANA_FORCEINLINE mac finalize(uint130_t& h, uint128_t s)
            {
                using namespace arkintr;

                // final reduction

                while (h[4] >= 4)
                {
                    auto t = std::exchange(h[4], h[4] & 3);
                    adc(adc(adc(adc(adc(0, h[0], t >> 2), h[1], 0u), h[2], 0u), h[3], 0u), h[4], 0u);
                    adc(adc(adc(adc(adc(0, h[0], t & ~3u), h[1], 0u), h[2], 0u), h[3], 0u), h[4], 0u);
                }

                constexpr uint130_t prime1305 = {0xFFFFFFFBu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 3u};
                if (std::tie(h[4], h[3], h[2], h[1], h[0]) >= std::make_tuple(prime1305[4], prime1305[3], prime1305[2], prime1305[1], prime1305[0]))
                    sbb(sbb(sbb(sbb(sbb(0, h[0], prime1305[0]), h[1], prime1305[1]), h[2], prime1305[2]), h[3], prime1305[3]), h[4], prime1305[4]);

                // h += s
                adc(adc(adc(adc(adc(0, h[0], s[0]), h[1], s[1]), h[2], s[2]), h[3], s[3]), h[4], 0u);
                return load_u<mac>(h.data());
            }
        }

        struct poly1305_tag_context
        {
            impl::uint130_t h{};
            impl::uint128_t r{};
            impl::uint128_t s{};
            message_digest_helper::digest_input_state_t<16> input{};
        };

        static poly1305_tag_context prepare_poly1305_tag_context(const key_r* r, const key_s* s)
        {
            using namespace arkintr;
            poly1305_tag_context ctx{};
            ctx.r = load_u<impl::uint128_t>(r);
            ctx.s = load_u<impl::uint128_t>(s);
            ctx.r[0] &= 0x0FFFFFFFu;
            ctx.r[1] &= 0x0FFFFFFCu;
            ctx.r[2] &= 0x0FFFFFFCu;
            ctx.r[3] &= 0x0FFFFFFCu;
            return ctx;
        }

        static void process_bytes(poly1305_tag_context& ctx, const void* message, size_t length)
        {
            using namespace arkintr;
            return message_digest_helper::process_bytes(
                ctx.input,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    impl::uint130_t h = ctx.h;
                    impl::uint128_t& r = ctx.r;
                    for (size_t i = 0, n = length / 16; i < n; ++i)
                    {
                        impl::process_chunk(h, load_u<impl::uint128_t>(message), 1, r);
                        message += 16;
                    }
                    ctx.h = h;
                },
                ctx,
                message, length);
        }

        static mac finalize_and_get_mac(poly1305_tag_context& ctx)
        {
            using namespace arkintr;
            return message_digest_helper::finalize(
                ctx.input,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    impl::uint130_t h = ctx.h;
                    impl::uint128_t& r = ctx.r;
                    if (length)
                    {
                        impl::uint128_t in{};
                        memcpy(in.data(), message, length);
                        in[length / sizeof(uint32_t)] |= uint32_t{0x01} << (length % sizeof(uint32_t) * 8);
                        impl::process_chunk(h, in, 0, r);
                    }
                    ctx.h = h;
                },
                [](poly1305_tag_context& ctx)
                {
                    impl::uint130_t h = ctx.h;
                    impl::uint128_t& s = ctx.s;
                    return impl::finalize(h, s);
                },
                ctx);
        }
    }

    namespace x64
    {
        namespace impl
        {
            using uint128_t = std::array<uint64_t, 2>;
            using uint130_t = std::array<uint64_t, 3>;

            static ARKANA_FORCEINLINE void process_chunk(uint130_t& h, uint128_t in, uint64_t pad, uint128_t r) noexcept
            {
                using namespace arkintr;

                // h += in
                adc(adc(adc(0, h[0], in[0]), h[1], in[1]), h[2], pad);

                // e = h * r
                std::array<uint64x2_t, 2> e{};
                {
                    std::array<uint64x2_t, 4> d{};
                    d[0] += muld(h[0], r[0]);
                    d[1] += muld(h[0], r[1]);
                    d[1] += muld(h[1], r[0]);
                    d[2] += muld(h[1], r[1]);
                    d[2] += muld(h[2], r[0]);
                    d[3] += muld(h[2], r[1]);

                    e[0].l = (d[0]).l;
                    e[0].h = (d[1] += uint64x2_t{d[0].h}).l;
                    e[1].l = (d[2] += uint64x2_t{d[1].h}).l;
                    e[1].h = (d[3] += uint64x2_t{d[2].h}).l;
                }

                // h = e & (1<<130)-1
                h[0] = e[0].l;
                h[1] = e[0].h;
                h[2] = e[1].l & 3;

                // h += (1+4) * (e>>130)
                adc(adc(adc(0, h[0], shrd(e[1].l, e[1].h, 2)), h[1], e[1].h >> 2), h[2], 0ull);
                adc(adc(adc(0, h[0], e[1].l & ~3ull), h[1], e[1].h), h[2], 0ull);
            }

            static ARKANA_FORCEINLINE mac finalize(uint130_t& h, uint128_t s) noexcept
            {
                using namespace arkintr;

                // final reduction
                while (h[2] >= 4)
                {
                    auto t = std::exchange(h[2], h[2] & 3);
                    adc(adc(adc(0, h[0], t >> 2), h[1], 0ull), h[2], 0ull);
                    adc(adc(adc(0, h[0], t & ~3ull), h[1], 0ull), h[2], 0ull);
                }

                constexpr uint130_t prime1305 = {0xFFFFFFFFFFFFFFFBu, 0xFFFFFFFFFFFFFFFFu, 3u};
                if (std::tie(h[2], h[1], h[0]) >= std::tie(prime1305[2], prime1305[1], prime1305[0]))
                    sbb(sbb(sbb(0, h[0], prime1305[0]), h[1], prime1305[1]), h[2], prime1305[2]);

                adc(adc(adc(0, h[0], s[0]), h[1], s[1]), h[2], 0ull);
                return load_u<mac>(h.data());
            }
        }

        struct poly1305_tag_context
        {
            impl::uint130_t h{};
            impl::uint128_t r{};
            impl::uint128_t s{};
            message_digest_helper::digest_input_state_t<16> input{};
        };

        static poly1305_tag_context prepare_poly1305_tag_context(const key_r* r, const key_s* s) noexcept
        {
            using namespace arkintr;
            poly1305_tag_context ctx{};
            ctx.r = load_u<impl::uint128_t>(r);
            ctx.s = load_u<impl::uint128_t>(s);
            ctx.r[0] &= 0x0FFFFFFC0FFFFFFFull;
            ctx.r[1] &= 0x0FFFFFFC0FFFFFFCull;
            return ctx;
        }

        static void process_bytes(poly1305_tag_context& ctx, const void* message, size_t length) noexcept
        {
            using namespace arkintr;
            return message_digest_helper::process_bytes(
                ctx.input,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    impl::uint130_t h = ctx.h;
                    for (size_t i = 0, n = length / 16; i < n; ++i)
                    {
                        impl::process_chunk(h, load_u<impl::uint128_t>(message), 1, ctx.r);
                        message += 16;
                    }
                    ctx.h = h;
                },
                ctx,
                message, length);
        }

        static mac finalize_and_get_mac(poly1305_tag_context& ctx) noexcept
        {
            using namespace arkintr;
            return message_digest_helper::finalize(
                ctx.input,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    impl::uint130_t h = ctx.h;
                    if (length)
                    {
                        impl::uint128_t in{};
                        memcpy(&in, message, length);
                        in[length / sizeof(uint64_t)] |= uint64_t{0x01} << (length % sizeof(uint64_t) * 8);
                        impl::process_chunk(h, in, 0, ctx.r);
                    }
                    ctx.h = h;
                },
                [](poly1305_tag_context& ctx)
                {
                    auto h = ctx.h;
                    return impl::finalize(h, ctx.s);
                },
                ctx);
        }
    }

    static inline mac calculate_poly1305_x86(const key_r* r, const key_s* s, const void* message, size_t length)
    {
        auto ctx = x86::prepare_poly1305_tag_context(r, s);
        x86::process_bytes(ctx, message, length);
        return x86::finalize_and_get_mac(ctx);
    }

    static inline mac calculate_poly1305_x64(const key_r* r, const key_s* s, const void* message, size_t length)
    {
        auto ctx = x64::prepare_poly1305_tag_context(r, s);
        x64::process_bytes(ctx, message, length);
        return x64::finalize_and_get_mac(ctx);
    }

    static inline mac calculate_poly1305(const key_r* r, const key_s* s, const byte* message, size_t length)
    {
        if constexpr (sizeof(void*) == 8)
            return calculate_poly1305_x64(r, s, message, length);
        else
            return calculate_poly1305_x86(r, s, message, length);
    }

#if (defined(_MSC_VER) && _MSC_VER >= 1920 && defined(_M_X64)) || defined(__x86_64__) // 64bit MSVC(2019 or later), GCC, clang
    using x64::prepare_poly1305_tag_context;
#else
    using x86::prepare_poly1305_tag_context;
#endif
    using x86::process_bytes;
    using x86::finalize_and_get_mac;
    using x64::process_bytes;
    using x64::finalize_and_get_mac;
}
