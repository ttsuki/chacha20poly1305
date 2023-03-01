/// @file
/// @brief  poly1305.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "./intrinsics.h"
#include "message_digest_helper.h"

namespace poly1305
{
    using byte = uint8_t;
    using key_r = std::array<byte, 16>;
    using key_s = std::array<byte, 16>;
    using mac = std::array<byte, 16>;

    // private impl
    namespace x86::impl
    {
        struct impl_tag {};

        using uint128_t = std::array<uint32_t, 4>;
        using uint130_t = std::array<uint32_t, 6>;

        static ARKANA_FORCEINLINE void initialize_state(impl_tag, uint128_t& r, uint128_t& s, const key_r* r_in, const key_s* s_in) noexcept
        {
            using namespace arkintr;

            r = load_u<uint128_t>(r_in);
            s = load_u<uint128_t>(s_in);
            r[0] &= 0x0FFFFFFF;
            r[1] &= 0x0FFFFFFC;
            r[2] &= 0x0FFFFFFC;
            r[3] &= 0x0FFFFFFC;
        }

        static ARKANA_FORCEINLINE void process_chunk(impl_tag, uint130_t& h, uint128_t in, uint32_t pad, const uint128_t& r) noexcept
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

        static ARKANA_FORCEINLINE mac finalize_and_get_mac(impl_tag, uint130_t& h, const uint128_t& s) noexcept
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

    // private impl
    namespace x64::impl
    {
        struct impl_tag {};

        using uint128_t = std::array<uint64_t, 2>;
        using uint130_t = std::array<uint64_t, 3>;

        static ARKANA_FORCEINLINE void initialize_state(impl_tag, uint128_t& r, uint128_t& s, const key_r* r_in, const key_s* s_in) noexcept
        {
            using namespace arkintr;
            r = load_u<uint128_t>(r_in);
            s = load_u<uint128_t>(s_in);
            r[0] &= 0x0FFFFFFC0FFFFFFFull;
            r[1] &= 0x0FFFFFFC0FFFFFFCull;
        }

        static ARKANA_FORCEINLINE void process_chunk(impl_tag, uint130_t& h, uint128_t in, uint64_t pad, const uint128_t& r) noexcept
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

        static ARKANA_FORCEINLINE mac finalize_and_get_mac(impl_tag, uint130_t& h, uint128_t s) noexcept
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

    // private impl
    namespace common::impl
    {
        template <class poly1305_tag_context>
        static inline poly1305_tag_context prepare_poly1305_tag_context(const key_r* r, const key_s* s)
        {
            poly1305_tag_context ctx{};
            initialize_state(ctx.tag, ctx.r, ctx.s, r, s);
            return ctx;
        }

        template <class poly1305_tag_context>
        static inline poly1305_tag_context& process_bytes(poly1305_tag_context& ctx, const void* message, size_t length)
        {
            using namespace arkintr;
            return arkana::message_digest_helper::process_bytes(
                ctx,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    auto h = ctx.h;
                    auto& r = ctx.r;
                    for (size_t i = 0, n = length / 16; i < n; ++i)
                    {
                        using input_layout_type = typename poly1305_tag_context::input_layout_type;
                        input_layout_type input = load_u<input_layout_type>(message);
                        process_chunk(ctx.tag, h, input, 1, r);
                        message += 16;
                    }
                    ctx.h = h;
                },
                ctx.input, message, length);
        }

        template <class poly1305_tag_context>
        static inline mac finalize_and_get_mac(poly1305_tag_context& ctx)
        {
            using namespace arkintr;
            auto mac = arkana::message_digest_helper::finalize(
                ctx,
                [](poly1305_tag_context& ctx, const std::byte* message, size_t length)
                {
                    auto h = ctx.h;
                    auto& r = ctx.r;
                    if (length)
                    {
                        using input_layout_type = typename poly1305_tag_context::input_layout_type;
                        using unit_t = typename input_layout_type::value_type;
                        input_layout_type input{};
                        memcpy(input.data(), message, length);
                        input[length / sizeof(unit_t)] |= unit_t{0x01} << (length % sizeof(unit_t) * 8);
                        process_chunk(ctx.tag, h, input, 0, r);
                    }
                    ctx.h = h;
                },
                [](poly1305_tag_context& ctx)
                {
                    auto h = ctx.h;
                    auto& s = ctx.s;
                    return finalize_and_get_mac(ctx.tag, h, s);
                },
                ctx.input);
            secure_be_zero(ctx);
            return mac;
        }

        template <class poly1305_tag_context>
        static inline mac calculate_poly1305(const key_r* r, const key_s* s, const void* message, size_t length)
        {
            auto ctx = prepare_poly1305_tag_context<poly1305_tag_context>(r, s);
            process_bytes(ctx, message, length);
            return finalize_and_get_mac(ctx);
        }
    }

    namespace x86
    {
        struct poly1305_tag_context
        {
            using input_layout_type = impl::uint128_t;
            impl::impl_tag tag{};
            impl::uint130_t h{};
            impl::uint128_t r{};
            impl::uint128_t s{};
            arkana::message_digest_helper::digest_input_state_t<16> input{};
        };

        static inline poly1305_tag_context prepare_poly1305_tag_context(const key_r* r, const key_s* s) { return common::impl::prepare_poly1305_tag_context<poly1305_tag_context>(r, s); }
        static inline poly1305_tag_context& process_bytes(poly1305_tag_context& ctx, const void* message, size_t length) { return common::impl::process_bytes<poly1305_tag_context>(ctx, message, length); }
        static inline mac finalize_and_get_mac(poly1305_tag_context& ctx) { return common::impl::finalize_and_get_mac(ctx); }
        static inline mac calculate_poly1305(const key_r* r, const key_s* s, const void* message, size_t length) { return common::impl::calculate_poly1305<poly1305_tag_context>(r, s, message, length); }
    }

    namespace x64
    {
        struct poly1305_tag_context
        {
            using input_layout_type = impl::uint128_t;
            impl::impl_tag tag{};
            impl::uint130_t h{};
            impl::uint128_t r{};
            impl::uint128_t s{};
            arkana::message_digest_helper::digest_input_state_t<16> input{};
        };

        static inline poly1305_tag_context prepare_poly1305_tag_context(const key_r* r, const key_s* s) { return common::impl::prepare_poly1305_tag_context<poly1305_tag_context>(r, s); }
        static inline poly1305_tag_context& process_bytes(poly1305_tag_context& ctx, const void* message, size_t length) { return common::impl::process_bytes<poly1305_tag_context>(ctx, message, length); }
        static inline mac finalize_and_get_mac(poly1305_tag_context& ctx) { return common::impl::finalize_and_get_mac(ctx); }
        static inline mac calculate_poly1305(const key_r* r, const key_s* s, const void* message, size_t length) { return common::impl::calculate_poly1305<poly1305_tag_context>(r, s, message, length); }
    }

    // Expose default implementation as api

#if (defined(_MSC_VER) && _MSC_VER >= 1920 && defined(_M_X64)) || defined(__x86_64__) // 64bit MSVC(2019 or later), GCC, clang
    using x64::poly1305_tag_context;
    using x64::prepare_poly1305_tag_context;
    using x64::process_bytes;
    using x64::finalize_and_get_mac;
    using x64::calculate_poly1305;
#else
    using x86::poly1305_tag_context;
    using x86::prepare_poly1305_tag_context;
    using x86::process_bytes;
    using x86::finalize_and_get_mac;
    using x86::calculate_poly1305;
#endif
}
