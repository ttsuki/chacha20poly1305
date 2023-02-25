/// @file
/// @brief  poly1305.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

#include "./intrinsics.h"

namespace poly1305
{
    using byte = uint8_t;
    using key_r = std::array<byte, 16>;
    using key_s = std::array<byte, 16>;
    using mac = std::array<byte, 16>;

    static mac calculate_poly1305_x86(
        const key_r* r_,
        const key_s* s_,
        const byte* message,
        size_t length)
    {
        using namespace arkintr;
        std::array<uint32_t, 5> a{};

        std::array<uint32_t, 4> r = load_u<std::array<uint32_t, 4>>(r_);
        std::array<uint32_t, 4> s = load_u<std::array<uint32_t, 4>>(s_);
        r[0] &= 0x0FFFFFFFu;
        r[1] &= 0x0FFFFFFCu;
        r[2] &= 0x0FFFFFFCu;
        r[3] &= 0x0FFFFFFCu;

        while (length)
        {
            std::array<uint32_t, 5> in{};
            if (length >= 16)
            {
                in[0] = load_u<uint32_t>(message + 0);
                in[1] = load_u<uint32_t>(message + 4);
                in[2] = load_u<uint32_t>(message + 8);
                in[3] = load_u<uint32_t>(message + 12);
                in[4] = 1;
                message += 16;
                length -= 16;
            }
            else
            {
                std::array<byte, 16> t{};
                std::memcpy(t.data(), message, length);
                t[length] = 1;

                in[0] = load_u<uint32_t>(t.data() + 0);
                in[1] = load_u<uint32_t>(t.data() + 4);
                in[2] = load_u<uint32_t>(t.data() + 8);
                in[3] = load_u<uint32_t>(t.data() + 12);
                in[4] = 0;
                message += length;
                length -= length;
            }

            {
                carry_flag_t cf = 0;
                cf = adc(cf, a[0], in[0]);
                cf = adc(cf, a[1], in[1]);
                cf = adc(cf, a[2], in[2]);
                cf = adc(cf, a[3], in[3]);
                cf = adc(cf, a[4], in[4]);
                (void)cf;
            }

            std::array<uint64_t, 8> d{};
            d[0] += muld(a[0], r[0]);
            d[1] += muld(a[0], r[1]);
            d[2] += muld(a[0], r[2]);
            d[3] += muld(a[0], r[3]);
            d[1] += muld(a[1], r[0]);
            d[2] += muld(a[1], r[1]);
            d[3] += muld(a[1], r[2]);
            d[4] += muld(a[1], r[3]);
            d[2] += muld(a[2], r[0]);
            d[3] += muld(a[2], r[1]);
            d[4] += muld(a[2], r[2]);
            d[5] += muld(a[2], r[3]);
            d[3] += muld(a[3], r[0]);
            d[4] += muld(a[3], r[1]);
            d[5] += muld(a[3], r[2]);
            d[6] += muld(a[3], r[3]);
            d[4] += muld(a[4], r[0]);
            d[5] += muld(a[4], r[1]);
            d[6] += muld(a[4], r[2]);
            d[7] += muld(a[4], r[3]);

            std::array<uint32_t, 8> e{};
            e[0] = static_cast<uint32_t>(d[0]);
            e[1] = static_cast<uint32_t>(d[1] += (d[0] >> 32));
            e[2] = static_cast<uint32_t>(d[2] += (d[1] >> 32));
            e[3] = static_cast<uint32_t>(d[3] += (d[2] >> 32));
            e[4] = static_cast<uint32_t>(d[4] += (d[3] >> 32));
            e[5] = static_cast<uint32_t>(d[5] += (d[4] >> 32));
            e[6] = static_cast<uint32_t>(d[6] += (d[5] >> 32));
            e[7] = static_cast<uint32_t>(d[7] += (d[6] >> 32));

            a[0] = e[0];
            a[1] = e[1];
            a[2] = e[2];
            a[3] = e[3];
            a[4] = e[4] & 3;

            {
                carry_flag_t cf = 0;
                cf = adc(cf, a[0], e[4] >> 2 | e[5] << 30);
                cf = adc(cf, a[1], e[5] >> 2 | e[6] << 30);
                cf = adc(cf, a[2], e[6] >> 2 | e[7] << 30);
                cf = adc(cf, a[3], e[7] >> 2);
                cf = adc(cf, a[4], 0u);
            }

            {
                carry_flag_t cf = 0;
                cf = adc(cf, a[0], e[4] & ~3);
                cf = adc(cf, a[1], e[5]);
                cf = adc(cf, a[2], e[6]);
                cf = adc(cf, a[3], e[7]);
                cf = adc(cf, a[4], 0u);
            }
        }

        while (a[4] >= 4)
        {
            auto t = a[4];
            a[4] &= 3;
            {
                carry_flag_t cf = 0;
                cf = adc(cf, a[0], t >> 2);
                cf = adc(cf, a[1], 0u);
                cf = adc(cf, a[2], 0u);
                cf = adc(cf, a[3], 0u);
                cf = adc(cf, a[4], 0u);
            }

            {
                carry_flag_t cf = 0;
                cf = adc(cf, a[0], t & ~3);
                cf = adc(cf, a[1], 0u);
                cf = adc(cf, a[2], 0u);
                cf = adc(cf, a[3], 0u);
                cf = adc(cf, a[4], 0u);
            }
        }

        if (std::tie(a[4], a[3], a[2], a[1], a[0])
            >= std::make_tuple(3u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFBu))
        {
            a[4] -= 3u;
            a[3] -= 0xFFFFFFFFu;
            a[2] -= 0xFFFFFFFFu;
            a[1] -= 0xFFFFFFFFu;
            a[0] -= 0xFFFFFFFBu;
        }

        {
            carry_flag_t cf = 0;
            cf = adc(cf, a[0], s[0]);
            cf = adc(cf, a[1], s[1]);
            cf = adc(cf, a[2], s[2]);
            cf = adc(cf, a[3], s[3]);
            cf = adc(cf, a[4], 0u);
        }
        return load_u<mac>(a.data());
    }

    static mac calculate_poly1305_x64(
        const key_r* r_,
        const key_s* s_,
        const byte* message,
        size_t length)
    {
        using namespace arkintr;
        std::array<uint64_t, 3> a{};
        const auto r = load_u<uint64x2_t>(r_) & uint64x2_t{0x0FFFFFFC0FFFFFFFu, 0x0FFFFFFC0FFFFFFCu};
        const auto s = load_u<uint64x2_t>(s_);
        constexpr std::array<uint64_t, 3> prime1305 = {0xFFFFFFFFFFFFFFFBu, 0xFFFFFFFFFFFFFFFFu, 3u};

        while (length)
        {
            if (length >= 16)
            {
                auto in = load_u<uint64x2_t>(message);
                adc(adc(adc(0, a[0], in.l), a[1], in.h), a[2], 1ull);
                message += 16;
                length -= 16;
            }
            else
            {
                std::array<byte, 16> t{};
                std::memcpy(t.data(), message, length);
                t[length] = 1;

                auto in = load_u<uint64x2_t>(t.data());
                adc(adc(adc(0, a[0], in.l), a[1], in.h), a[2], 0ull);
                message += length;
                length -= length;
            }

            std::array<uint64x2_t, 4> d{};
            d[0] += muld(a[0], r.l);
            d[1] += muld(a[0], r.h);
            d[1] += muld(a[1], r.l);
            d[2] += muld(a[1], r.h);
            d[2] += muld(a[2], r.l);
            d[3] += muld(a[2], r.h);

            std::array<uint64x2_t, 2> e{};
            e[0].l = (d[0]).l;
            e[0].h = (d[1] += uint64x2_t{d[0].h}).l;
            e[1].l = (d[2] += uint64x2_t{d[1].h}).l;
            e[1].h = (d[3] += uint64x2_t{d[2].h}).l;

            a[0] = e[0].l;
            a[1] = e[0].h;
            a[2] = e[1].l & 3;
            adc(adc(adc(0, a[0], shrd(e[1].l, e[1].h, 2)), a[1], e[1].h >> 2), a[2], 0ull);
            adc(adc(adc(0, a[0], e[1].l & ~3ull), a[1], e[1].h), a[2], 0ull);
        }

        while (a[2] >= 4)
        {
            auto t = std::exchange(a[2], a[2] & 3);
            adc(adc(adc(0, a[0], t >> 2), a[1], 0ull), a[2], 0ull);
            adc(adc(adc(0, a[0], t & ~3ull), a[1], 0ull), a[2], 0ull);
        }

        if (std::tie(a[2], a[1], a[0]) >= std::tie(prime1305[2], prime1305[1], prime1305[0]))
        {
            sbb(sbb(sbb(0, a[0], prime1305[0]), a[1], prime1305[1]), a[2], prime1305[2]);
        }

        adc(adc(adc(0, a[0], s.l), a[1], s.h), a[2], 0ull);
        return load_u<mac>(a.data());
    }

    static inline mac calculate_poly1305(
        const key_r* r_,
        const key_s* s_,
        const byte* message,
        size_t length)
    {
        if constexpr (sizeof(void*) == 8)
            return calculate_poly1305_x64(r_, s_, message, length);
        else
            return calculate_poly1305_x86(r_, s_, message, length);
    }
}
