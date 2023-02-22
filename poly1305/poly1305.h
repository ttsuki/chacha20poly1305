/// @file
/// @brief  poly1305.h
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

namespace poly1305
{
    using byte = uint8_t;
    using key_r = std::array<byte, 16>;
    using key_s = std::array<byte, 16>;
    using mac = std::array<byte, 16>;

    namespace intrinsics
    {
        /// Loads T from unaligned memory pointer
        template <class T, std::enable_if_t<std::is_trivially_copyable_v<T>>* = nullptr>
        static inline constexpr T load_u(const void* src) noexcept
        {
            T t;
            std::memcpy(&t, src, sizeof(T));
            return t;
        }

        static inline uint8_t adc32(uint8_t cf, uint32_t& a, uint32_t b) noexcept
        {
            return _addcarry_u32(cf, a, b, &a);
        }

        static inline uint8_t sbb32(uint8_t cf, uint32_t& a, uint32_t b) noexcept
        {
            return _subborrow_u32(cf, a, b, &a);
        }

        static inline uint64_t mul32(uint32_t a, uint32_t b) noexcept
        {
#if defined(_MSC_VER)
            // 32bit MSVC
            return __emulu(a, b);
#else
            return static_cast<uint64_t>(a) * b;
#endif
        }
    }

    static mac calculate_poly1305(
        const key_r* r_,
        const key_s* s_,
        const byte* message,
        size_t length)
    {
        using namespace intrinsics;
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
                uint8_t cf = 0;
                cf = adc32(cf, a[0], in[0]);
                cf = adc32(cf, a[1], in[1]);
                cf = adc32(cf, a[2], in[2]);
                cf = adc32(cf, a[3], in[3]);
                cf = adc32(cf, a[4], in[4]);
                (void)cf;
            }

            std::array<uint64_t, 8> d{};
            d[0] += mul32(a[0], r[0]);
            d[1] += mul32(a[0], r[1]);
            d[2] += mul32(a[0], r[2]);
            d[3] += mul32(a[0], r[3]);
            d[1] += mul32(a[1], r[0]);
            d[2] += mul32(a[1], r[1]);
            d[3] += mul32(a[1], r[2]);
            d[4] += mul32(a[1], r[3]);
            d[2] += mul32(a[2], r[0]);
            d[3] += mul32(a[2], r[1]);
            d[4] += mul32(a[2], r[2]);
            d[5] += mul32(a[2], r[3]);
            d[3] += mul32(a[3], r[0]);
            d[4] += mul32(a[3], r[1]);
            d[5] += mul32(a[3], r[2]);
            d[6] += mul32(a[3], r[3]);
            d[4] += mul32(a[4], r[0]);
            d[5] += mul32(a[4], r[1]);
            d[6] += mul32(a[4], r[2]);
            d[7] += mul32(a[4], r[3]);

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
                uint8_t cf = 0;
                cf = adc32(cf, a[0], e[4] >> 2 | e[5] << 30);
                cf = adc32(cf, a[1], e[5] >> 2 | e[6] << 30);
                cf = adc32(cf, a[2], e[6] >> 2 | e[7] << 30);
                cf = adc32(cf, a[3], e[7] >> 2);
                a[4] += cf;
            }

            {
                uint8_t cf = 0;
                cf = adc32(cf, a[0], e[4] & ~3);
                cf = adc32(cf, a[1], e[5]);
                cf = adc32(cf, a[2], e[6]);
                cf = adc32(cf, a[3], e[7]);
                a[4] += cf;
            }
        }

        while (a[4] >= 4)
        {
            auto t = a[4];
            a[4] &= 3;
            {
                uint8_t cf = 0;
                cf = adc32(cf, a[0], t >> 2);
                cf = adc32(cf, a[1], 0);
                cf = adc32(cf, a[2], 0);
                cf = adc32(cf, a[3], 0);
                a[4] += cf;
            }

            {
                uint8_t cf = 0;
                cf = adc32(cf, a[0], t & ~3);
                cf = adc32(cf, a[1], 0);
                cf = adc32(cf, a[2], 0);
                cf = adc32(cf, a[3], 0);
                a[4] += cf;
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
            uint8_t cf = 0;
            cf = adc32(cf, a[0], s[0]);
            cf = adc32(cf, a[1], s[1]);
            cf = adc32(cf, a[2], s[2]);
            cf = adc32(cf, a[3], s[3]);
            a[4] += cf;
        }
        return intrinsics::load_u<mac>(a.data());
    }
}
