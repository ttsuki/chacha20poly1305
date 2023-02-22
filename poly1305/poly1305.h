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

    static mac calculate_poly1305_x86(
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

    namespace intrinsics
    {
        static inline constexpr std::array<uint32_t, 2> decompose64(uint64_t v) noexcept
        {
            return std::array<uint32_t, 2>{static_cast<uint32_t>(v), static_cast<uint32_t>(v >> 32)};
        }

        static inline uint8_t adc64(uint8_t cf, uint64_t& a, uint64_t b) noexcept
        {
#if (defined(_MSC_VER) && _MSC_VER >= 1920 && defined(_M_X64)) || defined(__x86_64__)
            // 64bit MSVC(2019 or later: VS2017 has bug?), GCC, clang
            static_assert(sizeof(uint64_t) == sizeof(unsigned long long));
            return _addcarry_u64(cf, a, b, reinterpret_cast<unsigned long long*>(&a));
#else
            uint32_t l32 = static_cast<uint32_t>(a), h32 = static_cast<uint32_t>(a >> 32);
            cf = adc32(cf, l32, static_cast<uint32_t>(b));
            cf = adc32(cf, h32, static_cast<uint32_t>(b >> 32));
            a = static_cast<uint64_t>(h32) << 32 | l32;
            return cf;
#endif
        }

        static inline uint8_t sbb64(uint8_t cf, uint64_t& a, uint64_t b) noexcept
        {
#if (defined(_MSC_VER) && _MSC_VER >= 1920 && defined(_M_X64)) || defined(__x86_64__)
            // 64bit MSVC(2019 or later: VS2017 has bug?), GCC, clang
            static_assert(sizeof(uint64_t) == sizeof(unsigned long long));
            return _subborrow_u64(cf, a, b, reinterpret_cast<unsigned long long*>(&a));
#else
            uint32_t l32 = static_cast<uint32_t>(a), h32 = static_cast<uint32_t>(a >> 32);
            cf = sbb32(cf, l32, static_cast<uint32_t>(b));
            cf = sbb32(cf, h32, static_cast<uint32_t>(b >> 32));
            a = static_cast<uint64_t>(h32) << 32 | l32;
            return cf;
#endif
        }

        static inline uint64_t muld64(uint64_t a, uint64_t b, uint64_t* h) noexcept
        {
#if defined(_MSC_VER) && defined(_M_X64)
            // 64bit MSVC
            return _umul128(a, b, h);
#elif defined(__SIZEOF_INT128__)
            auto ab = static_cast<unsigned __int128>(a) * b;
            *h = static_cast<uint64_t>(ab >> 64);
            return static_cast<uint64_t>(ab);
#else
            auto [al, ah] = decompose64(a);
            auto [bl, bh] = decompose64(b);

            auto [ll, lh] = decompose64(mul32(al, bl)); // ___a * ___b = __ll
            auto [xl, xh] = decompose64(mul32(ah, bl)); // __a_ * ___b = _xx_
            auto [yl, yh] = decompose64(mul32(al, bh)); // ___a * __b_ = _yy_
            auto [hl, hh] = decompose64(mul32(ah, bh)); // __a_ * __b_ = hh__

            hh += adc32(adc32(0, lh, xl), hl, xh);
            hh += adc32(adc32(0, lh, yl), hl, yh);

            *h = static_cast<uint64_t>(hh) << 32 | hl;
            return static_cast<uint64_t>(lh) << 32 | ll;
#endif
        }

        static inline uint64_t shld64(uint64_t l, uint64_t h, int i) noexcept
        {
#if defined(_MSC_VER) && defined(_M_X64)
            // 64bit MSVC
            return __shiftleft128(l, h, static_cast<unsigned char>(i));
#else
            return (i & 63) ? h << (i & 63) | l >> (-i & 63) : h;
#endif
        }

        static inline uint64_t shrd64(uint64_t l, uint64_t h, int i) noexcept
        {
#if defined(_MSC_VER) && defined(_M_X64)
            // 64bit MSVC
            return __shiftright128(l, h, static_cast<unsigned char>(i));
#else
            return (i & 63) ? l >> (i & 63) | h << (-i & 63) : l;
#endif
        }

        struct uint128_t
        {
            uint64_t l{}, h{};
            inline constexpr uint128_t() = default;
            inline constexpr uint128_t(uint64_t l, uint64_t h = {}) : l{l}, h{h} { }
            inline constexpr explicit operator bool() const noexcept { return l | h; }
            inline constexpr explicit operator uint64_t() const noexcept { return l; }
        };

        static inline bool operator ==(uint128_t a, uint128_t b) noexcept { return !((a.h ^ b.h) | (a.l ^ b.l)); }
        static inline bool operator !=(uint128_t a, uint128_t b) noexcept { return !(a == b); }
        static inline bool operator <(uint128_t a, uint128_t b) noexcept { return intrinsics::sbb64(a.l < b.l, a.h, b.h); }
        static inline bool operator >(uint128_t a, uint128_t b) noexcept { return b < a; }
        static inline bool operator <=(uint128_t a, uint128_t b) noexcept { return !(a > b); }
        static inline bool operator >=(uint128_t a, uint128_t b) noexcept { return !(a < b); }

        static inline uint128_t operator +(uint128_t a, uint128_t b) noexcept
        {
            a.h += b.h + adc64(0, a.l, b.l);
            return a;
        }

        static inline uint128_t operator -(uint128_t a, uint128_t b) noexcept
        {
            a.h -= b.h + sbb64(0, a.l, b.l);
            return a;
        }

        static inline uint128_t operator *(uint128_t a, uint128_t b) noexcept
        {
            uint64_t h;
            uint64_t l = muld64(a.l, b.l, &h);
            h += a.l * b.h + a.h * b.l;
            return {l, h};
        }

        static inline uint128_t operator ~(uint128_t a) noexcept { return {~a.l, ~a.h}; }
        static inline uint128_t operator &(uint128_t a, uint128_t b) noexcept { return {a.l & b.l, a.h & b.h}; }
        static inline uint128_t operator |(uint128_t a, uint128_t b) noexcept { return {a.l | b.l, a.h | b.h}; }
        static inline uint128_t operator ^(uint128_t a, uint128_t b) noexcept { return {a.l ^ b.l, a.h ^ b.h}; }

        static inline uint128_t operator <<(uint128_t a, int i) noexcept
        {
            uint64_t l = a.l << (i & 63);
            uint64_t h = shld64(a.l, a.h, static_cast<unsigned char>(i));
            return i & 64 ? uint128_t{0, l} : uint128_t{l, h};
        }

        static inline uint128_t operator >>(uint128_t a, int i) noexcept
        {
            uint64_t l = shrd64(a.l, a.h, static_cast<unsigned char>(i));
            uint64_t h = a.h >> (i & 63);
            return i & 64 ? uint128_t{h, 0} : uint128_t{l, h};
        }

        static inline uint128_t& operator +=(uint128_t& a, uint128_t b) noexcept { return a = a + b; }
        static inline uint128_t& operator -=(uint128_t& a, uint128_t b) noexcept { return a = a - b; }
        static inline uint128_t& operator *=(uint128_t& a, uint128_t b) noexcept { return a = a * b; }
        static inline uint128_t& operator &=(uint128_t& a, uint128_t b) noexcept { return a = a & b; }
        static inline uint128_t& operator |=(uint128_t& a, uint128_t b) noexcept { return a = a | b; }
        static inline uint128_t& operator ^=(uint128_t& a, uint128_t b) noexcept { return a = a ^ b; }
        static inline uint128_t& operator <<=(uint128_t& a, int b) noexcept { return a = a << b; }
        static inline uint128_t& operator >>=(uint128_t& a, int b) noexcept { return a = a << b; }

        static inline uint128_t mul64(uint64_t a, uint64_t b) noexcept
        {
            uint128_t ret{};
            ret.l = muld64(a, b, &ret.h);
            return ret;
        }
    }

    static mac calculate_poly1305_x64(
        const key_r* r_,
        const key_s* s_,
        const byte* message,
        size_t length)
    {
        using namespace intrinsics;
        std::array<uint64_t, 3> a{};
        constexpr auto adc130 = [](std::array<uint64_t, 3>& a, uint128_t b, uint64_t pad = 0)
        {
            uint8_t cf = 0;
            cf = adc64(cf, a[0], b.l);
            cf = adc64(cf, a[1], b.h);
            return adc64(cf, a[2], pad);
        };

        const uint128_t r = load_u<uint128_t>(r_) & uint128_t{0x0FFFFFFC0FFFFFFFu, 0x0FFFFFFC0FFFFFFCu};

        while (length)
        {
            if (length >= 16)
            {
                adc130(a, load_u<uint128_t>(message), 1);
                message += 16;
                length -= 16;
            }
            else
            {
                std::array<byte, 16> t{};
                std::memcpy(t.data(), message, length);
                t[length] = 1;

                adc130(a, load_u<uint128_t>(t.data()), 0);
                message += length;
                length -= length;
            }

            std::array<uint128_t, 4> d{};
            d[0] += mul64(a[0], r.l);
            d[1] += mul64(a[0], r.h);
            d[1] += mul64(a[1], r.l);
            d[2] += mul64(a[1], r.h);
            d[2] += mul64(a[2], r.l);
            d[3] += mul64(a[2], r.h);

            std::array<uint128_t, 2> e{};
            e[0].l = (d[0]).l;
            e[0].h = (d[1] += uint128_t{d[0].h}).l;
            e[1].l = (d[2] += uint128_t{d[1].h}).l;
            e[1].h = (d[3] += uint128_t{d[2].h}).l;

            a[0] = e[0].l;
            a[1] = e[0].h;
            a[2] = e[1].l & 3;
            adc130(a, e[1] >> 2);
            adc130(a, e[1] & ~uint128_t{3});
        }

        while (a[2] >= 4)
        {
            auto t = std::exchange(a[2], a[2] & 3);
            adc130(a, t >> 2);
            adc130(a, t & ~3);
        }

        if (constexpr std::array<uint64_t, 3> prime1305 = {0xFFFFFFFFFFFFFFFBu, 0xFFFFFFFFFFFFFFFFu, 3u};
            std::tie(a[2], a[1], a[0]) >= std::tie(prime1305[2], prime1305[1], prime1305[0]))
        {
            uint8_t bf = 0;
            bf = sbb64(bf, a[0], prime1305[0]);
            bf = sbb64(bf, a[1], prime1305[1]);
            (void)sbb64(bf, a[2], prime1305[2]);
        }

        adc130(a, load_u<uint128_t>(s_));
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
