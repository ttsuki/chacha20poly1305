/// @file
/// @brief  poly1305.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>

namespace poly1305
{
    using byte = uint8_t;
    using key_r = std::array<byte, 16>;
    using key_s = std::array<byte, 16>;
    using mac = std::array<byte, 16>;

    static mac calculate_poly1305(
        const key_r* r,
        const key_s* s,
        const byte* message,
        const size_t length)
    {
        return mac{};
    }
}
