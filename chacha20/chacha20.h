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

namespace chacha20
{
    using byte = uint8_t;
    using key = std::array<byte, 32>;
    using nonce = std::array<byte, 12>;
    using key_stream = std::array<byte, 64>;

    static key_stream make_key_stream(const key* key, const nonce* nonce, uint32_t counter)
    {
        return key_stream{};
    }

    static void process_stream(
        const key* key, const nonce* nonce,
        const void* input, void* output, size_t position, size_t length)
    {
        // TODO:
    }
}
