/// @file
/// @brief	arkana::ark::ctr_cipher_stream_helper
/// @author Copyright(c) 2023 ttsuki
/// 
/// This software is released under the MIT License.
/// https://opensource.org/licenses/MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <type_traits>

namespace arkana::ctr_cipher_stream_helper
{
    template <class block_t, class counter_t = uint32_t, class stream_position_t = uint64_t, class context_t, class process_blocks_function>
    static inline void process_stream_with_ctr(
        // process_blocks(context_t& ctx, const block_t* input, block_t* output, counter_t counter, size_t count)
        process_blocks_function&& process_blocks,
        context_t& ctx,
        const std::byte* input,
        std::byte* output,
        stream_position_t position,
        size_t length)
    {
        constexpr size_t block_size = sizeof(block_t);
        static_assert(std::is_trivial_v<block_t>);

        // calculates first block index.
        counter_t block_index = static_cast<counter_t>(position / block_size);

        if (size_t offset = static_cast<size_t>(position % block_size))
        {
            size_t len = std::min<size_t>(length, block_size - offset);

            // processes partial block.
            block_t b{};
            std::memcpy(reinterpret_cast<std::byte*>(&b) + offset, input, len);
            process_blocks(ctx, &b, &b, block_index++, 1);
            std::memcpy(output, reinterpret_cast<std::byte*>(&b) + offset, len);

            // advances pointers.
            position += static_cast<stream_position_t>(len);
            input += len;
            output += len;
            length -= len;
        }

        if (size_t block_count = length / block_size)
        {
            // processes blocks.
            process_blocks(ctx, reinterpret_cast<const block_t*>(input), reinterpret_cast<block_t*>(output), block_index, block_count);

            // advances pointers.
            block_index += static_cast<counter_t>(block_count);
            position += static_cast<stream_position_t>(block_count * block_size);
            input += block_count * block_size;
            output += block_count * block_size;
            length -= block_count * block_size;
        }

        if (size_t len = length)
        {
            // processes partial block.
            block_t b{};
            std::memcpy(reinterpret_cast<std::byte*>(&b), input, len);
            process_blocks(ctx, &b, &b, block_index++, 1);
            std::memcpy(output, reinterpret_cast<std::byte*>(&b), len);

            // advances pointers.
            position += static_cast<stream_position_t>(len);
            input += len;
            output += len;
            length -= len;
        }
    }
}
