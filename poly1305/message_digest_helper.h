/// @file
/// @brief	arkana::ark::message_digest_helper
/// @author Copyright(c) 2023 ttsuki
/// 
/// This software is released under the MIT License.
/// https://opensource.org/licenses/MIT

#pragma once

#include <cstddef>
#include <array>
#include <algorithm>
#include <type_traits>

namespace arkana::message_digest_helper
{
    template <size_t input_block_size>
    struct digest_input_state_t
    {
        static constexpr inline size_t block_size = input_block_size;
        std::array<std::byte, block_size> buffer{};
        size_t total_input_byte_count{};
    };

    // Callback process_blocks with per input_bytes.
    template <class process_block_function, class digest_context, size_t input_block_size>
    static inline digest_context& process_bytes(
        digest_context& context,
        process_block_function&& process_blocks,
        digest_input_state_t<input_block_size>& input_state, const void* message, size_t length)
    {
        const std::byte* src = static_cast<const std::byte*>(message);
        const std::byte* end = src + length;

        if (size_t offset = input_state.total_input_byte_count % input_block_size)
        {
            size_t bytes = std::min<size_t>(input_block_size - offset, end - src);
            memcpy(input_state.buffer.data() + offset, src, bytes);
            src += bytes;
            input_state.total_input_byte_count += bytes;

            if (input_state.total_input_byte_count % input_block_size == 0)
                process_blocks(context, input_state.buffer.data(), input_block_size);
        }

        if (size_t bytes = (end - src) / input_block_size * input_block_size)
        {
            process_blocks(context, src, bytes);
            src += bytes;
            input_state.total_input_byte_count += bytes;
        }

        if (size_t bytes = (end - src))
        {
            memcpy(input_state.buffer.data(), src, bytes);
            src += bytes;
            input_state.total_input_byte_count += bytes;
        }

        return context;
    }

    // Finalize context
    template <class process_block_function, class get_digest_function, class digest_context, size_t input_block_size>
    static inline std::invoke_result_t<get_digest_function, digest_context&> finalize(
        digest_context& context,
        process_block_function&& process_final_block,
        get_digest_function&& get_digest,
        digest_input_state_t<input_block_size>& input_state)
    {
        process_final_block(context, input_state.buffer.data(), input_state.total_input_byte_count % input_block_size); // may be calling with 0 bytes
        return get_digest(context);
    }
}
