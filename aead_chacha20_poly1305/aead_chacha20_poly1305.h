/// @file
/// @brief  aead_chacha20_poly1305.h
/// @author (c) 2023 ttsuki

#pragma once

#include <cstddef>
#include <cstdint>

#include "../chacha20/chacha20.h"
#include "../poly1305/poly1305.h"

namespace aead_chacha20_poly1305
{
    struct aead_chacha20_poly1305_context
    {
        chacha20::context_t chacha20_context;
        poly1305::poly1305_tag_context poly1305_tag_context;

        struct length_data_t
        {
            uint64_t aad_length;
            uint64_t data_length;
        } message_length;
    };

    static inline aead_chacha20_poly1305_context prepare_aead_chacha20_poly1305_context(const void* aad_data, size_t aad_length, const chacha20::key* key, const chacha20::nonce* nonce)
    {
        std::array<std::byte, 16> empty{};
        aead_chacha20_poly1305_context context{};
        struct
        {
            poly1305::key_r r;
            poly1305::key_s s;
        } poly1305_key_pair{};

        context.chacha20_context = chacha20::prepare_context(key, nonce);
        process_stream(context.chacha20_context, &poly1305_key_pair, &poly1305_key_pair, 0, sizeof(poly1305_key_pair));
        context.poly1305_tag_context = poly1305::prepare_poly1305_tag_context(&poly1305_key_pair.r, &poly1305_key_pair.s);

        process_bytes(context.poly1305_tag_context, aad_data, aad_length);
        process_bytes(context.poly1305_tag_context, empty.data(), /* pad length */ (-static_cast<int>(aad_length) & 15));
        context.message_length.aad_length = aad_length;

        return context;
    }

    static inline aead_chacha20_poly1305_context& encrypt_bytes(aead_chacha20_poly1305_context& context, const void* input, void* output, size_t length)
    {
        process_stream(context.chacha20_context, input, output, context.message_length.data_length + 64 /* counter = 1 */, length);
        process_bytes(context.poly1305_tag_context, output, length);
        context.message_length.data_length += length;
        return context;
    }

    static inline aead_chacha20_poly1305_context& decrypt_bytes(aead_chacha20_poly1305_context& context, const void* input, void* output, size_t length)
    {
        process_bytes(context.poly1305_tag_context, input, length);
        process_stream(context.chacha20_context, input, output, context.message_length.data_length + 64 /* counter = 1 */, length);
        context.message_length.data_length += length;
        return context;
    }

    static inline poly1305::mac finalize_and_calculate_tag(aead_chacha20_poly1305_context& context)
    {
        std::array<std::byte, 16> empty{};
        process_bytes(context.poly1305_tag_context, empty.data(), /* pad length */ (-static_cast<int>(context.message_length.data_length) & 15));
        process_bytes(context.poly1305_tag_context, &context.message_length, sizeof(context.message_length));
        poly1305::mac result = finalize_and_get_mac(context.poly1305_tag_context);
        arkana::intrinsics::secure_be_zero(context);
        return result;
    }
}
