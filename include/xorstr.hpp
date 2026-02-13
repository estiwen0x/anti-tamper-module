#pragma once

#include <string>
#include <utility>

/**
 * @file SecureStorage.hpp
 * @brief compile-time string obfuscation utility for research projects.
 */

namespace SecurityUtils
{

    template<typename T>
    constexpr T ParseChar(T c) {
        return (c >= '0' && c <= '9') ? (c - '0') : 0;
    }
}

#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE __attribute__((always_inline))
#endif

template<typename StringType, size_t Length>
class EncryptedString
{
    using CharType = typename StringType::value_type;
    static constexpr auto RealLength = Length - 1;

public:
    constexpr FORCE_INLINE EncryptedString(CharType const (&raw_str)[Length])
        : EncryptedString(raw_str, std::make_index_sequence<RealLength>()) {}

    inline const CharType* get_raw() const {
        perform_conversion();
        return buffer;
    }

    inline StringType to_std_string() const {
        perform_conversion();
        return StringType(buffer, buffer + RealLength);
    }

    inline operator StringType() const { return to_std_string(); }

private:
    template<size_t... Is>
    constexpr FORCE_INLINE EncryptedString(CharType const (&str)[Length], std::index_sequence<Is...>)
        : buffer{ transform(str[Is], Is)..., '\0' }, 
          is_dirty(true) {}


    static constexpr CharType SEED_KEY = static_cast<CharType>(
        (SecurityUtils::ParseChar(__TIME__[7]) * 0x1337) ^
        (SecurityUtils::ParseChar(__TIME__[6]) * 0x10) +
        (SecurityUtils::ParseChar(__TIME__[4]) * 0x5) ^
        (SecurityUtils::ParseChar(__TIME__[3]) * 0x20)
    );


    static FORCE_INLINE constexpr CharType transform(CharType c, size_t i) {
        return static_cast<CharType>(c ^ (SEED_KEY + (i * 0x7F)));
    }

    inline void perform_conversion() const {
        if (is_dirty) {
            for (size_t i = 0; i < RealLength; i++) {
                buffer[i] = transform(buffer[i], i);
            }
            is_dirty = false;
        }
    }

    mutable CharType buffer[Length];
    mutable bool is_dirty;
};


template<size_t L> using ObfuscatedA = EncryptedString<std::string, L>;
template<size_t L> using ObfuscatedW = EncryptedString<std::wstring, L>;


template<size_t L>
constexpr FORCE_INLINE auto ProtectedStr(char const (&s)[L]) { return ObfuscatedA<L>(s); }

template<size_t L>
constexpr FORCE_INLINE auto ProtectedStr(wchar_t const (&s)[L]) { return ObfuscatedW<L>(s); }
