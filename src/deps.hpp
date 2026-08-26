#pragma once
#include <string_view>
#include <optional>
#include <span>

template <class T>
using span_t = std::span<T>;

template <class T>
using optional_t = std::optional<T>;

using string_view_t = std::string_view;
