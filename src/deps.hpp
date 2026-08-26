#pragma once
#include <span>
#include <string_view>

template <class T>
using span_t = std::span<T>;

using string_view_t = std::string_view;
