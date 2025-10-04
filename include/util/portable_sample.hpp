#pragma once

#include <algorithm>
#include <vector>
#include <boost/random/uniform_int_distribution.hpp>

namespace ligero::vm {

template<
    class PopulationIterator,
    class SampleIterator,
    class Distance,
    class URBG
>
SampleIterator portable_sample(
    PopulationIterator first, PopulationIterator last,
    SampleIterator out, Distance n,
    URBG&& g
) {
    Distance k = std::distance(first, last);
    if (n <= 0 || k <= 0) return out;
    if (n > k) n = k;

    // Partial shuffle (Fisher-Yates)
    for (Distance i = 0; i < n; ++i) {
        boost::random::uniform_int_distribution<Distance> dist(i, k - 1);
        Distance j = dist(g);
        std::iter_swap(first + i, first + j);
        *out++ = *(first + i);
    }

    return out;
}


}  // namespace ligero::vm
