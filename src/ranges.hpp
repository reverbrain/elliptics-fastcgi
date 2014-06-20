#ifndef SRC__RANGES_HPP
#define SRC__RANGES_HPP

#include <boost/optional.hpp>

#include <string>
#include <vector>

namespace elliptics {

struct range_t {
	size_t offset;
	size_t size;
};

typedef std::vector<range_t> ranges_t;

boost::optional<ranges_t> parse_range_header(const std::string &header, size_t total_size);

} // namespace elliptics

#endif /* SRC__RANGES_HPP */
