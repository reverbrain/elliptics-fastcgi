#ifndef _FASTCGI_MAGIC_PROVIDER_HPP_INCLUDED_
#define _FASTCGI_MAGIC_PROVIDER_HPP_INCLUDED_

#include <boost/noncopyable.hpp>

#include <magic.h>

namespace elliptics {

class magic_provider_t : private boost::noncopyable {

public:
	magic_provider_t() {
		magic_ = magic_open(MAGIC_MIME_TYPE);
		magic_load(magic_, 0);
	}

	~magic_provider_t() {
		magic_close(magic_);
	}

public:
	std::string type(const std::string &content) {
		const char *result(magic_buffer(magic_, content.data(), content.size()));

		if (result) {
			return result;
		}

		return "application/octet-stream";
	}

private:
	magic_t magic_;

};

} // namespace elliptics

#endif // _FASTCGI_MAGIC_PROVIDER_HPP_INCLUDED_
