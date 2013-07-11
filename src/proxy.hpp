#ifndef PROXY_HPP_MODULE
#define PROXY_HPP_MODULE

#include <fastcgi2/component_factory.h>
#include <fastcgi2/handler.h>
#include <fastcgi2/request.h>
#include <fastcgi2/logger.h>

#include <boost/tokenizer.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>

#include <elliptics/proxy.hpp>

#include <map>
#include <set>

#include "component_base.hpp"
#include "embed_processor.hpp"

class proxy_t
		: /*virtual */public fastcgi::Component
		, /*virtual */public fastcgi::Handler {
public:
	proxy_t(fastcgi::ComponentContext *context);
	virtual ~proxy_t();

	virtual void onLoad();
	virtual void onUnload();
	virtual void handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context);

protected:
	typedef void (proxy_t::*request_handler)(fastcgi::Request *request);
	typedef boost::char_separator<char> separator_t;
	typedef boost::tokenizer<separator_t> tokenizer_t;

	static size_t params_num(tokenizer_t &tok);
	static std::string get_filename(fastcgi::Request *request);
	static elliptics::key_t get_key(fastcgi::Request *request);

	template <typename T>
	T get_arg(fastcgi::Request *request, const std::string &name, const T &default_value = T()) {
		assert(request != 0);
		try {
			return request->hasArg(name) ? boost::lexical_cast<T>(request->getArg(name)) : default_value;
		} catch (...) {
			log()->error(std::string("Incorrect").append(name).c_str());
			request->setStatus(503);
			throw;
		}
	}

	template <typename T>
	std::vector<T> get_results(fastcgi::Request *request, ioremap::elliptics::async_result<T> &ar) {
		assert(request != 0);
		try {
			return ar.get();
		} catch (...) {
			log()->error("Cannot get the result");
			request->setStatus(503);
			throw;
		}
	}

	const fastcgi::Logger *log() const;
	fastcgi::Logger *log();

	ioremap::elliptics::node &elliptics_node();
	ioremap::elliptics::session get_session(fastcgi::Request *request = 0);
	std::vector<int> get_groups(fastcgi::Request *request, size_t count = 0);
	bool upload_is_good(size_t success_copies_num, size_t replication_count, size_t size);
	size_t uploads_need(size_t success_copies_num);
	elliptics::lookup_result_t parse_lookup(const ioremap::elliptics::lookup_result_entry &entry);

	virtual void register_handlers();
	void register_handler(const char *name, request_handler handler, bool override = false);

private:
	typedef std::map<std::string, request_handler> request_handlers;

	struct data;
	std::unique_ptr<data> m_data;

	void allow_origin(fastcgi::Request *request) const;

	void upload_handler(fastcgi::Request *request);
	void get_handler(fastcgi::Request *request);
	void delete_handler(fastcgi::Request *request);
	void download_info_handler(fastcgi::Request *request);

	void ping_handler(fastcgi::Request *request);
	void stat_log_handler(fastcgi::Request *request);

	void bulk_upload_handler(fastcgi::Request *request);
	void bulk_get_handler(fastcgi::Request *request);
	void exec_script_handler(fastcgi::Request *request);

	ioremap::elliptics::async_write_result write(ioremap::elliptics::session &session
												 , const ioremap::elliptics::key &key
												 , const ioremap::elliptics::data_pointer &data
												 , const uint64_t &offset, fastcgi::Request *request
												 );
};

#endif /* PROXY_HPP_MODULE */
