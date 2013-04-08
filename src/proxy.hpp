#ifndef PROXY_HPP_MODULE
#define PROXY_HPP_MODULE

#include <fastcgi2/component_factory.h>
#include <fastcgi2/handler.h>
#include <fastcgi2/request.h>
#include <fastcgi2/logger.h>

#include <boost/tokenizer.hpp>
#include <boost/shared_ptr.hpp>

#include <elliptics/proxy.hpp>

#include <map>
#include <set>

#include "component_base.hpp"
#include "embed_processor.hpp"

class proxy_t :
	virtual public component_base_t
	, virtual public fastcgi::Handler
{
private:
	typedef void (proxy_t::*RequestHandler)(fastcgi::Request *request);
	//using RequestHandler = void (Proxy::*) (fastcgi::Request *request);
	typedef std::map<std::string, RequestHandler> RequestHandlers;

public:
	typedef boost::char_separator<char> separator_t;
	typedef boost::tokenizer<separator_t> tokenizer_t;

	struct signature_t {
		std::string path;
		std::string key;
	};

	proxy_t(fastcgi::ComponentContext *context);
	virtual ~proxy_t();

	virtual void onLoad();
	virtual void onUnload();
	virtual void handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context);

private:
	void register_handler(const char *name, RequestHandler handler);

	void upload_handler(fastcgi::Request *request);
	void get_handler(fastcgi::Request *request);
	void delete_handler(fastcgi::Request *request);
	void download_info_handler(fastcgi::Request *request);
	void bulk_upload_handler(fastcgi::Request *request);
	void bulk_get_handler(fastcgi::Request *request);
	void ping_handler(fastcgi::Request *request);
	void stat_log_handler(fastcgi::Request *request);
	void exec_script_handler(fastcgi::Request *request);

	void allow_origin(fastcgi::Request *request) const;

	boost::shared_ptr<elliptics::elliptics_proxy_t> m_elliptics_proxy;

	RequestHandlers m_handlers;

	int m_write_port;

	std::set<std::string> m_deny_list;
	std::set<std::string> m_allow_list;
	std::map<std::string, std::string> m_typemap;
	std::map<uint32_t, embed_processor_module_base_t *> m_embed_processors;
	std::set<std::string> m_allow_origin_domains;
	std::set<std::string> m_allow_origin_handlers;
};

#endif /* PROXY_HPP_MODULE */
