#include "proxy.hpp"

#include <fastcgi2/except.h>
#include <fastcgi2/config.h>

#include <cstring>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <string>
#include <chrono>
#include <thread>
#include <condition_variable>

#include <boost/lexical_cast.hpp>
#include <boost/optional/optional.hpp>

#include <openssl/md5.h>

struct proxy_t::data {
	data()
		: m_logger(0)
	{
	}

	bool collect_group_weights();
	void collect_group_weights_loop();

	fastcgi::Logger *m_logger;

	int m_write_port;

	std::set<std::string> m_deny_list;
	std::set<std::string> m_allow_list;
	std::map<std::string, std::string> m_typemap;
	std::set<std::string> m_allow_origin_domains;
	std::set<std::string> m_allow_origin_handlers;

	request_handlers m_handlers;

	std::shared_ptr<ioremap::elliptics::file_logger>   m_elliptics_log;
	std::shared_ptr<ioremap::elliptics::node>          m_elliptics_node;
	std::vector<int>                                   m_groups;

	int                                                m_base_port;
	int                                                m_directory_bit_num;
	int                                                m_success_copies_num;
	int                                                m_die_limit;
	int                                                m_replication_count;
	int                                                m_chunk_size;
	bool                                               m_eblob_style_path;

#ifdef HAVE_METABASE
	std::unique_ptr<cocaine::dealer::dealer_t>         m_cocaine_dealer;
	cocaine::dealer::message_policy_t                  m_cocaine_default_policy;
	int                                                m_metabase_timeout;
	int                                                m_metabase_usage;
	uint64_t                                           m_metabase_current_stamp;

	int                                                m_group_weights_update_period;
	std::thread                                        m_weight_cache_update_thread;
	std::condition_variable                            m_weight_cache_condition_variable;
	std::mutex                                         m_mutex;
	bool                                               m_done;
#endif /* HAVE_METABASE */
};

proxy_t::proxy_t(fastcgi::ComponentContext *context)
	: fastcgi::Component(context)
	, m_data(new proxy_t::data)
{
}

proxy_t::~proxy_t() {
}

void proxy_t::onLoad() {
	assert(0 == m_data->m_logger);

	const fastcgi::Config *config = context()->getConfig();
	std::string path(context()->getComponentXPath());

	m_data->m_logger = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!m_data->m_logger) {
		throw std::runtime_error("can't find logger");
	}

	m_data->m_die_limit = config->asInt(path + "/dnet/die-limit");
	m_data->m_base_port = config->asInt(path + "/dnet/base-port");
	m_data->m_write_port = config->asInt(path + "/dnet/write-port", 9000);
	m_data->m_directory_bit_num = config->asInt(path + "/dnet/directory-bit-num");
	m_data->m_eblob_style_path = config->asInt(path + "/dnet/eblob_style_path", 0);

	m_data->m_chunk_size = config->asInt(path + "/dnet/chunk_size", 0);
	if (m_data->m_chunk_size < 0) m_data->m_chunk_size = 0;

	std::string log_path = config->asString(path + "/dnet/log/path");
	int log_mask = config->asInt(path + "/dnet/log/mask");

	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof (dnet_conf));

	dnet_conf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
	dnet_conf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
	dnet_conf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

	m_data->m_elliptics_log.reset(new ioremap::elliptics::file_logger(log_path.c_str(), log_mask));
	m_data->m_elliptics_node.reset(new ioremap::elliptics::node(*m_data->m_elliptics_log, dnet_conf));

	std::vector<std::string> names;

	config->subKeys(path + "/dnet/remote/addr", names);

	if (!names.size()) {
		throw std::runtime_error("Remotes can't be empty");
	}

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end();
		 end != it; ++it) {
		std::string remote = config->asString(it->c_str());
		separator_t sep(":");
		tokenizer_t tok(remote, sep);

		if (params_num(tok) != 2) {
			log()->error("invalid dnet remote %s", remote.c_str());
			continue;
		}

		std::string addr;
		int port, family;

		try {
			tokenizer_t::iterator tit = tok.begin();
			addr = *tit;
			port = boost::lexical_cast<int>(*(++tit));
			family = boost::lexical_cast<int>(*(++tit));

			m_data->m_elliptics_node->add_remote(addr.c_str(), port, family);

			log()->info("added dnet remote %s:%d:%d", addr.c_str(), port, family);
		} catch(const std::exception &e) {
			std::stringstream msg;
			msg << "Can't connect to remote node " << addr << ":" << port << ":" << family << " : " << e.what() << std::endl;
			m_data->m_elliptics_log->log(DNET_LOG_ERROR, msg.str().c_str());
		}
		catch (...) {
			log()->error("invalid dnet remote %s", remote.c_str());
		}

	}

	names.clear();
	config->subKeys(path + "/dnet/allow/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		m_data->m_allow_list.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/deny/extention", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		m_data->m_deny_list.insert(config->asString(it->c_str()));
	}


	{
		std::string groups = config->asString(path + "/dnet/groups", "");

		separator_t sep(":");
		tokenizer_t tok(groups, sep);

		for (tokenizer_t::iterator it = tok.begin(), end = tok.end(); end != it; ++it) {
			try {
				m_data->m_groups.push_back(boost::lexical_cast<int>(*it));
			}
			catch (...) {
				log()->error("invalid dnet group id %s", it->c_str());
			}
		}
	}

	m_data->m_replication_count = config->asInt(path + "/dnet/replication-count", 0);
	m_data->m_success_copies_num = config->asInt(path + "/dnet/success-copies-num", m_data->m_groups.size());
	if (m_data->m_replication_count == 0) {
		m_data->m_replication_count = m_data->m_groups.size();
	}
	if (m_data->m_success_copies_num == 0) {
		m_data->m_success_copies_num = elliptics::SUCCESS_COPIES_TYPE__QUORUM;
	}


	names.clear();
	config->subKeys(path + "/dnet/typemap/type", names);

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		std::string match = config->asString(it->c_str());

		std::string::size_type pos = match.find("->");
		std::string extention = match.substr(0, pos);
		std::string type = match.substr(pos + sizeof ("->") - 1, std::string::npos);

		m_data->m_typemap[extention] = type;
	}

	// TODO:
	//expires_ = config->asInt(path + "/dnet/expires-time", 0);

	std::string cocaine_config = config->asString(path + "/dnet/cocaine_config", "");

	// TODO:
	//std::string			ns;
	//int					group_weights_refresh_period;

	names.clear();
	config->subKeys(path + "/dnet/allow-origin/domains/domain", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		m_data->m_allow_origin_domains.insert(config->asString(it->c_str()));
	}

	names.clear();
	config->subKeys(path + "/dnet/allow-origin/handlers/handler", names);
	for (std::vector<std::string>::iterator it = names.begin(), end = names.end(); end != it; ++it) {
		m_data->m_allow_origin_handlers.insert(config->asString(it->c_str()));
	}

#ifdef HAVE_METABASE
	if (cocaine_config.size()) {
		m_data->m_cocaine_dealer.reset(new cocaine::dealer::dealer_t(cocaine_config));
	}

	m_data->m_cocaine_default_policy.deadline = dnet_conf.wait_timeout;
#endif /* HAVE_METABASE */


	register_handlers();
}

void proxy_t::onUnload() {
}

void proxy_t::handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context) {
	(void)context;
	log()->debug("Handling request: %s", request->getScriptName().c_str());
	std::cout << "handleRequest" << std::endl;

	try {
		std::string handler;
		if (request->getQueryString().length() != 0) {
			if (request->hasArg("direct")) {
				handler = "get";
			} else if (request->hasArg("unlink")) {
				handler = "delete";
			}
			else if (request->hasArg("stat") || request->hasArg("ping")) {
				handler = "stat";
			}
			else if (request->hasArg("stat_log")) {
				handler = "stat-log";
			}
			else if (request->hasArg("range")) {
				handler = "range";
			}
			else if (request->hasArg("range-delete")) {
				handler = "range-delete";
			}
			else if (request->hasArg("bulk-read")) {
				handler = "bulk-read";
			}
			else if (request->hasArg("bulk-write")) {
				handler = "bulk-write";
			}
			else if (request->hasArg("exec-script")) {
				handler = "exec-script";
			}
			else if (request->hasArg("name")) {
				handler = request->getServerPort() == m_data->m_write_port ? "upload" : "download-info";
			}
			else {
				handler = request->getScriptName().substr(1, std::string::npos);
			}
		}
		else {
			handler = request->getScriptName().substr(1, std::string::npos);
		}

		std::string::size_type pos = handler.find('/');
		handler = handler.substr(0, pos);
		auto it = m_data->m_handlers.find(handler);
		if (m_data->m_handlers.end() == it) {
			log()->debug("Handle for <%s> request not found",
						   handler.c_str());
			throw fastcgi::HttpException(404);
		}

		if (m_data->m_allow_origin_handlers.end() != m_data->m_allow_origin_handlers.find(handler)) {
			allow_origin(request);
		}

		std::cout << "QueryString: " << request->getQueryString() << std::endl;
		std::cout << "ScriptName: " << request->getScriptName() << std::endl;
		std::cout << "filename: " << get_filename(request) << std::endl;
		std::cout << "handler: " << handler << std::endl;

		log()->debug("Process request <%s>", handler.c_str());
		(this->*it->second)(request);
	}
	catch (const fastcgi::HttpException &e) {
		log()->debug("Exception: %s", e.what());
		throw;
	}
	catch (...) {
		log()->debug("Exception: unknown");
		throw fastcgi::HttpException(501);
	}
}

size_t proxy_t::params_num(tokenizer_t &tok) {
	size_t result = 0;
	for (auto it = ++tok.begin(), end = tok.end(); end != it; ++it) {
		++result;
	}
	return result;
}

std::string proxy_t::get_filename(fastcgi::Request *request) {
	assert(request != 0);

	if (request->hasArg("name")) {
		return request->getArg("name");
	} else {
		std::string scriptname = request->getScriptName();
		std::string::size_type begin = scriptname.find('/', 1) + 1;
		std::string::size_type end = scriptname.find('?', begin);
		return scriptname.substr(begin, end - begin);
	}
}

ioremap::elliptics::key proxy_t::get_key(fastcgi::Request *request) {
	assert(request != 0);

	if (request->hasArg("id")) {
		struct dnet_id id;
		dnet_parse_numeric_id(request->getArg("id").c_str(), id.id);
		return ioremap::elliptics::key(id);
	} else {
		std::string filename = get_filename(request);
		return ioremap::elliptics::key(filename);
	}
}

const fastcgi::Logger *proxy_t::log() const {
	return m_data->m_logger;
}

fastcgi::Logger *proxy_t::log() {
	return m_data->m_logger;
}

ioremap::elliptics::node &proxy_t::elliptics_node() {
	return *m_data->m_elliptics_node;
}

ioremap::elliptics::session proxy_t::get_session(fastcgi::Request *request) {
	ioremap::elliptics::session session(*m_data->m_elliptics_node);

	if (request) {
		session.set_cflags(request->hasArg("cflags") ? boost::lexical_cast<unsigned int>(request->getArg("cflags")) : 0);
		session.set_ioflags(request->hasArg("ioflags") ? boost::lexical_cast<unsigned int>(request->getArg("ioflags")) : 0);
		session.set_groups(get_groups(request));
	}

	return session;
}

std::vector<int> proxy_t::get_groups(fastcgi::Request *request, size_t count) {
	assert(request != 0);

	if (count == 0) {
		count = m_data->m_replication_count;
	}

	std::vector <int> groups;

	if (request->hasArg("groups")) {

		separator_t sep(":");
		tokenizer_t tok(request->getArg("groups"), sep);

		try {
			for (auto it = tok.begin(), end = tok.end(); end != it; ++it) {
				groups.push_back(boost::lexical_cast<int>(*it));
			}
		}
		catch (...) {
			std::stringstream ss;
			ss << "groups <" << request->getArg("groups") << "> is incorrect";
			std::string str = ss.str();
			log()->error(str.c_str());
			throw std::runtime_error(str);
		}
	}

	if (groups.empty()) {
		groups = m_data->m_groups;
	}
#if 0
#ifdef HAVE_METABASE
	if (m_data->m_metabase_usage >= PROXY_META_OPTIONAL) {
		try {
			if (groups.size() != count || m_data->m_metabase_usage == PROXY_META_MANDATORY) {
				groups = get_metabalancer_groups_impl(count, size, key);
			}
		} catch (std::exception &e) {
			log()->log(DNET_LOG_ERROR, e.what());
			if (m_data->m_metabase_usage >= PROXY_META_NORMAL) {
				log()->error("Metabase does not respond");
				request->setStatus(503);
				throw std::runtime_error("Metabase does not respond");
			}
		}
	}
#endif /* HAVE_METABASE */
#endif

	std::random_shuffle(++groups.begin(), groups.end());

	if (count != 0 && count < groups.size()) {
		groups.erase(groups.begin() + count, groups.end());
	}

	return groups;
}

bool proxy_t::upload_is_good(size_t success_copies_num, size_t replication_count, size_t size) {
	switch (success_copies_num) {
	case elliptics::SUCCESS_COPIES_TYPE__ANY:
		return size >= 1;
	case elliptics::SUCCESS_COPIES_TYPE__QUORUM:
		return size >= ((replication_count >> 1) + 1);
	case elliptics::SUCCESS_COPIES_TYPE__ALL:
		return size == replication_count;
	default:
		return size >= success_copies_num;
	}
}

size_t proxy_t::uploads_need(size_t success_copies_num) {
	size_t replication_count = m_data->m_replication_count;
	switch (success_copies_num) {
	case elliptics::SUCCESS_COPIES_TYPE__ANY:
		return 1;
	case elliptics::SUCCESS_COPIES_TYPE__QUORUM:
		return ((replication_count >> 1) + 1);
	case elliptics::SUCCESS_COPIES_TYPE__ALL:
		return replication_count;
	default:
		return success_copies_num;
	}
}

elliptics::lookup_result_t proxy_t::parse_lookup(const ioremap::elliptics::lookup_result_entry &entry) {
	return elliptics::lookup_result_t(entry, m_data->m_eblob_style_path, m_data->m_base_port);
}

void proxy_t::register_handlers() {
	register_handler("upload", &proxy_t::upload_handler);
	register_handler("get", &proxy_t::get_handler);
	register_handler("delete", &proxy_t::delete_handler);
	register_handler("download-info", &proxy_t::download_info_handler);
	register_handler("ping", &proxy_t::ping_handler);
	register_handler("stat", &proxy_t::ping_handler);
	register_handler("stat_log", &proxy_t::stat_log_handler);
	register_handler("stat-log", &proxy_t::stat_log_handler);
	register_handler("bulk-upload", &proxy_t::bulk_upload_handler);
	register_handler("bulk-read", &proxy_t::bulk_get_handler);
	register_handler("exec-script", &proxy_t::exec_script_handler);
}

void proxy_t::register_handler(const char *name, proxy_t::request_handler handler, bool override) {
	if (override) {
		log()->debug("Override handler: %s", name);
		m_data->m_handlers[name] = handler;
	} else {
		log()->debug("Register handler: %s", name);
		bool was_inserted = m_data->m_handlers.insert(std::make_pair(name, handler)).second;
		if (!was_inserted) {
			log()->error("Repeated registration of %s handler", name);
		}
	}
}

void proxy_t::allow_origin(fastcgi::Request *request) const {
	if (0 == m_data->m_allow_origin_domains.size()) {
		return;
	}

	if (!request->hasHeader("Origin")) {
		return;
	}

	std::string domain = request->getHeader("Origin");
	if (!domain.compare(0, sizeof ("http://") - 1, "http://")) {
		domain = domain.substr(sizeof ("http://") - 1, std::string::npos);
	}

	for (std::set<std::string>::const_iterator it = m_data->m_allow_origin_domains.begin(), end = m_data->m_allow_origin_domains.end();
		 end != it; ++it) {
		std::string allow_origin_domain = *it;

		if (domain.length() < allow_origin_domain.length() - 1) {
			continue;
		}

		bool allow = false;

		if (domain.length() == allow_origin_domain.length() - 1) {
			allow = !allow_origin_domain.compare(1, std::string::npos, domain);
		}
		else {
			allow = !domain.compare(domain.length() - allow_origin_domain.length(), std::string::npos, allow_origin_domain);
		}

		if (allow) {
			domain =(!request->getHeader("Origin").compare(0, sizeof ("https://") - 1, "https://") ? "https://" : "http://") + domain;
			request->setHeader("Access-Control-Allow-Origin", domain);
			request->setHeader("Access-Control-Allow-Credentials", "true");
			return;
		}
	}
	throw fastcgi::HttpException(403);
}

void proxy_t::upload_handler(fastcgi::Request *request) {
	std::string data;
	request->requestBody().toString(data);
	elliptics::data_container_t dc(data);

	if (request->hasArg("embed") || request->hasArg("embed_timestamp")) {
		timespec timestamp;
		timestamp.tv_sec = get_arg<uint64_t>(request, "timestamp", 0);
		timestamp.tv_nsec = 0;

		dc.set<elliptics::DNET_FCGI_EMBED_TIMESTAMP>(timestamp);
	}

	auto session = get_session(request);

	if (session.state_num() < m_data->m_die_limit) {
		log()->error("Too low number of existing states");
		request->setStatus(503);
		return;
	}

	if (dc.embeds_count() != 0) {
		session.set_user_flags(session.get_user_flags() | elliptics::UF_EMBEDS);
	}

	auto key = get_key(request);
	auto content = elliptics::data_container_t::pack(dc);
	auto offset = get_arg<uint64_t>(request, "offset", 0);

	ioremap::elliptics::async_write_result awr = write(session, key, content, offset, request);

	auto lrs = get_results(request, awr);
	auto success_copies_num = get_arg<int>(request, "success-copies-num", m_data->m_success_copies_num);

	if (upload_is_good(success_copies_num, session.get_groups().size(), lrs.size()) == false) {
		std::ostringstream oss;
		oss << "Not enough copies were written. Only (";

		std::vector <int> groups;
		for (auto it = lrs.begin(); it != lrs.end(); ++it) {
			ioremap::elliptics::write_result_entry &entry = *it;
			int g = entry.command()->id.group_id;
			groups.push_back(g);
			if (it != lrs.begin()) {
				oss << ", ";
			}
			oss << g;
		}
		session.set_groups(groups);

		oss << ") groups responded";

		log()->error(oss.str().c_str());

		try {
			session.remove(key).wait();
		} catch (...) {
			log()->error("Cannot remove written replicas");
		}

		request->setStatus(503);
		return;
	}

	std::stringstream ss;
	ss << "written " << lrs.size() << " copies" << std::endl;
	for (auto it = lrs.begin(); it != lrs.end(); ++it) {
		auto entry = elliptics::lookup_result_t(*it, m_data->m_eblob_style_path, m_data->m_base_port);
		ss << "\tgroup: " << entry.group() << "\tpath: " << entry.host()
		   << ":" << entry.port() << entry.path() << std::endl;
	}

	std::string str = ss.str();

	request->setContentType("text/plaint");
	request->setHeader("Context-Lenght",
						boost::lexical_cast<std::string>(
							str.length()));
	request->write(str.c_str(), str.size());
}

void proxy_t::get_handler(fastcgi::Request *request) {
	std::string content_type;
	{
		std::string filename = get_filename(request);
		std::string extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

		if (m_data->m_deny_list.find(extention) != m_data->m_deny_list.end() ||
			(m_data->m_deny_list.find("*") != m_data->m_deny_list.end() &&
			m_data->m_allow_list.find(extention) == m_data->m_allow_list.end())) {
			request->setStatus(403);
			return;
		}

		std::map<std::string, std::string>::iterator it = m_data->m_typemap.find(extention);

		if (m_data->m_typemap.end() == it) {
			content_type = "application/octet";
		} else {
			content_type = it->second;
		}
	}

	auto session = get_session(request);
	auto key = get_key(request);
	auto offset = get_arg<uint64_t>(request, "offset", 0);
	auto size = get_arg<uint64_t>(request, "size", 0);

	auto arr = session.read_data(key, offset, size);

	auto rr = get_results(request, arr).front();

	bool embeded = request->hasArg("embed") || request->hasArg("embed_timestamp");
	if (rr.io_attribute()->user_flags & elliptics::UF_EMBEDS) {
		embeded = true;
	}

	auto dc = elliptics::data_container_t::unpack(rr.file(), embeded);

	request->setStatus(200);
	request->setContentType(content_type);

	auto ts = dc.get<elliptics::DNET_FCGI_EMBED_TIMESTAMP>();

	char ts_str[128] = {0};
	if (ts) {
		time_t timestamp = (time_t)(ts->tv_sec);
		struct tm tmp;
		strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", gmtime_r(&timestamp, &tmp));

		if (request->hasHeader("If-Modified-Since")) {
			if (request->getHeader("If-Modified-Since") == ts_str) {
				request->setStatus(304);
				return;
			}
		}
	}

	request->setHeader("Last-Modified", ts_str);

	std::string d = dc.data.to_string();

	request->setHeader("Content-Length",
						boost::lexical_cast<std::string>(d.size()));


	request->write(d.data(), d.size());
}

void proxy_t::delete_handler(fastcgi::Request *request) {
	auto key = get_key(request);
	auto session = get_session(request);
	session.set_filter(ioremap::elliptics::filters::all);

	try {
		session.remove(key).wait();
	} catch (std::exception &e) {
		log()->error("Exception: %s", e.what());
		request->setStatus(503);
	} catch (...) {
		log()->error("Eexception: unknown");
		request->setStatus(503);
	}
}

void proxy_t::download_info_handler(fastcgi::Request *request) {
	auto key = get_key(request);
	auto session = get_session(request);

	session.set_filter(ioremap::elliptics::filters::all);
	auto alr = session.lookup(key);
	auto result = get_results(request, alr);


	for (auto it = result.begin(); it != result.end(); ++it) {
		auto &entry = *it;
		if (!entry.error()) {
			std::stringstream ss;
			ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
			std::string region = "-1";

			auto lr = parse_lookup(entry);

			long time;
			{
				using namespace std::chrono;
				time = duration_cast<microseconds>(
							system_clock::now().time_since_epoch()
							).count();
			}

			ss << "<download-info>";
			ss << "<host>" << lr.host() << "</host>";
			ss << "<path>" << lr.path() << "</path>";
			ss << "<region>" << region << "</region>";
			ss << "</download-info>";


			std::string str = ss.str();

			request->setStatus(200);
			request->setContentType("text/xml");
			request->write(str.c_str(), str.length());
			return;
		}
	}
	request->setStatus(503);
}

void proxy_t::ping_handler(fastcgi::Request *request) {
	unsigned short status_code = 200;
	auto session = get_session();
	if (session.state_num() < m_data->m_die_limit) {
		status_code = 500;
	}
	request->setStatus(status_code);
}

void proxy_t::stat_log_handler(fastcgi::Request *request) {
	auto session = get_session();

	auto srs = session.stat_log().get();

	char id_str[DNET_ID_SIZE * 2 + 1];
	char addr_str[128];

	std::ostringstream oss;
	oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
	oss << "<data>\n";

	for (auto it = srs.begin(); it != srs.end(); ++it) {
		const ioremap::elliptics::stat_result_entry &data = *it;
		struct dnet_addr *addr = data.address();
		struct dnet_cmd *cmd = data.command();
		struct dnet_stat *st = data.statistics();

		dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str));
		dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str);

		oss << "<stat addr=\"" << addr_str << "\" id=\"" << id_str << "\">";
		oss << "<la>";
		for (size_t i = 0; i != 3; ++i) {
			oss << std::fixed << std::setprecision(2) << static_cast<float>(st->la[i]) / 100.0;
			if (i != 2)
				oss << ' ';
		}
		oss << "</la>";
		oss << "<memtotal>" << st->vm_total << "</memtotal>";
		oss << "<memfree>" << st->vm_free << "</memfree>";
		oss << "<memcached>" << st->vm_cached << "</memcached>";
		oss << "<storage_size>" << st->frsize * st->blocks / 1024 / 1024 << "</storage_size>";
		oss << "<available_size>" << st->bavail * st->bsize / 1024 / 1024 << "</available_size>";
		oss << "<files>" << st->files << "</files>";
		oss << "<fsid>" << std::hex << st->fsid << "</fsid>";
		oss << "</stat>";
	}

	oss << "</data>";

	std::string body = oss.str();
	request->setStatus(200);
	request->setContentType("text/plaint");
	request->setHeader("Context-Lenght",
						boost::lexical_cast<std::string>(
							body.length()));
	request->write(body.c_str(), body.size());
}

ioremap::elliptics::async_write_result proxy_t::write(ioremap::elliptics::session &session
											 , const ioremap::elliptics::key &key
											 , const ioremap::elliptics::data_pointer &data
											 , const uint64_t &offset, fastcgi::Request *request
											 ) {
	assert(request != 0);
	if (request->hasArg("prepare")) {
		size_t size = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
		return session.write_prepare(key, data, offset, size);
	} else if (request->hasArg("commit")) {
		size_t size = boost::lexical_cast<uint64_t>(request->getArg("commit"));
		return session.write_commit(key, data, offset, size);
	} else if (request->hasArg("plain_write") || request->hasArg("plain-write")) {
		return session.write_plain(key, data, offset);
	} else {
		return session.write_data(key, data, offset, m_data->m_chunk_size);
	}
}

struct dnet_id_less {
	bool operator () (const struct dnet_id &ob1, const struct dnet_id &ob2) {
		int res = memcmp(ob1.id, ob2.id, DNET_ID_SIZE);
		return (res < 0);
	}
};

void proxy_t::bulk_upload_handler(fastcgi::Request *request) {
	std::vector<std::string> filenames;
	request->remoteFiles(filenames);
	std::vector<std::string> data;
	std::vector<dnet_io_attr> ios;
	ios.resize(filenames.size());
	data.resize(filenames.size());

	std::map<dnet_id, std::string, dnet_id_less> keys_transform;
	std::map<std::string, std::vector<ioremap::elliptics::write_result_entry> > res;
	std::map<std::string, std::vector<int> > res_groups;

	auto session = get_session(request);

	for (size_t index = 0; index != filenames.size(); ++index) {
		request->remoteFile(filenames[index]).toString(data[index]);
		dnet_io_attr &io = ios[index];
		memset(&io, 0, sizeof(io));

		ioremap::elliptics::key key(filenames[index]);
		key.transform(session);

		memcpy(io.id, key.id().id, sizeof(io.id));
		io.size = data[index].size();

		keys_transform.insert(std::make_pair(key.id(), filenames[index]));
	}

	auto awr = session.bulk_write(ios, data);
	auto result = get_results(request, awr);

	auto success_copies_num = get_arg<int>(request, "success-copies-num", 0);

	for (auto it = result.begin(); it != result.end(); ++it) {
		const ioremap::elliptics::lookup_result_entry &lr = *it;
		auto r = parse_lookup(lr);
		std::string str = keys_transform[lr.command()->id];
		res[str].push_back(lr);
		res_groups [str].push_back(lr.command()->id.group_id);
	}

	unsigned int replication_need =  uploads_need(success_copies_num);

	auto it = res_groups.begin();
	auto end = res_groups.end();
	for (; it != end; ++it) {
		if (it->second.size() < replication_need)
			break;
	}

	if (it != end) {
		for (auto it = res_groups.begin(), end = res_groups.end(); it != end; ++it) {
			session.set_groups(it->second);
			session.remove(it->first);
		}
		request->setStatus(503);
		return;
	}

	request->setStatus(200);

	std::ostringstream oss;
	oss << "writte result: " << std::endl;

	for (auto it = res.begin(); it != res.end(); ++it) {
		oss << it->first << ':' << std::endl;
		for (auto it2 = it->second.begin(), end2 = it->second.end(); it2 != end2; ++it2) {
			auto l = parse_lookup(*it2);
			oss << "\tgroup: " << l.group() << "\tpath: " << l.host()
				<< ":" << l.port() << l.path() << std::endl;
		}
	}

	std::string str = oss.str();

	request->setContentType("text/plaint");
	request->setHeader("Context-Lenght",
					   boost::lexical_cast<std::string>(
						   str.length()));
	request->write(str.c_str(), str.size());
}

void proxy_t::bulk_get_handler(fastcgi::Request *request) {
	std::vector<std::string> filenames;
	auto session = get_session(request);

	{
		std::string filenames_str;
		request->requestBody().toString(filenames_str);

		separator_t sep("\n");
		tokenizer_t tok(filenames_str, sep);

		try {
			for (auto it = tok.begin(), end = tok.end(); it != end; ++it) {
				filenames.push_back(*it);
			}
		} catch (...) {
			log()->error("invalid keys list: %s", filenames_str.c_str());
		}
	}


	std::map<dnet_id, std::string, dnet_id_less> keys_transform;
	std::vector<dnet_io_attr> ios;
	ios.resize(filenames.size());

	for (size_t index = 0; index != filenames.size(); ++index) {
		dnet_io_attr &io = ios[index];
		const std::string &filename = filenames[index];
		memset(&io, 0, sizeof(io));

		ioremap::elliptics::key key(filename);
		key.transform(session);

		memcpy(io.id, key.id().id, sizeof(io.id));

		keys_transform.insert(std::make_pair(key.id(), filename));
	}

	auto abr = session.bulk_read(ios);
	auto result = get_results(request, abr);

	std::map<std::string, elliptics::data_container_t> ret;
	for (auto it = result.begin(), end = result.end(); it != end; ++it) {
		ioremap::elliptics::read_result_entry &entry = *it;

		ret.insert(std::make_pair(keys_transform[entry.command()->id], elliptics::data_container_t::unpack(entry.file())));
	}


	request->setStatus(200);
	request->setContentType("text/html");
	request->setHeader("Transfer-Encoding", "chunked");

	std::ostringstream oss(std::ios_base::binary | std::ios_base::out);
	//unsigned char CRLF [2] = {0x0D, 0x0A};
	char CRLF [] = "\r\n";
	for (auto it = ret.begin(), end = ret.end(); it != end; ++it) {
		std::string content = it->second.data.to_string();
		size_t size = content.size();
		oss << std::hex << size << "; name=\"" << it->first << "\"" << CRLF;
		oss << content << CRLF;
	}
	oss << 0 << CRLF << CRLF;
	std::string body = oss.str();
	request->write(body.data(), body.length());

}

void proxy_t::exec_script_handler(fastcgi::Request *request) {
	auto key = get_key(request);
	auto session = get_session(request);
	std::string script = request->hasArg("script") ? request->getArg("script") : "";
	key.transform(session);

	std::string data;
	request->requestBody().toString(data);

	auto id = key.id();
	auto aer = session.exec(&id, script, ioremap::elliptics::data_pointer(data));
	auto res = get_results(request, aer).front();
	auto res_data = res.data();
	auto data_str = res_data.to_string();

	request->setStatus(200);
	request->write(data_str.c_str(), data_str.size());
}

FCGIDAEMON_REGISTER_FACTORIES_BEGIN()
FCGIDAEMON_ADD_DEFAULT_FACTORY("proxy_factory", proxy_t)
FCGIDAEMON_REGISTER_FACTORIES_END()
