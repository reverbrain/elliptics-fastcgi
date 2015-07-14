#include "elliptics-fastcgi/proxy.hpp"
#include "ranges.hpp"

#include <fastcgi2/except.h>
#include <fastcgi2/config.h>
#include <fastcgi2/component_factory.h>

#include <crypto++/md5.h>

#include <boost/thread/tss.hpp>

#include <iomanip>
#include <chrono>
#include <functional>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <list>
#include <cstdlib>
#include <cstdio>

#include "elliptics-fastcgi/data_container.hpp"
#include "magic_provider.hpp"

namespace {

namespace details {

template <typename T>
void set_trace_id(ioremap::elliptics::session &session, const std::string &request_id, const T &v) {
	size_t bytes = std::min(request_id.size(), sizeof(T) * 2);
	T id = 0;

	for (size_t index = 0; index != bytes; ++index) {
		char c = request_id[index];
		id = id * 16 + (isalpha(c) ? toupper(c) - 'A' + 10 : c - '0');
	}

	session.set_trace_id(id);
}

} // namespace details

void set_trace_id(ioremap::elliptics::session &session, const std::string &request_id) {
	details::set_trace_id(session, request_id, session.get_trace_id());
}

std::string generate_etag(uint64_t timestamp, uint64_t size) {
	using namespace CryptoPP;

	MD5 hash;

	hash.Update((const byte *)&timestamp, sizeof(uint64_t));
	hash.Update((const byte *)&size, sizeof(uint64_t));

	std::vector<byte> result(hash.DigestSize());
	hash.Final(result.data());

	std::ostringstream oss;
	oss << std::hex;
	oss << "\"";
	for (auto it = result.begin(), end = result.end(); it != end; ++it) {
		oss << std::setfill('0') << std::setw(2) << static_cast<int>(*it);
	}
	oss << "\"";

	return oss.str();
}

} // namespace
namespace elliptics {

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

	ioremap::elliptics::logger_base                    m_elliptics_log;
	std::shared_ptr<ioremap::elliptics::node>          m_elliptics_node;
	std::vector<int>                                   m_groups;

	int                                                m_base_port;
	int                                                m_directory_bit_num;
	int                                                m_success_copies_num;
	int                                                m_die_limit;
	int                                                m_replication_count;
	int                                                m_write_chunk_size;
	int                                                m_read_chunk_size;
	bool                                               m_eblob_style_path;
	int                                                m_data_flow_rate;

	boost::thread_specific_ptr<magic_provider_t>       m_magic;

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
	m_data->m_data_flow_rate = config->asInt(path + "/dnet/data-flow-rate", 0);

	m_data->m_write_chunk_size = config->asInt(path + "/dnet/write_chunk_size", 0);
	m_data->m_read_chunk_size = config->asInt(path + "/dnet/read_chunk_size", 0);
	if (m_data->m_write_chunk_size < 0) m_data->m_write_chunk_size = 0;
	if (m_data->m_read_chunk_size < 0) m_data->m_read_chunk_size = 0;

	std::string log_path = config->asString(path + "/dnet/log/path");
	int log_mask = config->asInt(path + "/dnet/log/mask");

	struct dnet_config dnet_conf;
	memset(&dnet_conf, 0, sizeof (dnet_conf));

	dnet_conf.wait_timeout = config->asInt(path + "/dnet/wait-timeout", 0);
	dnet_conf.check_timeout = config->asInt(path + "/dnet/reconnect-timeout", 0);
	dnet_conf.flags = config->asInt(path + "/dnet/cfg-flags", 4);

	m_data->m_elliptics_log = ioremap::elliptics::file_logger(
			log_path.c_str(), (dnet_log_level)log_mask);
	m_data->m_elliptics_node.reset(new ioremap::elliptics::node(
				ioremap::elliptics::logger(m_data->m_elliptics_log,  blackhole::log::attributes_t())
				, dnet_conf));

	std::vector<std::string> names;

	config->subKeys(path + "/dnet/remote/addr", names);

	if (!names.size()) {
		throw std::runtime_error("Remotes can't be empty");
	}

	for (std::vector<std::string>::iterator it = names.begin(), end = names.end();
		 end != it; ++it) {
		auto remote = config->asString(*it);
		try {
			m_data->m_elliptics_node->add_remote(remote);

			log()->info("added dnet remote %s", remote.c_str());
		} catch(const std::exception &e) {
			log()->error("Can't connect to remote %s", remote.c_str());
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

	this->register_handlers();
}

void proxy_t::onUnload() {
}

void proxy_t::handleRequest(fastcgi::Request *request, fastcgi::HandlerContext *context) {
	(void)context;
	log()->debug("Handling request: %s", request->getScriptName().c_str());

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

		log()->debug("Process request <%s>", handler.c_str());
		(it->second)(request);
	}
	catch (const fastcgi::HttpException &e) {
		log()->error("Http Exception: %s", e.what());
		throw;
	}
	catch (const std::exception &e) {
		log()->error("Exception: %s", e.what());
		throw;
	}
	catch (...) {
		log()->error("Exception: unknown");
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

		set_trace_id(session, request->getRequestId());
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

	if (!groups.empty()) {
		std::random_shuffle(++groups.begin(), groups.end());
	}

	if (count != 0 && count < groups.size()) {
		groups.erase(groups.begin() + count, groups.end());
	}

	if (groups.empty()) {
		log()->info("%s: there are no groups for operation with elliptics"
				, request->getScriptName().c_str());
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
	return elliptics::lookup_result_t(entry, m_data->m_eblob_style_path, m_data->m_base_port, m_data->m_directory_bit_num);
}

void proxy_t::register_handlers() {
	register_handler("upload", std::bind(&proxy_t::upload_handler, this, std::placeholders::_1));
	register_handler("get", std::bind(&proxy_t::get_handler, this, std::placeholders::_1));
	register_handler("delete", std::bind(&proxy_t::delete_handler, this, std::placeholders::_1));
	register_handler("download-info", std::bind(&proxy_t::download_info_handler, this, std::placeholders::_1));
	register_handler("ping", std::bind(&proxy_t::ping_handler, this, std::placeholders::_1));
	register_handler("stat", std::bind(&proxy_t::ping_handler, this, std::placeholders::_1));
	register_handler("stat_log", std::bind(&proxy_t::stat_log_handler, this, std::placeholders::_1));
	register_handler("stat-log", std::bind(&proxy_t::stat_log_handler, this, std::placeholders::_1));
	register_handler("bulk-write", std::bind(&proxy_t::bulk_upload_handler, this, std::placeholders::_1));
	register_handler("bulk-read", std::bind(&proxy_t::bulk_get_handler, this, std::placeholders::_1));
	register_handler("exec-script", std::bind(&proxy_t::exec_script_handler, this, std::placeholders::_1));
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

namespace {
std::string id_str(const ioremap::elliptics::key &key, ioremap::elliptics::session sess) {
	struct dnet_id id;
	memset(&id, 0, sizeof(id));
	if (key.by_id()) {
		id = key.id();
	} else {
		sess.transform(key.remote(), id);
	}
	char str[2 * DNET_ID_SIZE + 1];
	dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, str);
	return std::string(str);
}
} // namespace

void proxy_t::upload_handler(fastcgi::Request *request) {
	std::string data;
	request->requestBody().toString(data);

	if (data.size() == 0) {
		log()->info("upload: request=\"%s\" err=\"cannot upload data of zero-length\"",
			request->getScriptName().c_str());
		request->setStatus(400);
		return;
	}

	elliptics::data_container_t dc(data);

	if (request->hasArg("embed") || request->hasArg("embed_timestamp")) {
		uint64_t t = time(0);
		timespec timestamp;
		timestamp.tv_sec = get_arg<uint64_t>(request, "timestamp", t);
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

	std::ostringstream oss;
	oss
		<< "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		<< "<post obj=\"" << key.remote() << "\" id=\""
		<< id_str(key, session)
		<< "\" crc=\"" << id_str(ioremap::elliptics::key(data), session)
		<< "\" groups=\"" << lrs.size()
		<< "\" size=\"" << content.size() << "\">\n";

	size_t written = 0;
	for (auto it = lrs.begin(); it != lrs.end(); ++it) {
		const auto &pl = parse_lookup(*it);
		if (pl.status() == 0)
			written += 1;
		oss << "<complete addr=\"" << pl.addr() << "\" path=\"" <<
			pl.full_path() << "\" group=\"" << pl.group() <<
			"\" status=\"" << pl.status() << "\"/>\n";
	}

	oss << "<written>" << written << "</written>\n</post>";
	std::string str = oss.str();

	request->setContentType("text/plain");
	request->setHeader("Content-Length",
						boost::lexical_cast<std::string>(
							str.length()));
	request->write(str.c_str(), str.size());
}

bool proxy_t::read_chunk(fastcgi::Request *request, size_t offset, size_t size,
		const std::function<ioremap::elliptics::async_read_result(uint64_t, uint64_t)> &read_func) {
	size_t read_size = 0;
	size_t rcs = m_data->m_read_chunk_size;
	do {
		auto arr = read_func(offset + read_size, std::min(size - read_size, rcs));
		arr.wait();

		if (arr.error()) {
			request->setStatus(501);
			log()->error(arr.error().message().c_str());
			return false;
		}

		auto rr = get_results(request, arr).front();
		auto file = rr.file();
		auto data = file.to_string();
		request->write(data.data(), data.size());
		read_size += file.size();
	} while (read_size < size);
	return true;
}

std::tuple<size_t, int, bool, uint64_t> proxy_t::lookup(ioremap::elliptics::session session,
		const ioremap::elliptics::key &key, bool latest) {
	struct {
		size_t total_size;
		int group;
		bool embed;
		uint64_t timestamp;
	} ret {0, 0, false};
	std::ostringstream oss;
	oss << "lookup " << key.to_string() << ": " << (latest ? "latest" : "any") << "; groups=[";

	auto ioflags_bkp = session.get_ioflags();
	session.set_ioflags(ioflags_bkp | DNET_IO_FLAGS_NOCSUM);

	{
		auto groups = session.get_groups();
		for (auto bit = groups.begin(), it = bit, end = groups.end(); it != end; ++it) {
			if (bit != it) oss << ", ";
			oss << *it;
		}
	}
	oss << "]; ";
	{
		auto msg = oss.str();
		log()->info("%s", msg.c_str());
	}

	std::list<ioremap::elliptics::async_read_result> arr;
	if (!latest) {
		arr.emplace_back(session.read_data(key, 0, 1));
	} else {
		std::vector<int> groups = session.get_groups();

		for (auto it = groups.begin(), end = groups.end(); it != end; ++it) {
			session.set_groups({*it});
			arr.emplace_back(std::move(session.read_data(key, 0, 1)));
		}

		session.set_groups(groups);
	}

	std::list<ioremap::elliptics::async_read_result> good_arr;
	std::list<ioremap::elliptics::async_read_result> bad_arr;
	for (auto it = arr.begin(), end = arr.end(); it != end; ++it) {
		it->wait();
		auto err = it->error();
		if (err) {
			bad_arr.emplace_back(std::move(*it));
			auto msg = err.message();
			log()->info("lookup %s: %s", key.to_string().c_str(), msg.c_str());
		} else {
			good_arr.emplace_back(std::move(*it));
		}
	}

	if (good_arr.empty()) {
		log()->info("lookup %s: failed"
			, key.to_string().c_str()
				);
		bad_arr.front().error().throw_error();
	}

	if (!latest) {
		auto &&result = good_arr.front();
		auto &&entrys = result.get();
		auto &&entry = entrys.front();
		ret.total_size = entry.io_attribute()->total_size;
		ret.group = entry.command()->id.group_id;
		if (entry.io_attribute()->user_flags & elliptics::UF_EMBEDS) {
			ret.embed = true;
		}
		ret.timestamp = entry.io_attribute()->timestamp.tsec;
	} else {
		std::vector<ioremap::elliptics::read_result_entry> results;
		results.reserve(good_arr.size());

		for (auto it = good_arr.begin(), end = good_arr.end(); it != end; ++it) {
			results.emplace_back(it->get_one());
		}

		size_t pos = 0;
		uint64_t timestamp = results.front().io_attribute()->timestamp.tsec;

		for (size_t index = 1, end = results.size(); index != end; ++index) {
			uint64_t tmp = results[index].io_attribute()->timestamp.tsec;
			if (tmp > timestamp) {
				timestamp = tmp;
				pos = index;
			}
		}
		ret.total_size = results[pos].io_attribute()->total_size;
		ret.timestamp = results[pos].io_attribute()->timestamp.tsec;
		ret.group = results[pos].command()->id.group_id;
		if (results[pos].io_attribute()->user_flags & elliptics::UF_EMBEDS) {
			ret.embed = true;
		}
	}
	log()->info("lookup %s: embed=%s, group=%d, size=%d"
			, key.to_string().c_str()
			, (ret.embed ? "yes" : "no"), int(ret.group), int(ret.total_size));

	{
		if (m_data->m_data_flow_rate) {
			session.set_timeout(session.get_timeout() + ret.total_size / m_data->m_data_flow_rate);
		}
		auto arr = session.read_data(key, 0, 1);
		auto error = arr.error();
		if (error) {
			error.throw_error();
		}
	}
	log()->info("lookup %s: checked sums"
			, key.to_string().c_str()
			);

	return std::make_tuple(ret.total_size, ret.group, ret.embed, ret.timestamp);
}

void proxy_t::get_handler(fastcgi::Request *request) {
	std::string file_extention;
	std::string ETag;
	{
		std::string filename = get_filename(request);
		file_extention = filename.substr(filename.rfind('.') + 1, std::string::npos);

		if (m_data->m_deny_list.find(file_extention) != m_data->m_deny_list.end() ||
			(m_data->m_deny_list.find("*") != m_data->m_deny_list.end() &&
			m_data->m_allow_list.find(file_extention) == m_data->m_allow_list.end())) {
			request->setStatus(403);
			return;
		}
	}

	auto session = get_session(request);
	auto key = get_key(request);
	auto offset = get_arg<uint64_t>(request, "offset", 0);
	auto size = get_arg<uint64_t>(request, "size", 0);
	bool embeded = request->hasArg("embed") || request->hasArg("embed_timestamp");

	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	size_t total_size = 0;

	try {
		auto res = lookup(session, key, request->hasArg("latest"));
		total_size = std::get<0>(res);
		session.set_groups({std::get<1>(res)});
		session.set_ioflags(session.get_ioflags() | DNET_IO_FLAGS_NOCSUM);
		if (std::get<2>(res)) {
			embeded = true;
		}
		if (!request->hasArg("offset") && !request->hasArg("size")) {
			ETag = generate_etag(std::get<3>(res), total_size);
		}
	} catch (const ioremap::elliptics::error &error) {
		request->setStatus(error.error_code() == -ENOENT ? 404 : 501);
		log()->error("%s: %s"
				, request->getScriptName().c_str()
				, error.error_message().c_str());
		return;
	}
	log()->info("read %s: embed=%s, total-size=%d, range=%s"
			, key.to_string().c_str()
			, (embeded ? "yes" : "no"), int(total_size), (request->hasHeader("Range") ? "yes" : "no"));

	{
		if (offset >= total_size) {
			request->setStatus(200);
			request->setHeader("Content-Length", "0");
			request->setHeader("Accept-Ranges", "bytes");
			return;
		}

		total_size -= offset;
		if (size !=0 && size < total_size) {
			total_size = size;
		}
	}

	typedef ioremap::elliptics::async_read_result (ioremap::elliptics::session::* read_func_t)
		(const ioremap::elliptics::key &, uint64_t, uint64_t);
	auto read_func = std::bind(static_cast<read_func_t>(&ioremap::elliptics::session::read_data),
						session, key, std::placeholders::_1, std::placeholders::_2);

	// There may be a problem with simultaneous use of range header and embed parameter:
	// in case you are wrong and set embed-parameter but there are no embeds in the data.
	// It's frequent mistake in practice.
	// So I can check it by reading first 48 bytes of file,
	// but I don't like an additional read for each (possibly smaller than 48 bytes) request.
	// In fact, nobody needs embeds -- it's legacy. Therefore this decision won't bring problems.
	if (request->hasHeader("Range") && !embeded) {
		size_t embed_offset = 0;
		if (embeded) {
			embed_offset = 48;
		}
		auto range_header = request->getHeader("Range");
		auto ranges_opt = parse_range_header(range_header, total_size - embed_offset);
		if (!ranges_opt) {
			request->setStatus(406);
			return;
		}

		if (ranges_opt->size() == 1) {
			auto &&range = ranges_opt->front();
			request->setStatus(206);
			request->setContentType("application/octet-stream");
			request->setHeader("Content-Length", boost::lexical_cast<std::string>(range.size));
			request->setHeader("Accept-Ranges", "bytes");
			request->setHeader("Content-Range",
					boost::lexical_cast<std::string>(range.offset) + '-'
					+ boost::lexical_cast<std::string>(range.size + range.offset - 1) + '/'
					+ boost::lexical_cast<std::string>(range.size));
			if (!ETag.empty()) {
				request->setHeader("ETag", ETag);
			}
			log()->info("read chunk %s: offset= %d; size=%d;"
					, request->getScriptName().c_str()
					, int(range.offset + embed_offset), int(range.size));
			read_chunk(request, range.offset + embed_offset, range.size, read_func);
		} else {
			size_t content_length = 0;
			std::vector<std::string> chunk_headers;

			std::string boundary;
			{
				char boundary_buf[17] = {0};
				for (size_t i = 0; i < 2; ++i) {
					uint32_t tmp = rand();
					sprintf(boundary_buf + i * 8, "%08X", tmp);
				}
				boundary.assign(boundary_buf);
			}
			
			{
				for (auto bit = ranges_opt->begin(), it = bit, end = ranges_opt->end();
						it != end; ++it) {
					std::ostringstream oss;

					if (it != bit) {
						oss << "\r\n";
					}

					oss << "--" << boundary << "\r\n"
						<< "Content-Type: application/octet-stream\r\n"
						<< "Content-Range: bytes "
						<< it->offset << '-' << (it->size + it->offset - 1) << '/' << it->size
						<< "\r\n\r\n";

					auto headers = oss.str();
					content_length += headers.size();
					content_length += it->size;
					chunk_headers.push_back(headers);
				}
				{
					std::ostringstream oss;
					oss << "\r\n--" << boundary << "--\r\n";
					auto last_boundary = oss.str();
					chunk_headers.push_back(last_boundary);
					content_length += last_boundary.size();
				}
			}

			request->setStatus(206);
			request->setContentType("multipart/byteranges; boundary=" + boundary);
			request->setHeader("Content-Length", boost::lexical_cast<std::string>(content_length));
			request->setHeader("Accept-Ranges", "bytes");
			if (!ETag.empty()) {
				request->setHeader("ETag", ETag);
			}

			for (size_t index = 0, end = ranges_opt->size(); end != index; ++index) {
				const auto &headers = chunk_headers[index];
				const auto &range = (*ranges_opt)[index];
				request->write(headers.data(), headers.size());
				log()->info("read chunk %s: offset= %d; size=%d;"
						, request->getScriptName().c_str()
						, int(range.offset + embed_offset), int(range.size));
				read_chunk(request, range.offset + embed_offset, range.size, read_func);
			}
			{
				const auto &headers = chunk_headers.back();
				request->write(headers.data(), headers.size());
			}
		}

		return;
	}

	log()->info("read %s: offset= %d; size=%d;"
			, request->getScriptName().c_str()
			, int(offset), int(m_data->m_read_chunk_size));
	auto arr = read_func(offset, m_data->m_read_chunk_size);
	arr.wait();

	if (arr.error()) {
		request->setStatus(501);
		log()->error(arr.error().message().c_str());
		return;
	}

	auto rr = get_results(request, arr).front();
	auto file = rr.file();
	time_t timestamp = rr.io_attribute()->timestamp.tsec;
	std::string data;

	if (offset == 0) {
		try {
			auto dc = elliptics::data_container_t::unpack(file, embeded);

			auto ts = dc.get<elliptics::DNET_FCGI_EMBED_TIMESTAMP>();
			if (ts) {
				timestamp = (time_t)(ts->tv_sec);
			}

			dc.data.to_string().swap(data);
		} catch (const std::exception &ex) {
			log()->error("%s: Cannot parse embeds from the read file: %s"
					, request->getScriptName().c_str()
					, ex.what());
			request->setStatus(500);
			return;
		}
	} else {
		file.to_string().swap(data);
	}

	char ts_str[128] = {0};
	struct tm tmp;

	if (!gmtime_r(&timestamp, &tmp)) {
		std::ostringstream oss;
		oss << "cannot convert timestamp " << timestamp << " to calendar time: errno=" << errno;
		log()->error("%s", oss.str().c_str());
		request->setStatus(500);
		return;
	}

	if (!strftime(ts_str, sizeof (ts_str), "%a, %d %b %Y %T %Z", &tmp)) {
		std::ostringstream oss;
		oss << "cannot format date string from calendar time: errno=" << errno;
		log()->error("%s", oss.str().c_str());
		request->setStatus(500);
		return;
	}

	if (request->hasHeader("If-Modified-Since")) {
		if (request->getHeader("If-Modified-Since") == ts_str) {
			request->setStatus(304);
			return;
		}
	}

	request->setStatus(200);

	{
		auto it = m_data->m_typemap.find(file_extention);
		if (m_data->m_typemap.end() == it) {
			if (NULL == m_data->m_magic.get()) {
				m_data->m_magic.reset(new magic_provider_t());
			}
			request->setContentType(m_data->m_magic->type(data));
		} else {
			request->setContentType(it->second);
		}
	}

	request->setHeader("Content-Length",
						boost::lexical_cast<std::string>(total_size - file.size() + data.size()));
	request->setHeader("Last-Modified", ts_str);
	request->setHeader("Accept-Ranges", "bytes");
	if (!ETag.empty()) {
		request->setHeader("ETag", ETag);
	}

	request->write(data.data(), data.size());

	if (total_size > m_data->m_read_chunk_size) {
		log()->info("read chunk %s: offset= %d; size=%d;"
				, request->getScriptName().c_str()
				, int(offset + file.size()), int(total_size - m_data->m_read_chunk_size));
		read_chunk(request, offset + file.size(), total_size - m_data->m_read_chunk_size, read_func);
	}

	return;

}

void proxy_t::delete_handler(fastcgi::Request *request) {
	auto key = get_key(request);
	auto session = get_session(request);
	session.set_filter(ioremap::elliptics::filters::all);

	try {
		session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
		auto arr = session.remove(key);
		arr.wait();
		if (arr.error()) {
			request->setStatus(arr.error().code() == -ENOENT ? 402 : 501);
			log()->error(arr.error().message().c_str());
			return;
		}
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
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	auto alr = session.lookup(key);
	alr.wait();
    if (alr.error()) {
        request->setStatus(alr.error().code() == -ENOENT ? 404 : 501);
        log()->error(alr.error().message().c_str());
        return;
    }
	auto result = get_results(request, alr);


	for (auto it = result.begin(); it != result.end(); ++it) {
		auto &entry = *it;
		if (!entry.error()) {
			std::stringstream ss;
			ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
			std::string region = "-1";

			auto lr = parse_lookup(entry);

/*
			long time;
			{
				using namespace std::chrono;
				time = duration_cast<microseconds>(
							system_clock::now().time_since_epoch()
							).count();
			}
*/

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

	auto srs = session.monitor_stat(DNET_MONITOR_PROCFS).get();

	char id_str[DNET_ID_SIZE * 2 + 1];
	char addr_str[128];

	std::ostringstream oss;
	oss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
	oss << "<data>\n";

	for (auto it = srs.begin(); it != srs.end(); ++it) {
		const auto &data = *it;
		struct dnet_addr *addr = data.address();
		struct dnet_cmd *cmd = data.command();
		const std::string st = data.statistics();

		dnet_addr_string_raw(addr, addr_str, sizeof(addr_str));
		dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str);

		oss << "<stat addr=\"" << addr_str << "\" id=\"" << id_str << "\">\n";
        oss << "<json><![CDATA[" << st << "]]></json>\n";
/*
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
*/
		oss << "</stat>\n";
	}

	oss << "</data>";

	std::string body = oss.str();
	request->setStatus(200);
	request->setContentType("text/xml");
	request->setHeader("Content-Length",
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
		size_t size;
		try {
			size = boost::lexical_cast<uint64_t>(request->getArg("prepare"));
		} catch (...) {
			log()->info("Cannot parse size of file from \'prepare\' argument");
			throw fastcgi::HttpException(400);
		}
		return session.write_prepare(key, data, offset, size);
	} else if (request->hasArg("commit")) {
		size_t size;
		try {
			size = boost::lexical_cast<uint64_t>(request->getArg("commit"));
		} catch (...) {
			log()->info("Cannot parse size of file from \'commit\' argument");
			throw fastcgi::HttpException(400);
		}
		return session.write_commit(key, data, offset, size);
	} else if (request->hasArg("plain_write") || request->hasArg("plain-write")) {
		return session.write_plain(key, data, offset);
	} else {
		return session.write_data(key, data, offset, m_data->m_write_chunk_size);
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

	request->setContentType("text/plain");
	request->setHeader("Content-Length",
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
	auto aer = session.exec(&id, script, data);
	auto res = get_results(request, aer).front();
	auto res_data = res.data();
	auto data_str = res_data.to_string();

	request->setStatus(200);
	request->write(data_str.c_str(), data_str.size());
}

} // namespace elliptics

FCGIDAEMON_REGISTER_FACTORIES_BEGIN()
FCGIDAEMON_ADD_DEFAULT_FACTORY("elliptics-proxy", elliptics::proxy_t)
FCGIDAEMON_REGISTER_FACTORIES_END()
