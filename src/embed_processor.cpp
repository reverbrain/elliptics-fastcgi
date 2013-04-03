#include "embed_processor.hpp"

#include <fastcgi2/config.h>

#include <stdexcept>

embed_processor_module_base_t::embed_processor_module_base_t(fastcgi::ComponentContext *context)
	: component_base_t(context)
	, m_logger(0) {
}

embed_processor_module_base_t::~embed_processor_module_base_t() {
}

void embed_processor_module_base_t::onLoad() {
	assert (0 == m_logger);

	const fastcgi::Config *config = context()->getConfig();
	std::string path (context()->getComponentXPath());

	m_logger = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!m_logger) {
		throw std::logic_error("can't find logger");
	}
}

void embed_processor_module_base_t::onUnload() {
}

bool embed_processor_module_base_t::process_embed(fastcgi::Request *request, uint32_t flags, char *data, uint32_t size, int &http_status) {
	(void)request;
	(void)flags;
	(void)data;
	http_status = 200;
	return true;
}

fastcgi::Logger *embed_processor_module_base_t::log() const {
	return m_logger;
}
