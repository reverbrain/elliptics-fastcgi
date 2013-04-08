#include "component_base.hpp"
#include <fastcgi2/config.h>
#include <stdexcept>

component_base_t::component_base_t(fastcgi::ComponentContext *context)
	: fastcgi::Component(context)
	, m_logger(0)
{}

component_base_t::~component_base_t() {
}

void component_base_t::onLoad() {
	assert(0 == m_logger);

	const fastcgi::Config *config = context()->getConfig();
	std::string path(context()->getComponentXPath());

	m_logger = context()->findComponent<fastcgi::Logger>(config->asString(path + "/logger"));
	if (!m_logger) {
		throw std::logic_error("can't find logger");
	}
}

void component_base_t::onUnload() {
}

fastcgi::Logger *component_base_t::log() const {
	return m_logger;
}
