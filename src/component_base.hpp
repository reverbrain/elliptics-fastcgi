#ifndef COMPONENT_BASE_MODULE
#define COMPONENT_BASE_MODULE

#include <fastcgi2/component.h>
#include <fastcgi2/logger.h>

class component_base_t : public fastcgi::Component {
public:
	component_base_t(fastcgi::ComponentContext *context);
	virtual ~component_base_t();

	virtual void onLoad();
	virtual void onUnload();
protected:
	fastcgi::Logger *log() const;
private:
	fastcgi::Logger *m_logger;
};

#endif /* COMPONENT_BASE_MODULE */
