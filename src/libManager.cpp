#include "libManager.h"
#include "s3eTypes.h"
#include "s3eTimer.h"

#define SECSPERMIN      60
#define MINSPERHOUR     60
#define HOURSPERDAY     24
#define DAYSPERWEEK     7
#define DAYSPERNYEAR    365
#define DAYSPERLYEAR    366
#define SECSPERHOUR     (SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY      ((long) SECSPERHOUR * HOURSPERDAY)
#define MONSPERYEAR     12
#define TM_YEAR_BASE    1900
#define isleap(y) ((((y) % 4) == 0 && ((y) % 100) != 0) || ((y) % 400) == 0)

namespace txmpp {
#ifndef __SINGLETON_UNDEF__//Do not define this :-p
	libManager* libManager::_instance = NULL;
	void libManager::Create()
	{
		if (_instance == NULL)
			_instance = new libManager;
	}
	void libManager::Destroy()
	{
		if (_instance != NULL)
		{
			delete _instance;
			_instance = NULL;
		}
	}
	libManager* libManager::GetInstance()
	{
		return _instance;
	}
	libManager::libManager(){}
	libManager::~libManager(){}
#endif //end Singleton definition


	int	libManager::gettimeofday(struct timeval* tv, struct timezone* tz){
		if (tv != NULL) {
			int64 timeInMillis = time();
			tv->tv_sec = timeInMillis / 1000;
			tv->tv_usec = timeInMillis % 1000;
		}
		return 0;
	}
	int64 libManager::time(){
		return s3eTimerGetUTC();
	}
}  // namespace txmpp
