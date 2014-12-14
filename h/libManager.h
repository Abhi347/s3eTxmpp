#pragma once

#ifndef _TXMPP_LIB_MANAGER_H_
#define _TXMPP_LIB_MANAGER_H_
#include "time.h"

namespace txmpp {

	class libManager
	{
	public:
		static void Create();
		static void Destroy();
		static libManager* GetInstance();

		int	gettimeofday(struct timeval* tv, struct timezone* tz);

		int64 time();


	private:
		static libManager* _instance;
		libManager();
		~libManager();
		libManager(const libManager &);
		libManager& operator=(const libManager &);
	};
#define LIB_MAN ( libManager::GetInstance()  )
}  // namespace txmpp

#endif  // _TXMPP_LIB_MANAGER_H_
