/*
 * libjingle
 * Copyright 2004--2005, Google Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "proxydetect.h"

#ifdef WIN32
#include "win32.h"
#include <shlobj.h>
#endif  // WIN32

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef OSX
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>
#include "macconversion.h"
#endif

#include <map>

#include "httpcommon.h"
#include "httpcommon-inl.h"
#include "stringutils.h"
#include "pathutils.h"
#include "s3eFile.h"

#ifdef WIN32
#define _TRY_WINHTTP 1
#define _TRY_JSPROXY 0
#define _TRY_WM_FINDPROXY 0
#define _TRY_IE_LAN_SETTINGS 1
#endif  // WIN32

// For all platforms try Firefox.
#define _TRY_FIREFOX 1

// Use profiles.ini to find the correct profile for this user.
// If not set, we'll just look for the default one.
#define USE_FIREFOX_PROFILES_INI 1

static const size_t kMaxLineLength = 1024;
static const char kFirefoxPattern[] = "Firefox";
static const char kInternetExplorerPattern[] = "MSIE";

struct StringMap {
 public:
  void Add(const char * name, const char * value) { map_[name] = value; }
  const std::string& Get(const char * name, const char * def = "") const {
    std::map<std::string, std::string>::const_iterator it =
        map_.find(name);
    if (it != map_.end())
      return it->second;
    def_ = def;
    return def_;
  }
  bool IsSet(const char * name) const {
    return (map_.find(name) != map_.end());
  }
 private:
  std::map<std::string, std::string> map_;
  mutable std::string def_;
};

enum UserAgent {
  UA_FIREFOX,
  UA_INTERNETEXPLORER,
  UA_OTHER,
  UA_UNKNOWN
};

#if _TRY_WINHTTP
//#include <winhttp.h>
// Note: From winhttp.h

const char WINHTTP[] = "winhttp";

typedef LPVOID HINTERNET;

typedef struct {
  DWORD  dwAccessType;      // see WINHTTP_ACCESS_* types below
  LPWSTR lpszProxy;         // proxy server list
  LPWSTR lpszProxyBypass;   // proxy bypass list
} WINHTTP_PROXY_INFO, * LPWINHTTP_PROXY_INFO;

typedef struct {
  DWORD   dwFlags;
  DWORD   dwAutoDetectFlags;
  LPCWSTR lpszAutoConfigUrl;
  LPVOID  lpvReserved;
  DWORD   dwReserved;
  BOOL    fAutoLogonIfChallenged;
} WINHTTP_AUTOPROXY_OPTIONS;

typedef struct {
  BOOL    fAutoDetect;
  LPWSTR  lpszAutoConfigUrl;
  LPWSTR  lpszProxy;
  LPWSTR  lpszProxyBypass;
} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;

extern "C" {
  typedef HINTERNET (WINAPI * pfnWinHttpOpen)
      (
          IN LPCWSTR pwszUserAgent,
          IN DWORD   dwAccessType,
          IN LPCWSTR pwszProxyName   OPTIONAL,
          IN LPCWSTR pwszProxyBypass OPTIONAL,
          IN DWORD   dwFlags
          );
  typedef BOOL (STDAPICALLTYPE * pfnWinHttpCloseHandle)
      (
          IN HINTERNET hInternet
          );
  typedef BOOL (STDAPICALLTYPE * pfnWinHttpGetProxyForUrl)
      (
          IN  HINTERNET                   hSession,
          IN  LPCWSTR                     lpcwszUrl,
          IN  WINHTTP_AUTOPROXY_OPTIONS * pAutoProxyOptions,
          OUT WINHTTP_PROXY_INFO *        pProxyInfo
          );
  typedef BOOL (STDAPICALLTYPE * pfnWinHttpGetIEProxyConfig)
      (
          IN OUT WINHTTP_CURRENT_USER_IE_PROXY_CONFIG * pProxyConfig
          );

} // extern "C"

#define WINHTTP_AUTOPROXY_AUTO_DETECT           0x00000001
#define WINHTTP_AUTOPROXY_CONFIG_URL            0x00000002
#define WINHTTP_AUTOPROXY_RUN_INPROCESS         0x00010000
#define WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY   0x00020000
#define WINHTTP_AUTO_DETECT_TYPE_DHCP           0x00000001
#define WINHTTP_AUTO_DETECT_TYPE_DNS_A          0x00000002
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY               0
#define WINHTTP_ACCESS_TYPE_NO_PROXY                    1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY                 3
#define WINHTTP_NO_PROXY_NAME     NULL
#define WINHTTP_NO_PROXY_BYPASS   NULL

#endif // _TRY_WINHTTP

#if _TRY_JSPROXY
extern "C" {
  typedef BOOL (STDAPICALLTYPE * pfnInternetGetProxyInfo)
      (
          LPCSTR lpszUrl,
          DWORD dwUrlLength,
          LPSTR lpszUrlHostName,
          DWORD dwUrlHostNameLength,
          LPSTR * lplpszProxyHostName,
          LPDWORD lpdwProxyHostNameLength
          );
} // extern "C"
#endif // _TRY_JSPROXY

#if _TRY_WM_FINDPROXY
#include <comutil.h>
#include <wmnetsourcecreator.h>
#include <wmsinternaladminnetsource.h>
#endif // _TRY_WM_FINDPROXY

#if _TRY_IE_LAN_SETTINGS
#include <wininet.h>
#include <string>
#endif // _TRY_IE_LAN_SETTINGS

namespace txmpp {

//////////////////////////////////////////////////////////////////////
// Utility Functions
//////////////////////////////////////////////////////////////////////

#ifdef WIN32
#ifdef _UNICODE

typedef std::wstring tstring;
std::string Utf8String(const tstring& str) { return ToUtf8(str); }

#else  // !_UNICODE

typedef std::string tstring;
std::string Utf8String(const tstring& str) { return str; }

#endif  // !_UNICODE
#endif  // WIN32

bool ProxyItemMatch(const Url<char>& url, char * item, size_t len) {
  // hostname:443
  if (char * port = ::strchr(item, ':')) {
    *port++ = '\0';
    if (url.port() != atol(port)) {
      return false;
    }
  }

  // A.B.C.D or A.B.C.D/24
  int a, b, c, d, m;
  int match = sscanf(item, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &m);
  if (match >= 4) {
    uint32 ip = ((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) |
        (d & 0xFF);
    if ((match < 5) || (m > 32))
      m = 32;
    else if (m < 0)
      m = 0;
    uint32 mask = (m == 0) ? 0 : (~0UL) << (32 - m);
    SocketAddress addr(url.host(), 0);
    return !addr.IsUnresolved() && ((addr.ip() & mask) == (ip & mask));
  }

  // .foo.com
  if (*item == '.') {
    size_t hostlen = url.host().length();
    return (hostlen > len)
        && (stricmp(url.host().c_str() + (hostlen - len), item) == 0);
  }

  // localhost or www.*.com
  if (!string_match(url.host().c_str(), item))
    return false;

  return true;
}

bool ProxyListMatch(const Url<char>& url, const std::string& proxy_list,
                    char sep) {
  const size_t BUFSIZE = 256;
  char buffer[BUFSIZE];
  const char* list = proxy_list.c_str();
  while (*list) {
    // Remove leading space
    if (isspace(*list)) {
      ++list;
      continue;
    }
    // Break on separator
    size_t len;
    const char * start = list;
    if (const char * end = ::strchr(list, sep)) {
      len = (end - list);
      list += len + 1;
    } else {
      len = strlen(list);
      list += len;
    }
    // Remove trailing space
    while ((len > 0) && isspace(start[len-1]))
      --len;
    // Check for oversized entry
    if (len >= BUFSIZE)
      continue;
    memcpy(buffer, start, len);
    buffer[len] = 0;
    if (!ProxyItemMatch(url, buffer, len))
      continue;
    return true;
  }
  return false;
}

bool Better(ProxyType lhs, const ProxyType rhs) {
  // PROXY_NONE, PROXY_HTTPS, PROXY_SOCKS5, PROXY_UNKNOWN
  const int PROXY_VALUE[5] = { 0, 2, 3, 1 };
  return (PROXY_VALUE[lhs] > PROXY_VALUE[rhs]);
}

bool ParseProxy(const std::string& saddress, ProxyInfo* proxy) {
  const size_t kMaxAddressLength = 1024;
  // Allow semicolon, space, or tab as an address separator
  const char* const kAddressSeparator = " ;\t";

  ProxyType ptype;
  std::string host;
  uint16 port;

  const char* address = saddress.c_str();
  while (*address) {
    size_t len;
    const char * start = address;
    if (const char * sep = strchr(address, kAddressSeparator)) {
      len = (sep - address);
      address += len + 1;
      while (::strchr(kAddressSeparator, *address)) {
        address += 1;
      }
    } else {
      len = strlen(address);
      address += len;
    }

    if (len > kMaxAddressLength - 1) {
      LOG(LS_WARNING) << "Proxy address too long [" << start << "]";
      continue;
    }

    char buffer[kMaxAddressLength];
    memcpy(buffer, start, len);
    buffer[len] = 0;

    char * colon = ::strchr(buffer, ':');
    if (!colon) {
      LOG(LS_WARNING) << "Proxy address without port [" << buffer << "]";
      continue;
    }

    *colon = 0;
    char * endptr;
    port = static_cast<uint16>(strtol(colon + 1, &endptr, 0));
    if (*endptr != 0) {
      LOG(LS_WARNING) << "Proxy address with invalid port [" << buffer << "]";
      continue;
    }

    if (char * equals = ::strchr(buffer, '=')) {
      *equals = 0;
      host = equals + 1;
      if (_stricmp(buffer, "socks") == 0) {
        ptype = PROXY_SOCKS5;
      } else if (_stricmp(buffer, "https") == 0) {
        ptype = PROXY_HTTPS;
      } else {
        LOG(LS_WARNING) << "Proxy address with unknown protocol ["
                        << buffer << "]";
        ptype = PROXY_UNKNOWN;
      }
    } else {
      host = buffer;
      ptype = PROXY_UNKNOWN;
    }

    if (Better(ptype, proxy->type)) {
      proxy->type = ptype;
      proxy->address.SetIP(host);
      proxy->address.SetPort(port);
    }
  }

  return proxy->type != PROXY_NONE;
}

UserAgent GetAgent(const char* agent) {
  if (agent) {
    std::string agent_str(agent);
    if (agent_str.find(kFirefoxPattern) != std::string::npos) {
      return UA_FIREFOX;
    } else if (agent_str.find(kInternetExplorerPattern) != std::string::npos) {
      return UA_INTERNETEXPLORER;
    } else if (agent_str.empty()) {
      return UA_UNKNOWN;
    }
  }
  return UA_OTHER;
}

bool EndsWith(const std::string& a, const std::string& b) {
  if (b.size() > a.size()) {
    return false;
  }
  int result = a.compare(a.size() - b.size(), b.size(), b);
  return result == 0;
}

bool GetFirefoxProfilePath(Pathname* path) {

  return false;
}

bool GetDefaultFirefoxProfile(Pathname* profile_path) {
  ASSERT(NULL != profile_path);
  Pathname path;
  if (!GetFirefoxProfilePath(&path)) {
    return false;
  }

  return true;
}

bool ReadFirefoxPrefs(const Pathname& filename,
                      const char * prefix,
                      StringMap* settings) {

  
  return false;
}

bool GetFirefoxProxySettings(const char* url, ProxyInfo* proxy) {
  Url<char> purl(url);
  Pathname path;
  bool success = false;
  if (GetDefaultFirefoxProfile(&path)) {
    StringMap settings;
    path.SetFilename("prefs.js");
    if (ReadFirefoxPrefs(path, "network.proxy.", &settings)) {
      success = true;
      proxy->bypass_list =
          settings.Get("no_proxies_on", "localhost, 127.0.0.1");
      if (settings.Get("type") == "1") {
        // User has manually specified a proxy, try to figure out what
        // type it is.
        if (ProxyListMatch(purl, proxy->bypass_list.c_str(), ',')) {
          // Our url is in the list of url's to bypass proxy.
        } else if (settings.Get("share_proxy_settings") == "true") {
          proxy->type = PROXY_UNKNOWN;
          proxy->address.SetIP(settings.Get("http"));
          proxy->address.SetPort(atoi(settings.Get("http_port").c_str()));
        } else if (settings.IsSet("socks")) {
          proxy->type = PROXY_SOCKS5;
          proxy->address.SetIP(settings.Get("socks"));
          proxy->address.SetPort(atoi(settings.Get("socks_port").c_str()));
        } else if (settings.IsSet("ssl")) {
          proxy->type = PROXY_HTTPS;
          proxy->address.SetIP(settings.Get("ssl"));
          proxy->address.SetPort(atoi(settings.Get("ssl_port").c_str()));
        } else if (settings.IsSet("http")) {
          proxy->type = PROXY_HTTPS;
          proxy->address.SetIP(settings.Get("http"));
          proxy->address.SetPort(atoi(settings.Get("http_port").c_str()));
        }
      } else if (settings.Get("type") == "2") {
        // Browser is configured to get proxy settings from a given url.
        proxy->autoconfig_url = settings.Get("autoconfig_url").c_str();
      } else if (settings.Get("type") == "4") {
        // Browser is configured to auto detect proxy config.
        proxy->autodetect = true;
      } else {
        // No proxy set.
      }
    }
  }
  return success;
}

bool AutoDetectProxySettings(const char* agent, const char* url,
                             ProxyInfo* proxy) {
#ifdef WIN32
  return WinHttpAutoDetectProxyForUrl(agent, url, proxy);
#else
  LOG(LS_WARNING) << "Proxy auto-detection not implemented for this platform";
  return false;
#endif
}

bool GetSystemDefaultProxySettings(const char* agent, const char* url,
                                   ProxyInfo* proxy) {
#ifdef WIN32
  return GetIeProxySettings(agent, url, proxy);
#elif OSX
  return GetMacProxySettings(proxy);
#else
  // TODO(oja): Get System settings if browser is not firefox.
  return GetFirefoxProxySettings(url, proxy);
#endif
}

bool GetProxySettingsForUrl(const char* agent, const char* url,
                            ProxyInfo& proxy, bool long_operation) {
  UserAgent a = GetAgent(agent);
  bool result;
  switch (a) {
    case UA_FIREFOX: {
      result = GetFirefoxProxySettings(url, &proxy);
      break;
    }
#ifdef WIN32
    case UA_INTERNETEXPLORER:
      result = GetIeProxySettings(agent, url, &proxy);
      break;
    case UA_UNKNOWN:
      // Agent not defined, check default browser.
      if (IsDefaultBrowserFirefox()) {
        result = GetFirefoxProxySettings(url, &proxy);
      } else {
        result = GetIeProxySettings(agent, url, &proxy);
      }
      break;
#endif  // WIN32
    default:
      result = GetSystemDefaultProxySettings(agent, url, &proxy);
      break;
  }

  // TODO(oja): Consider using the 'long_operation' parameter to
  // decide whether to do the auto detection.
  if (result && (proxy.autodetect ||
                 !proxy.autoconfig_url.empty())) {
    // Use WinHTTP to auto detect proxy for us.
    result = AutoDetectProxySettings(agent, url, &proxy);
    if (!result) {
      // Either auto detection is not supported or we simply didn't
      // find any proxy, reset type.
      proxy.type = txmpp::PROXY_NONE;
    }
  }
  return result;
}

}  // namespace txmpp
