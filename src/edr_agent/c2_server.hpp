#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <atomic>
#include <functional>

class C2Server {
public:
    static bool Start(USHORT port = 8443);
    static void Stop();
    static bool IsRunning();
    static USHORT GetPort();

    using RequestHandler = std::function<std::string(const std::string& method,
        const std::string& path, const std::string& body)>;
    static void SetRequestHandler(RequestHandler handler);

private:
    static HANDLE m_thread;
    static std::atomic<bool> m_running;
    static USHORT m_port;
    static RequestHandler m_handler;

    static DWORD WINAPI ServerThread(LPVOID param);
    static void HandleRequest(SOCKET client);
    static std::string BuildHttpResponse(int statusCode, const std::string& contentType,
                                          const std::string& body);
    static bool ParseHttpRequest(const std::string& raw, std::string& method,
                                 std::string& path, std::string& body);
    static std::string UrlDecode(const std::string& encoded);
    static std::string GetMimeType(const std::string& path);
};
