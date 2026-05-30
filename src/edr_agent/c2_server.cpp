#include "c2_server.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")

HANDLE C2Server::m_thread = NULL;
std::atomic<bool> C2Server::m_running{false};
USHORT C2Server::m_port = 8443;
C2Server::RequestHandler C2Server::m_handler = nullptr;

bool C2Server::Start(USHORT port) {
    if (m_running) return true;
    m_port = port;
    m_running = true;
    m_thread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    return m_thread != NULL;
}

void C2Server::Stop() {
    m_running = false;
    if (m_thread) {
        WaitForSingleObject(m_thread, 5000);
        CloseHandle(m_thread);
        m_thread = NULL;
    }
}

bool C2Server::IsRunning() {
    return m_running;
}

USHORT C2Server::GetPort() {
    return m_port;
}

void C2Server::SetRequestHandler(RequestHandler handler) {
    m_handler = handler;
}

std::string C2Server::UrlDecode(const std::string& encoded) {
    std::string result;
    for (size_t i = 0; i < encoded.size(); i++) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            int hi = encoded[i + 1];
            int lo = encoded[i + 2];
            hi = (hi >= 'a' ? hi - 'a' + 10 : hi >= 'A' ? hi - 'A' + 10 : hi - '0');
            lo = (lo >= 'a' ? lo - 'a' + 10 : lo >= 'A' ? lo - 'A' + 10 : lo - '0');
            result += (char)((hi << 4) | lo);
            i += 2;
        } else if (encoded[i] == '+') {
            result += ' ';
        } else {
            result += encoded[i];
        }
    }
    return result;
}

std::string C2Server::GetMimeType(const std::string& path) {
    if (path == "/" || path.empty()) return "text/html";
    if (path.find(".html") != std::string::npos) return "text/html";
    if (path.find(".json") != std::string::npos) return "application/json";
    if (path.find(".css") != std::string::npos) return "text/css";
    if (path.find(".js") != std::string::npos) return "application/javascript";
    return "text/plain";
}

bool C2Server::ParseHttpRequest(const std::string& raw, std::string& method,
                                 std::string& path, std::string& body) {
    std::istringstream iss(raw);
    std::string line;
    if (!std::getline(iss, line)) return false;

    std::istringstream lineStream(line);
    lineStream >> method >> path;

    size_t bodyStart = raw.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        body = raw.substr(bodyStart + 4);
    }

    path = UrlDecode(path);
    size_t queryPos = path.find('?');
    if (queryPos != std::string::npos) {
        path = path.substr(0, queryPos);
    }

    return !method.empty() && !path.empty();
}

std::string C2Server::BuildHttpResponse(int statusCode, const std::string& contentType,
                                         const std::string& body) {
    std::ostringstream oss;
    std::string statusText = (statusCode == 200) ? "OK" :
                             (statusCode == 404) ? "Not Found" :
                             (statusCode == 400) ? "Bad Request" :
                             (statusCode == 500) ? "Internal Server Error" : "Unknown";

    oss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    oss << "Content-Type: " << contentType << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

void C2Server::HandleRequest(SOCKET client) {
    char buf[65536];
    int received = recv(client, buf, sizeof(buf) - 1, 0);
    if (received <= 0) {
        closesocket(client);
        return;
    }
    buf[received] = 0;
    std::string raw(buf);

    std::string method, path, body;
    if (!ParseHttpRequest(raw, method, path, body)) {
        std::string resp = BuildHttpResponse(400, "text/plain", "Bad Request");
        send(client, resp.c_str(), (int)resp.size(), 0);
        closesocket(client);
        return;
    }

    std::string responseBody;

    if (path == "/" || path.empty()) {
        std::ostringstream html;
        html << "<!DOCTYPE html><html><head><title>AKIR-DKES Node</title>"
             << "<style>body{font-family:monospace;background:#0a0a0a;color:#00ff88;"
             << "padding:20px;max-width:800px;margin:auto}h1{border-bottom:1px solid #00ff88}"
             << ".status{color:#0f0}.info{padding:10px;background:#111;border-radius:4px}"
             << "a{color:#00ff88}</style></head><body>"
             << "<h1>AKIR-DKES Node</h1>"
             << "<div class='info'>"
             << "<p><strong>Port:</strong> " << m_port << "</p>"
             << "<p><strong>Status:</strong> <span class='status'>Online</span></p>"
             << "</div>"
             << "<h2>API Endpoints</h2>"
             << "<ul>"
             << "<li><a href='/api/state'>/api/state</a> - Node status</li>"
             << "<li><a href='/api/peer/list'>/api/peer/list</a> - Peer list</li>"
             << "<li><a href='/api/backup'>/api/backup</a> - Trigger backup</li>"
             << "<li><a href='/api/restore'>/api/restore</a> - Trigger restore</li>"
             << "</ul>"
             << "</body></html>";
        responseBody = html.str();
    } else if (path == "/api/state") {
        responseBody = "{\"status\":\"online\",\"port\":" + std::to_string(m_port) + ",\"version\":\"1.2.0\"}";
    } else if (path == "/api/peer/list") {
        responseBody = "{\"peers\":[]}";
    } else if (path == "/api/backup" || path == "/api/restore" ||
               path == "/api/peer/announce" || path == "/api/peer/shard" ||
               path == "/api/attest") {
        if (m_handler) {
            responseBody = m_handler(method, path, body);
        } else {
            responseBody = "{\"error\":\"no handler registered\"}";
        }
    } else {
        responseBody = "{\"error\":\"not found\"}";
    }

    std::string contentType = (path.find("/api/") == 0) ? "application/json" : "text/html";
    std::string resp = BuildHttpResponse(200, contentType, responseBody);
    send(client, resp.c_str(), (int)resp.size(), 0);
    closesocket(client);
}

DWORD WINAPI C2Server::ServerThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) return 1;

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(m_port);

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(server);
        WSACleanup();
        return 1;
    }

    listen(server, SOMAXCONN);

    fd_set readSet;
    TIMEVAL timeout = { 1, 0 };

    while (m_running) {
        FD_ZERO(&readSet);
        FD_SET(server, &readSet);
        int result = select(0, &readSet, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(server, &readSet)) {
            sockaddr_in clientAddr;
            int clientLen = sizeof(clientAddr);
            SOCKET client = accept(server, (sockaddr*)&clientAddr, &clientLen);
            if (client != INVALID_SOCKET) {
                HandleRequest(client);
            }
        }
    }

    closesocket(server);
    WSACleanup();
    return 0;
}
