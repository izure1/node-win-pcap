#include <node_api.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

// Helper to throw a more detailed Winsock error
void ThrowWinsockError(napi_env env, const char* message) {
    char full_message[256];
    int error_code = WSAGetLastError();
    // Use _snprintf_s for safety on Windows
    _snprintf_s(full_message, sizeof(full_message), _TRUNCATE, "%s. Winsock error: %d", message, error_code);
    napi_throw_error(env, nullptr, full_message);
}

// Create a pcap for Windows
napi_value CreateNodeWinPcap(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 1;
    napi_value args[1];
    napi_value result;

    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc < 1) {
        napi_throw_error(env, nullptr, "An IP address string for the local interface is required");
        return nullptr;
    }

    char ip_address[16];
    size_t ip_address_len;
    status = napi_get_value_string_utf8(env, args[0], ip_address, sizeof(ip_address), &ip_address_len);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to parse IP address string");
        return nullptr;
    }

    // Create a RAW socket. On Windows, the handle type is SOCKET.
    // IPPROTO_IP is required for SIO_RCVALL to work.
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    
    // On Windows, socket() returns INVALID_SOCKET on failure.
    if (sock == INVALID_SOCKET) {
        ThrowWinsockError(env, "Failed to create raw socket");
        return nullptr;
    }

    // Increase socket buffer size
    int bufsize = 65536 * 4; // 256KB
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize)) == SOCKET_ERROR) {
        ThrowWinsockError(env, "Failed to set receive buffer size");
        closesocket(sock);
        return nullptr;
    }

    // Bind the socket to the specified local interface. This is required for SIO_RCVALL.
    struct sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(ip_address);
    service.sin_port = 0;

    if (bind(sock, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR) {
        ThrowWinsockError(env, "Failed to bind socket");
        closesocket(sock);
        return nullptr;
    }

    // Set the socket to promiscuous mode (receive all packets).
    // This requires Administrator privileges.
    int value = RCVALL_IPLEVEL;
    DWORD dwBytesReturned = 0;
    if (WSAIoctl(sock, SIO_RCVALL, &value, sizeof(value), NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
        ThrowWinsockError(env, "WSAIoctl failed (SIO_RCVALL). Make sure to run with Administrator privileges.");
        closesocket(sock);
        return nullptr;
    }
    
    // Return the socket descriptor as a 64-bit number for compatibility (SOCKET is UINT_PTR)
    status = napi_create_int64(env, (int64_t)sock, &result);
    if (status != napi_ok) {
        closesocket(sock);
        napi_throw_error(env, nullptr, "Failed to create return value for socket handle");
        return nullptr;
    }
    
    return result;
}

// Helper function to parse IP header and return IP strings
struct IPHeaderInfo {
    std::string sourceIP;
    std::string destIP;
    int headerLength;
    int protocol;
    int sourcePort;
    int destPort;
};

IPHeaderInfo ParseIPHeader(const char* buffer, int buffer_len) {
    IPHeaderInfo info;
    info.sourceIP = "";
    info.destIP = "";
    info.headerLength = 0;
    info.protocol = 0;
    info.sourcePort = 0;
    info.destPort = 0;

    if (buffer_len < 20) { // Minimum IP header length
        return info;
    }

    // IP Header Length is in 4-byte words, so multiply by 4
    info.headerLength = (buffer[0] & 0x0F) * 4;
    info.protocol = buffer[9]; // Protocol field

    // Source IP (bytes 12-15)
    char src_ip_str[INET_ADDRSTRLEN];
    sprintf_s(src_ip_str, sizeof(src_ip_str), "%d.%d.%d.%d",
              (unsigned char)buffer[12], (unsigned char)buffer[13],
              (unsigned char)buffer[14], (unsigned char)buffer[15]);
    info.sourceIP = src_ip_str;

    // Destination IP (bytes 16-19)
    char dest_ip_str[INET_ADDRSTRLEN];
    sprintf_s(dest_ip_str, sizeof(dest_ip_str), "%d.%d.%d.%d",
              (unsigned char)buffer[16], (unsigned char)buffer[17],
              (unsigned char)buffer[18], (unsigned char)buffer[19]);
    info.destIP = dest_ip_str;

    // Check if it's TCP or UDP to parse ports
    if (info.protocol == 6 /* TCP */ || info.protocol == 17 /* UDP */) {
        if (buffer_len >= info.headerLength + 4) { // Check for transport header
            const char* transportHeader = buffer + info.headerLength;
            // Source Port (first 2 bytes of transport header)
            info.sourcePort = ntohs(*(unsigned short*)transportHeader);
            // Destination Port (next 2 bytes of transport header)
            info.destPort = ntohs(*(unsigned short*)(transportHeader + 2));
        }
    }

    return info;
}

napi_value ReceivePacket(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 3; // Expect socket, source_filter, dest_filter
    napi_value args[3];
    
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok || argc < 3) {
        napi_throw_error(env, nullptr, "Expected 3 arguments: socket, source_ip_filter, dest_ip_filter");
        return nullptr;
    }
    
    // Get the socket descriptor as a 64-bit integer
    int64_t sock_handle;
    status = napi_get_value_int64(env, args[0], &sock_handle);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to parse socket handle. Expected a 64-bit integer.");
        return nullptr;
    }
    SOCKET sock = (SOCKET)sock_handle;

    // Get filter strings
    char source_filter_buf[256];
    size_t source_filter_len;
    status = napi_get_value_string_utf8(env, args[1], source_filter_buf, sizeof(source_filter_buf), &source_filter_len);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to parse source_ip_filter string.");
        return nullptr;
    }
    std::string source_ip_filter_str(source_filter_buf, source_filter_len);

    char dest_filter_buf[256];
    size_t dest_filter_len;
    status = napi_get_value_string_utf8(env, args[2], dest_filter_buf, sizeof(dest_filter_buf), &dest_filter_len);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to parse dest_ip_filter string.");
        return nullptr;
    }
    std::string dest_ip_filter_str(dest_filter_buf, dest_filter_len);
    
    // Receive a packet
    char buffer[65536]; // Max IP packet size
    struct sockaddr_in addr;
    int addr_len = sizeof(addr); // Use int for socklen_t on Windows
    
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&addr, &addr_len);
    
    if (bytes_received == SOCKET_ERROR) {
        // If no packet received (e.g., timeout or error), return null
        if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK) {
            napi_value null_val;
            napi_get_null(env, &null_val);
            return null_val;
        }
        ThrowWinsockError(env, "Failed to receive packet");
        return nullptr;
    }
    
    // Parse IP header
    IPHeaderInfo ipHeader = ParseIPHeader(buffer, bytes_received);

    // Apply filtering
    bool source_match = source_ip_filter_str.empty() || 
                        (ipHeader.sourceIP.length() >= source_ip_filter_str.length() &&
                         ipHeader.sourceIP.rfind(source_ip_filter_str, 0) == 0); // startsWith
    
    bool dest_match = dest_ip_filter_str.empty() ||
                      (ipHeader.destIP.length() >= dest_ip_filter_str.length() &&
                       ipHeader.destIP.rfind(dest_ip_filter_str, 0) == 0); // startsWith

    if (!source_match || !dest_match) {
        // If filters don't match, return null
        napi_value null_val;
        napi_get_null(env, &null_val);
        return null_val;
    }

    // Create a result object
    napi_value result, data, source_ip_napi, dest_ip_napi, length, ip_header_obj;
    status = napi_create_object(env, &result);
    if (status != napi_ok) return nullptr;
    
    // Convert packet data to a Buffer
    void* buffer_data;
    status = napi_create_buffer_copy(env, bytes_received, buffer, &buffer_data, &data);
    if (status != napi_ok) return nullptr;
    
    // Source IP address
    napi_create_string_utf8(env, ipHeader.sourceIP.c_str(), NAPI_AUTO_LENGTH, &source_ip_napi);
    // Destination IP address
    napi_create_string_utf8(env, ipHeader.destIP.c_str(), NAPI_AUTO_LENGTH, &dest_ip_napi);
    
    // Packet length
    napi_create_int32(env, bytes_received, &length);

    // Create IP header object
    status = napi_create_object(env, &ip_header_obj);
    if (status != napi_ok) return nullptr;
    napi_set_named_property(env, ip_header_obj, "sourceIP", source_ip_napi);
    napi_set_named_property(env, ip_header_obj, "destIP", dest_ip_napi);

    napi_value source_port_napi, dest_port_napi;
    napi_create_int32(env, ipHeader.sourcePort, &source_port_napi);
    napi_create_int32(env, ipHeader.destPort, &dest_port_napi);
    napi_set_named_property(env, ip_header_obj, "sourcePort", source_port_napi);
    napi_set_named_property(env, ip_header_obj, "destPort", dest_port_napi);
    
    napi_value protocol_napi;
    napi_create_int32(env, ipHeader.protocol, &protocol_napi);
    napi_set_named_property(env, ip_header_obj, "protocol", protocol_napi);

    napi_value header_length_napi;
    napi_create_int32(env, ipHeader.headerLength, &header_length_napi);
    napi_set_named_property(env, ip_header_obj, "headerLength", header_length_napi);

    // Add properties to the object
    napi_set_named_property(env, result, "data", data);
    napi_set_named_property(env, result, "length", length);
    napi_set_named_property(env, result, "ipHeader", ip_header_obj); // Attach parsed IP header

    return result;
}

napi_value CloseSocket(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 1;
    napi_value args[1];
    
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (status != napi_ok) return nullptr;
    
    // Get the socket descriptor as a 64-bit integer
    int64_t sock_handle;
    status = napi_get_value_int64(env, args[0], &sock_handle);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to parse socket handle. Expected a 64-bit integer.");
        return nullptr;
    }
    SOCKET sock = (SOCKET)sock_handle;
    
    // Turn off promiscuous mode before closing the socket
    DWORD dwBufferIn = 0;
    DWORD dwBytesReturned = 0;
    if (WSAIoctl(sock, SIO_RCVALL, &dwBufferIn, sizeof(dwBufferIn), NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
        // Log a warning, but don't stop the closing process
    }
    
    if (closesocket(sock) == SOCKET_ERROR) {
        ThrowWinsockError(env, "Failed to close socket");
        return nullptr;
    }
    
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// Cleanup hook to be called when the environment is torn down
void Cleanup(void* arg) {
    WSACleanup();
}

napi_value Init(napi_env env, napi_value exports) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        napi_throw_error(env, nullptr, "WSAStartup failed");
        return nullptr;
    }
    // Register a cleanup hook to call WSACleanup when the addon is unloaded
    napi_add_env_cleanup_hook(env, Cleanup, nullptr);

    napi_status status;
    napi_value fn;
    
    // Register the createNodeWinPcap function
    status = napi_create_function(env, nullptr, 0, CreateNodeWinPcap, nullptr, &fn);
    if (status != napi_ok) return nullptr;
    status = napi_set_named_property(env, exports, "createNodeWinPcap", fn);
    if (status != napi_ok) return nullptr;
    
    // Register the receivePacket function
    status = napi_create_function(env, nullptr, 0, ReceivePacket, nullptr, &fn);
    if (status != napi_ok) return nullptr;
    status = napi_set_named_property(env, exports, "receivePacket", fn);
    if (status != napi_ok) return nullptr;
    
    // Register the closeSocket function
    status = napi_create_function(env, nullptr, 0, CloseSocket, nullptr, &fn);
    if (status != napi_ok) return nullptr;
    status = napi_set_named_property(env, exports, "closeSocket", fn);
    if (status != napi_ok) return nullptr;
    
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
