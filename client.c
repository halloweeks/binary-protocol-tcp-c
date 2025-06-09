#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "protocol_version.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 1024

const char *base_name(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash != NULL ? last_slash + 1 : path;
}

typedef struct {
	uint16_t packet_id;
	uint16_t version;
} __attribute__ ((packed)) packet_header_t;

// Request packet types sent from client to server
typedef enum {
    REQ_LOGIN = 0x0001,   // Login request packet (ID = 1)
    REQ_REGISTER = 0x0002, // Register request packet (ID 2)
} req_packet_t;

// Response packet types sent from server to client
typedef enum {
    RES_LOGIN = 0x8001,   // Login response packet (ID = 0x8001 = 32769)
    RES_REGISTER = 0x8002, // Register response packet (ID = 0x8002 = 32770)
} res_packet_t;

typedef struct {
	char username[255];
	char password[255];
} login_info;

typedef struct {
	int status_code;
	uint8_t session_id[16];
} __attribute__ ((packed)) login_result_t;


typedef enum {
    STATUS_OK = 0,
    
    // Login-specific errors
    STATUS_LOGIN_FAILED = -1,
    STATUS_LOGIN_USER_NOT_FOUND = -2,
    STATUS_LOGIN_WRONG_PASSWORD = -3,
    STATUS_LOGIN_TOO_MANY_ATTEMPTS = -4,
    STATUS_LOGIN_ACCOUNT_LOCKED = -5,
    
    // Protocol errors
    STATUS_PROTOCOL_MISMATCH = -100,
    STATUS_INVALID_RESPONSE = -101,
    STATUS_UNEXPECTED_PACKET_ID = -102,

    // System errors
    STATUS_NETWORK_ERROR = -200,
    STATUS_TIMEOUT = -201,
    STATUS_UNKNOWN_ERROR = -202

} status_code_t;

bool is_valid_status(status_code_t code) {
    switch (code) {
        case STATUS_OK:
        case STATUS_LOGIN_FAILED:
        case STATUS_LOGIN_USER_NOT_FOUND:
        case STATUS_LOGIN_WRONG_PASSWORD:
        case STATUS_LOGIN_TOO_MANY_ATTEMPTS:
        case STATUS_LOGIN_ACCOUNT_LOCKED:
        case STATUS_PROTOCOL_MISMATCH:
        case STATUS_INVALID_RESPONSE:
        case STATUS_UNEXPECTED_PACKET_ID:
        case STATUS_NETWORK_ERROR:
        case STATUS_TIMEOUT:
        case STATUS_UNKNOWN_ERROR:
            return true;
        default:
            return false;
    }
}

login_result_t api_request_login_v1(int sock, const char *username, const char *password) {
	int status;
	packet_header_t req_header, res_header;
	login_result_t res = {0};
	
	uint8_t user_len = strlen(username);
	uint8_t pass_len = strlen(password);
	
	req_header.packet_id = REQ_LOGIN;
	req_header.version = MAKE_VERSION(1, 0);
	
	// write request headers
	if (send(sock, &req_header, sizeof(req_header), 0) != sizeof(req_header)) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write username length 1 byte
	if (send(sock, &user_len, 1, 0) != 1) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// send username byte
	if (send(sock, username, user_len, 0) != user_len) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write password length 1 byte
	if (send(sock, &pass_len, 1, 0) != 1) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write password byte 
	if (send(sock, password, pass_len, 0) != pass_len) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// read response 
	if (recv(sock, &res_header, sizeof(res_header), 0) != sizeof(res_header)) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	if (res_header.packet_id != RES_LOGIN) {
		res.status_code = STATUS_UNEXPECTED_PACKET_ID;
		return res;
	}
	
	if (res_header.version != PROTOCOL_VERSION) {
		res.status_code = STATUS_PROTOCOL_MISMATCH;
		return res;
	}
	
	if (recv(sock, &status, 4, 0) != 4) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	if (is_valid_status(status)) {
		res.status_code = status;
	} else {
		res.status_code = STATUS_UNKNOWN_ERROR;
	}
	
	if (status == STATUS_OK) {
		if (read(sock, res.session_id, 16) != 16) {
			res.status_code = STATUS_NETWORK_ERROR;
			return res;
		}
	}
	
	return res;
}

const char *get_error_msg(status_code_t code) {
    switch (code) {
        case STATUS_OK: return "Success";
        case STATUS_LOGIN_FAILED: return "Login failed";
        case STATUS_LOGIN_USER_NOT_FOUND: return "User not found";
        case STATUS_LOGIN_WRONG_PASSWORD: return "Wrong password";
        case STATUS_LOGIN_TOO_MANY_ATTEMPTS: return "Too many login attempts";
        case STATUS_LOGIN_ACCOUNT_LOCKED: return "Account is locked";
        case STATUS_PROTOCOL_MISMATCH: return "Protocol version mismatch";
        case STATUS_INVALID_RESPONSE: return "Invalid response from server";
        case STATUS_UNEXPECTED_PACKET_ID: return "Unexpected packet ID";
        case STATUS_NETWORK_ERROR: return "Network error";
        case STATUS_TIMEOUT: return "Connection timeout";
        case STATUS_UNKNOWN_ERROR: return "Unknown error";
        default: return "Unrecognized status code";
    }
}

int connect_server(const char *ip, const unsigned int port) {
	struct sockaddr_in serv_addr;
	
	// Create socket
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) {
		perror("Socket creation error");
		return -1;
	}
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	
	// Convert IPv4 address from text to binary
	if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
		perror("Invalid address or Address not supported");
		return -1;
	}
	
	// Connect to server
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Connection failed");
		return -1;
	}
	
	return sock;
}

typedef int conn_t;

int main(int argc, const char *argv[]) {
	// connection to server!
	conn_t conn = connect_server(SERVER_IP, SERVER_PORT);
	
	if (conn == -1) {
		fprintf(stderr, "Failed to connect server!\n");
		return EXIT_FAILURE;
	}
	
	// make login request to server 
	login_result_t res = api_request_login_v1(conn, "admin", "admin@1234");
	
	if (res.status_code == STATUS_OK) {
		printf("login: successful\nsession_id: ");
		for (uint8_t i = 0; i < 16; i++) {
			printf("%02x", res.session_id[i]);
		}
		printf("\n");
	} else {
		printf("login: failed\nerror: %s\n", get_error_msg(res.status_code));
	}
	
	close(conn);
	return 0;
}