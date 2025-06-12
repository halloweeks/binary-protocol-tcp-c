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

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 8888
#define BUFFER_SIZE 1024

static const uint8_t key[] = "L*#)@!&8";

void xor_cipher(unsigned char *data, unsigned int size, const unsigned char *key, const unsigned int key_len) {
    for (uint32_t i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
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

typedef struct {
	int conn;
	uint8_t sid[16];
} conn_t;


login_result_t api_login_v1(conn_t *c, const char *username, const char *password) {
	int status;
	packet_header_t req_header, res_header;
	login_result_t res = {0};
	
	uint8_t user_len = strlen(username);
	uint8_t pass_len = strlen(password);
	
	req_header.packet_id = REQ_LOGIN;
	req_header.version = PROTOCOL_VERSION;
	
	// write request headers
	if (send(c->conn, &req_header, sizeof(req_header), 0) != sizeof(req_header)) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write username length 1 byte
	if (send(c->conn, &user_len, 1, 0) != 1) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// send username byte
	if (send(c->conn, username, user_len, 0) != user_len) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write password length 1 byte
	if (send(c->conn, &pass_len, 1, 0) != 1) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// write password byte 
	if (send(c->conn, password, pass_len, 0) != pass_len) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	// read response 
	if (recv(c->conn, &res_header, sizeof(res_header), 0) != sizeof(res_header)) {
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
	
	if (recv(c->conn, &status, 4, 0) != 4) {
		res.status_code = STATUS_NETWORK_ERROR;
        return res;
	}
	
	if (is_valid_status(status)) {
		res.status_code = status;
	} else {
		res.status_code = STATUS_UNKNOWN_ERROR;
	}
	
	if (status == STATUS_OK) {
		if (read(c->conn, res.session_id, 16) == 16) {
			memcpy(c->sid, res.session_id, 16);
		} else {
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



conn_t connect_server(const char *ip, const unsigned int port) {
	conn_t c = { .conn = -1 };  // Default to invalid
	
	struct sockaddr_in serv_addr;
	
	// Create socket
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) {
		perror("Socket creation error");
		return c;
	}
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	
	// Convert IPv4 address from text to binary
	if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
		perror("Invalid address or Address not supported");
		return c;
	}
	
	// Connect to server
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Connection failed");
		return c;
	}
	
	c.conn = sock;
	return c;
}

bool is_connected(const conn_t *c) {
    return c != NULL && c->conn != -1;
}

bool conn_close(conn_t *c) {
    if (c != NULL && c->conn != -1) {
        close(c->conn);
        c->conn = -1;  // Invalidate socket
        return true;
    }
    return false;  // Nothing to close
}

// typedef int conn_t;

void print_sid(const uint8_t *sid) {
	printf("sid: ");
	for (uint8_t i = 0; i < 16; i++) {
		printf("%02x", sid[i]);
	}
	printf("\n");
}

int main(int argc, const char *argv[]) {
	// connection to server!
	conn_t conn = connect_server("127.0.0.1", 8888);
	
	if (!is_connected(&conn)) {
		fprintf(stderr, "Failed to connect server!\n");
		return EXIT_FAILURE;
	}
	
	login_result_t res = api_login_v1(&conn, "admin", "admin@1234");
	
	if (res.status_code == STATUS_OK) {
		printf("logged successful\n");
		print_sid(res.session_id);
		print_sid(conn.sid);
	} else {
		printf("login: failed\nerror: %s\n", get_error_msg(res.status_code));
	}
	
	conn_close(&conn);
	return 0;
}
