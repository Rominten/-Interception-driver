#pragma once

#define DEVICE_NAME L"\\Device\\InterceptDriver"
#define DEVICE_SYMBOLIC_LINK L"\\??\\InterceptDriver"
#define MY_DEVICE_TYPE 666
#define EVENT_HANDLE_INDEX 1024
#define FILE_HOOK_INDEX 1025
#define IOCTL_EVENT_HANDLE CTL_CODE(MY_DEVICE_TYPE, EVENT_HANDLE_INDEX, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILE_HOOK CTL_CODE(MY_DEVICE_TYPE, FILE_HOOK_INDEX, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BUF_SIZE 1024