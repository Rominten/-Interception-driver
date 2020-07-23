#include <stdio.h>
#include <Windows.h>

#include "../InterceptDriver/IODef.h"

int main()
{
	WCHAR outBuf[BUF_SIZE];
	WCHAR inBuf[BUF_SIZE];
	DWORD bytesWrite;

	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, L"Hook");
	HANDLE device = CreateFile(L"\\\\.\\InterceptDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	int err = GetLastError();

	if (device == INVALID_HANDLE_VALUE)
	{
		printf("Device error: %d\n", err);

		system("pause");

		return 0;
	}

	DeviceIoControl(device, IOCTL_EVENT_HANDLE, &hEvent, sizeof(hEvent), &hEvent, sizeof(hEvent), &bytesWrite, NULL);

	while (1)
	{
		WaitForSingleObject(hEvent, INFINITE);

		DeviceIoControl(device, IOCTL_FILE_HOOK, &inBuf, BUF_SIZE, &outBuf, BUF_SIZE, &bytesWrite, NULL);

		if (bytesWrite == 0)
			continue;

		printf("Get message from driver\n");

		wprintf(outBuf);

		printf("\n\n");
	}

	return 0;
}