/*
 * main.c
 * Copyright (C) 2015, basil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <commctrl.h>

#include "domain.h"
#include "main.h"
#include "redirect.h"

// GUI parameters:
#define STATUS_TOR_ON_COLOR         RGB(196, 255, 196)
#define STATUS_TOR_OFF_COLOR        RGB(255, 196, 196)
#define BUTTON_OFFSET_X             10
#define BUTTON_OFFSET_Y             10
#define BUTTON_SIZE_X               138
#define BUTTON_SIZE_Y               138
#define WINDOW_SIZE_X               \
    (10 + 2 * BUTTON_SIZE_X + 3 * BUTTON_OFFSET_X)
#define WINDOW_SIZE_Y               \
    (50 + BUTTON_SIZE_Y + 2 * BUTTON_OFFSET_Y)
#define TOR_ON_MESSAGE              "Tor divert is ON"
#define TOR_OFF_MESSAGE             "Tor divert is OFF"
#define ID_TOR_BUTTON               3100
#define ID_DIRECT_CHECK             3101
#define ID_WEB_CHECK                3102

// Prototypes:
static DWORD WINAPI tor_thread(LPVOID arg);
static DWORD WINAPI cleanup_thread(DWORD arg);
static void save_option(const char *option, bool val0);
static bool restore_option(const char *option);


// The GUI:
static HWND button = NULL;
static HWND status_bar = NULL;
static HWND status_label = NULL;

// Tor state:
static bool state = false;

// Options:
#define OPTION_FORCE_WEB_ONLY       "ForceWebOnly"
#define OPTION_FORCE_SOCKS4a_ONLY   "ForceSOCKS4aOnly"
bool option_force_web_only = true;
bool option_force_socks4a  = true;

// Start/stop Tor:
static void start_tor(void)
{
    state = true;
    redirect_start();
    SetWindowText(status_label, TOR_ON_MESSAGE);
    status(TOR_ON_MESSAGE);
}

static void stop_tor(void)
{
    state = false;
    redirect_stop();
    SetWindowText(status_label, TOR_OFF_MESSAGE);
    status(TOR_OFF_MESSAGE);
}

// Tor SOCKS4a config control:
static WNDPROC config_proc0 = NULL;
static LRESULT CALLBACK config_proc(HWND hwnd, UINT msg, WPARAM wparam,
    LPARAM lparam)
{
    switch (msg)
    {
        case WM_COMMAND:
        {
            int event = HIWORD(wparam);
            if (event == BN_CLICKED)
            {
                LRESULT state = SendMessage((HWND)lparam, BM_GETCHECK, 0, 0);
                switch (LOWORD(wparam))
                {
                    case ID_DIRECT_CHECK:
                        option_force_socks4a = (state == BST_CHECKED);
                        save_option(OPTION_FORCE_SOCKS4a_ONLY,
                            option_force_socks4a);
                        break;
                    case ID_WEB_CHECK:
                        option_force_web_only = (state == BST_CHECKED);
                        save_option(OPTION_FORCE_WEB_ONLY,
                            option_force_web_only);
                        break;
                    default:
                        break;
                }
            }
            break;
        }
        default:
            break;
    }
    return CallWindowProc(config_proc0, hwnd, msg, wparam, lparam);
}

// Tor status control:
static WNDPROC status_proc0 = NULL;
static LRESULT CALLBACK status_proc(HWND hwnd, UINT msg, WPARAM wparam,
    LPARAM lparam)
{
    switch (msg)
    {
        case WM_CTLCOLORSTATIC:
        {
            HDC hdc = (HDC)wparam;
            if (state)
            {
                SetBkColor(hdc, STATUS_TOR_ON_COLOR);
                SetDCBrushColor(hdc, STATUS_TOR_ON_COLOR);
            }
            else
            {
                SetBkColor(hdc, STATUS_TOR_OFF_COLOR);
                SetDCBrushColor(hdc, STATUS_TOR_OFF_COLOR);
            }
            return (LRESULT)GetStockObject(DC_BRUSH);
        }
        default:
            break;
    }
    return CallWindowProc(status_proc0, hwnd, msg, wparam, lparam);
}

// Window control:
LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch(msg)
    {
        case WM_CREATE:
        {
            InitCommonControls();

            // (1) Create the big Tor button:
            HINSTANCE instance = (HINSTANCE)GetWindowLong(hwnd,
                GWLP_HINSTANCE);
            button = CreateWindow(
                "BUTTON", "Tor",
                BS_ICON | BS_AUTOCHECKBOX | BS_PUSHLIKE | WS_CHILD | WS_VISIBLE,
                BUTTON_OFFSET_X, BUTTON_OFFSET_Y,
                BUTTON_SIZE_X, BUTTON_SIZE_Y,
                hwnd, (HMENU)ID_TOR_BUTTON, instance, NULL);
            if (button == NULL)
                goto gui_init_failed;
            HICON image = LoadImage(GetModuleHandle(NULL), "TOR_ICON",
                IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
            if (image == NULL)
                goto gui_init_failed;
            SendMessage(button, BM_SETIMAGE, (WPARAM)IMAGE_ICON,
                (LPARAM)image);
            EnableWindow(button, FALSE);
            

            // (2) Create the status bar:
            status_bar = CreateWindow(
                STATUSCLASSNAME, "Starting...",
                WS_CHILD | WS_VISIBLE | SBT_TOOLTIPS,
                0, 0, 0, 0, hwnd, NULL, instance, NULL);
            if (status_bar == NULL)
                goto gui_init_failed;

            // (3) Create the status box:
            size_t status_offset_x = 2 * BUTTON_OFFSET_X + BUTTON_SIZE_X,
                   status_offset_y = BUTTON_OFFSET_Y;
            size_t status_size_x = BUTTON_SIZE_X, status_size_y = 45;
            HWND status_box = CreateWindow(
                "BUTTON", "Status",
                WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | BS_GROUPBOX,
                status_offset_x, status_offset_y,
                status_size_x, status_size_y, hwnd, NULL, instance, NULL);
            if (status_box == NULL)
                goto gui_init_failed;
            status_proc0 = (WNDPROC)SetWindowLongPtr(status_box, GWLP_WNDPROC,
                (LONG_PTR)status_proc);
            HGDIOBJ font = GetStockObject(DEFAULT_GUI_FONT);
            SendMessage(status_box, WM_SETFONT, (WPARAM)font, 0);
            status_label = CreateWindow(
                WC_STATIC, TOR_OFF_MESSAGE,
                WS_VISIBLE | WS_CHILD | SS_CENTER,
                15, 20, status_size_x - 30, 15, 
                status_box, NULL, instance, NULL);
            if (status_label == NULL)
                goto gui_init_failed;
            SendMessage(status_label, WM_SETFONT, (WPARAM)font, 0);

            // (4) Create the config box:
            size_t config_offset_x = status_offset_x,
                   config_offset_y = status_offset_y + status_size_y +
                        BUTTON_OFFSET_Y;
            size_t config_size_x = status_size_x,
                   config_size_y = BUTTON_SIZE_X - status_size_y -
                        BUTTON_OFFSET_Y;
            HWND config_box = CreateWindow(
                "BUTTON", "Config (Advanced)",
                WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                config_offset_x, config_offset_y,
                config_size_x, config_size_y, hwnd, NULL, instance, NULL);
            if (config_box == NULL)
                goto gui_init_failed;
            SendMessage(config_box, WM_SETFONT, (WPARAM)font, 0);
            config_proc0 = (WNDPROC)SetWindowLongPtr(config_box,
                GWLP_WNDPROC, (LONG_PTR)config_proc);
            
            HWND web_check = CreateWindow(
                "BUTTON", "Force web-only",
                BS_AUTOCHECKBOX | WS_CHILD | WS_VISIBLE,
                15, 20, config_size_x - 30, 15,
                config_box, (HMENU)ID_WEB_CHECK, instance, NULL);
            if (web_check == NULL)
                goto gui_init_failed;
            SendMessage(web_check, WM_SETFONT, (WPARAM)font, 0);
            if (option_force_web_only)
                SendMessage(web_check, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);

            HWND direct_check = CreateWindow(
                "BUTTON", "Force SOCKS4a",
                BS_AUTOCHECKBOX | WS_CHILD | WS_VISIBLE,
                15, 40, config_size_x - 30, 15,
                config_box, (HMENU)ID_DIRECT_CHECK, instance, NULL);
            if (direct_check == NULL)
                goto gui_init_failed;
            SendMessage(direct_check, WM_SETFONT, (WPARAM)font, 0);
            if (option_force_socks4a)
                SendMessage(direct_check, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);

            break;
        }
        case WM_COMMAND:
        {
            int event = HIWORD(wparam);
            if (event == BN_CLICKED && LOWORD(wparam) == ID_TOR_BUTTON)
            {
                LRESULT state = SendMessage((HWND)lparam, BM_GETCHECK, 0, 0);
                if (state == BST_CHECKED)
                    start_tor();
                else
                    stop_tor();
            }
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wparam, lparam);
    }
    return 0;

gui_init_failed:
    warning("failed to create the GUI");
    exit(EXIT_FAILURE);
}

// Entry point:
int WINAPI WinMain(HINSTANCE instance, HINSTANCE prev_instance,
    LPSTR cmd_line, int cmd_show)
{
    // Attach to the parent console if it exists.
    if (AttachConsole(ATTACH_PARENT_PROCESS))
    {
        freopen("conout$", "w", stdout);
        freopen("conout$", "w", stderr);
        putchar('\n');
    }

    WNDCLASSEX class;
    HWND window;

    // (0) Init stuff:
    srand(random());
    domain_init();
    redirect_init();
    option_force_socks4a  = restore_option(OPTION_FORCE_SOCKS4a_ONLY);
    option_force_web_only = restore_option(OPTION_FORCE_WEB_ONLY);

    // (1) Register the window class:
    memset(&class, 0, sizeof(class));
    class.cbSize = sizeof(WNDCLASSEX);
    class.lpfnWndProc = window_proc;
    class.hInstance = instance;
    class.hIcon = LoadImage(GetModuleHandle(NULL), "TALLOW_ICON_SMALL",
        IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);
    class.hCursor = LoadCursor(NULL, IDC_ARROW);
    class.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    class.lpszClassName = PROGNAME "_WINDOW";

    if (!RegisterClassEx(&class))
    {
        warning("failed to register window class; cannot display the GUI");
        return EXIT_FAILURE;
    }

    // (2) Create the window:
    window = CreateWindow(PROGNAME "_WINDOW", PROGNAME " (beta)",
        WS_OVERLAPPEDWINDOW & (~WS_THICKFRAME),
        CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_SIZE_X, WINDOW_SIZE_Y,
        NULL, NULL, instance, NULL);
    if (window == NULL)
    {
        warning("failed to create the main window");
        return EXIT_FAILURE;
    }

    // (3) Start Tor:
    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)tor_thread, NULL, 0, NULL);
    if (thread == NULL)
    {
        warning("failed to create Tor thread");
        return EXIT_FAILURE;
    }

    // (4) Start clean-up thread:
    thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)cleanup_thread, NULL, 0, NULL);
    if (thread == NULL)
    {
        warning("failed to create cleanup thread");
        return EXIT_FAILURE;
    }

    ShowWindow(window, cmd_show);
    UpdateWindow(window);

    // (5) Handle messages:
    MSG message;
    for (size_t i = 0; GetMessage(&message, NULL, 0, 0) > 0; i++)
    {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }
    return message.wParam;
}

// Tor thread:
static DWORD WINAPI tor_thread(LPVOID arg)
{
    // (1) Create the Tor process:
    status("starting Tor");

    HANDLE job = CreateJobObject(NULL, NULL);
    if (job == NULL)
    {
        warning("failed to create Tor job object");
        exit(EXIT_FAILURE);
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ji;
    memset(&ji, 0, sizeof(ji));
    ji.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &ji,
            sizeof(ji)))
    {
        warning("failed to configure Tor job object");
        exit(EXIT_FAILURE);
    }

    HANDLE out, in;
    SECURITY_ATTRIBUTES attr;
    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    attr.bInheritHandle = TRUE;
    attr.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&out, &in, &attr, 0))
    {
        warning("failed to create Tor pipe");
        exit(EXIT_FAILURE);
    }
    if (!SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        warning("failed to set handle information for Tor pipe");
        exit(EXIT_FAILURE);
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = in;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    const char *tor_path = ".\\tor.exe";

    // NOTE: Tor warns about allowing external connections.  However, such
    //       connections are blocked (see redirect_init).
    if (!CreateProcess(tor_path,
        "tor.exe --SOCKSListenAddress 0.0.0.0:" STR(TOR_PORT) " -f .\\torrc",
        NULL, NULL, TRUE, CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi))
    {
        warning("failed to start Tor");
        exit(EXIT_FAILURE);
    }

    if (!AssignProcessToJobObject(job, pi.hProcess))
    {
        TerminateProcess(pi.hProcess, 0);
        warning("failed to assign Tor process to Tor job object");
        exit(EXIT_FAILURE);
    }

    // Forward Tor messages to the status bar:
    while (TRUE)
    {
        char buf[BUFSIZ];
        DWORD len;

        if (!ReadFile(out, buf, sizeof(buf)-1, &len, NULL))
        {
            warning("failed to read Tor output");
            continue;
        }
        if (len <= 2)
            continue;
        buf[len-2] = '\0';

        // Tidy-up the Tor message a bit:
        size_t i = 0;
        while (buf[i] != ']' && buf[i] != '\0')
            i++;
        if (buf[i] != ']' && buf[i+1] != ' ')
            continue;
        char *msg = buf+i+2;
        
        // Crude-but-effective:
        if (strstr(msg, "Bootstrapped 100%") != NULL)
        {
            EnableWindow(button, TRUE);
            status("Bootstrapped 100%%: Press the \"Tor\" button to begin");
            continue;
        }

        status("%s", msg);
    }
}

// Cleanup thread:
static DWORD WINAPI cleanup_thread(DWORD arg)
{
    size_t count = 0;
    while (true)
    {
        Sleep(8000 + random() % 1024);

        domain_cleanup(count);
        redirect_cleanup(count);
        count++;
    }
    return 0;
}

// Status handling:
#define MAX_STATUS_LEN      256
extern void status(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    char buf[MAX_STATUS_LEN+8];

    int n = vsnprintf(buf, MAX_STATUS_LEN, message, args);
    if (n < 0 || n >= MAX_STATUS_LEN)
    {
        // Do nothing if something goes wrong...
        return;
    }

    if (islower(buf[0]))
        buf[0] = toupper(buf[0]);

    if (n < 3 || buf[n-1] != '.' || buf[n-2] != '.' || buf[n-3] != '.')
    {
        buf[n++] = '.';
        buf[n++] = '.';
        buf[n++] = '.';
        buf[n++] = '\0';
    }

    printf("%s\n", buf);

    if (status_bar != NULL)
    {
        SendMessage(status_bar, SB_SETTEXT, 0, (LPARAM)buf);
        SendMessage(status_bar, SB_SETTIPTEXT, 0, (LPARAM)buf);
    }
}

// Error handling:
#define MAX_WARNING_LEN         1024
extern void warning(const char *message, ...)
{
    // (1) Construct the message:
    int err = GetLastError();
    va_list args;
    va_start(args, message);
    char buf[MAX_WARNING_LEN+1];

    int n = vsnprintf(buf, MAX_WARNING_LEN, message, args);
    if (n < 0 || n >= MAX_WARNING_LEN)
    {
warning_failed:
        MessageBox(NULL, "failed to display warning message", NULL,
            MB_ICONERROR | MB_OK);
        exit(EXIT_FAILURE);
    }

    if (islower(buf[0]))
        buf[0] = toupper(buf[0]);

    if (err != 0)
    {
        // Compare FormatMessage() vs. strerror() -- no wonder people do not
        // use it...
        LPTSTR err_str = NULL;
        DWORD err_len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM, 0, err, 0, (LPTSTR)&err_str, 0, 0);
        if (err_len != 0)
        {
            if (n + 3 + err_len >= MAX_WARNING_LEN)
                goto warning_failed;
            buf[n++] = ':';
            buf[n++] = ' ';
            for (int i = 0; i < err_len; i++)
                buf[n++] = err_str[i];
            buf[n++] = '\0';
            LocalFree(err_str);
        }
    }

    // (2) Display the message.
    HANDLE console = GetStdHandle(STD_ERROR_HANDLE);
    SetConsoleTextAttribute(console, FOREGROUND_RED);
    fprintf(stderr, "warning: %s\n", buf);
    SetConsoleTextAttribute(console,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    MessageBox(NULL, buf, PROGNAME " - Warning", MB_ICONWARNING | MB_OK);
}

// Save/restore config options:
#define REG_PATH        "SOFTWARE\\" PROGNAME
static void save_option(const char *option, bool val0)
{
    HKEY key;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, REG_PATH, 0, NULL, 0, KEY_WRITE,
            NULL, &key, NULL) != ERROR_SUCCESS)
    {
        warning("failed to open registry key for option \"%s\"", option);
        return;
    }
    DWORD val = (DWORD)val0;
    if (RegSetValueEx(key, option, 0, REG_DWORD, (LPBYTE)&val, sizeof(val))
            != ERROR_SUCCESS)
        warning("failed to write value to regisyry for option \"%s\"", option);
    RegCloseKey(key);
}
static bool restore_option(const char *option)
{
    HKEY key;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, REG_PATH, 0, KEY_READ, &key)
            != ERROR_SUCCESS)
        return true;
    DWORD type, val, len = sizeof(val);
    RegQueryValueEx(key, option, NULL, &type, (LPBYTE)&val, &len);
    RegCloseKey(key);
    if (type != REG_DWORD)
        return true;
    return (bool)val;
}

