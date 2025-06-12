//! Namespace containing missing utils from std

const std = @import("std");
const windows = std.os.windows;
const posix = std.posix;

pub extern "kernel32" fn DeleteFileW(lpFileName: [*:0]const u16) callconv(windows.WINAPI) windows.BOOL;

pub const exp = struct {
    pub const STATUS_PENDING = 0x00000103;
    pub const STILL_ACTIVE = STATUS_PENDING;

    pub const JOBOBJECT_ASSOCIATE_COMPLETION_PORT = extern struct {
        CompletionKey: windows.ULONG_PTR,
        CompletionPort: windows.HANDLE,
    };

    pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
        PerProcessUserTimeLimit: windows.LARGE_INTEGER,
        PerJobUserTimeLimit: windows.LARGE_INTEGER,
        LimitFlags: windows.DWORD,
        MinimumWorkingSetSize: windows.SIZE_T,
        MaximumWorkingSetSize: windows.SIZE_T,
        ActiveProcessLimit: windows.DWORD,
        Affinity: windows.ULONG_PTR,
        PriorityClass: windows.DWORD,
        SchedulingClass: windows.DWORD,
    };

    pub const IO_COUNTERS = extern struct {
        ReadOperationCount: windows.ULONGLONG,
        WriteOperationCount: windows.ULONGLONG,
        OtherOperationCount: windows.ULONGLONG,
        ReadTransferCount: windows.ULONGLONG,
        WriteTransferCount: windows.ULONGLONG,
        OtherTransferCount: windows.ULONGLONG,
    };

    pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        IoInfo: IO_COUNTERS,
        ProcessMemoryLimit: windows.SIZE_T,
        JobMemoryLimit: windows.SIZE_T,
        PeakProcessMemoryUsed: windows.SIZE_T,
        PeakJobMemoryUsed: windows.SIZE_T,
    };

    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    pub const JOB_OBJECT_LIMIT_AFFINITY = 0x00000010;
    pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
    pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
    pub const JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    pub const JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    pub const JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x00000004;
    pub const JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020;
    pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    pub const JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
    pub const JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x00000080;
    pub const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
    pub const JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x00004000;
    pub const JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001;

    pub const JOBOBJECT_INFORMATION_CLASS = enum(c_int) {
        JobObjectAssociateCompletionPortInformation = 7,
        JobObjectBasicLimitInformation = 2,
        JobObjectBasicUIRestrictions = 4,
        JobObjectCpuRateControlInformation = 15,
        JobObjectEndOfJobTimeInformation = 6,
        JobObjectExtendedLimitInformation = 9,
        JobObjectGroupInformation = 11,
        JobObjectGroupInformationEx = 14,
        JobObjectLimitViolationInformation2 = 34,
        JobObjectNetRateControlInformation = 32,
        JobObjectNotificationLimitInformation = 12,
        JobObjectNotificationLimitInformation2 = 33,
        JobObjectSecurityLimitInformation = 5,
    };

    pub const JOB_OBJECT_MSG_TYPE = enum(windows.DWORD) {
        JOB_OBJECT_MSG_END_OF_JOB_TIME = 1,
        JOB_OBJECT_MSG_END_OF_PROCESS_TIME = 2,
        JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3,
        JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4,
        JOB_OBJECT_MSG_NEW_PROCESS = 6,
        JOB_OBJECT_MSG_EXIT_PROCESS = 7,
        JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8,
        JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT = 9,
        JOB_OBJECT_MSG_JOB_MEMORY_LIMIT = 10,
        JOB_OBJECT_MSG_NOTIFICATION_LIMIT = 11,
        JOB_OBJECT_MSG_JOB_CYCLE_TIME_LIMIT = 12,
        JOB_OBJECT_MSG_SILO_TERMINATED = 13,
        _,
    };

    pub const kernel32 = struct {
        pub extern "kernel32" fn GetProcessId(Process: windows.HANDLE) callconv(windows.WINAPI) windows.DWORD;
        pub extern "kernel32" fn CreateJobObjectA(lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES, lpName: ?windows.LPCSTR) callconv(windows.WINAPI) windows.HANDLE;
        pub extern "kernel32" fn AssignProcessToJobObject(hJob: windows.HANDLE, hProcess: windows.HANDLE) callconv(windows.WINAPI) windows.BOOL;
        pub extern "kernel32" fn SetInformationJobObject(
            hJob: windows.HANDLE,
            JobObjectInformationClass: JOBOBJECT_INFORMATION_CLASS,
            lpJobObjectInformation: windows.LPVOID,
            cbJobObjectInformationLength: windows.DWORD,
        ) callconv(windows.WINAPI) windows.BOOL;
    };

    pub const CreateFileError = error{} || posix.UnexpectedError;

    pub fn CreateFile(
        lpFileName: [*:0]const u16,
        dwDesiredAccess: windows.DWORD,
        dwShareMode: windows.DWORD,
        lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
        dwCreationDisposition: windows.DWORD,
        dwFlagsAndAttributes: windows.DWORD,
        hTemplateFile: ?windows.HANDLE,
    ) CreateFileError!windows.HANDLE {
        const handle = windows.kernel32.CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        if (handle == windows.INVALID_HANDLE_VALUE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                else => windows.unexpectedError(err),
            };
        }

        return handle;
    }

    pub fn ReadFile(
        handle: windows.HANDLE,
        buffer: []u8,
        overlapped: ?*windows.OVERLAPPED,
    ) windows.ReadFileError!?usize {
        var read: windows.DWORD = 0;
        const result: windows.BOOL = windows.kernel32.ReadFile(handle, buffer.ptr, @as(windows.DWORD, @intCast(buffer.len)), &read, overlapped);
        if (result == windows.FALSE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                windows.Win32Error.IO_PENDING => null,
                else => windows.unexpectedError(err),
            };
        }

        return @as(usize, @intCast(read));
    }

    pub fn WriteFile(
        handle: windows.HANDLE,
        buffer: []const u8,
        overlapped: ?*windows.OVERLAPPED,
    ) windows.WriteFileError!?usize {
        var written: windows.DWORD = 0;
        const result: windows.BOOL = windows.kernel32.WriteFile(handle, buffer.ptr, @as(windows.DWORD, @intCast(buffer.len)), &written, overlapped);
        if (result == windows.FALSE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                windows.Win32Error.IO_PENDING => null,
                else => windows.unexpectedError(err),
            };
        }

        return @as(usize, @intCast(written));
    }

    pub const DeleteFileError = error{} || posix.UnexpectedError;

    pub fn DeleteFile(name: [*:0]const u16) exp.DeleteFileError!void {
        const result: windows.BOOL = DeleteFileW(name);
        if (result == windows.FALSE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                else => windows.unexpectedError(err),
            };
        }
    }

    pub const CreateJobObjectError = error{AlreadyExists} || posix.UnexpectedError;
    pub fn CreateJobObject(
        lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
        lpName: ?windows.LPCSTR,
    ) !windows.HANDLE {
        const handle = exp.kernel32.CreateJobObjectA(lpSecurityAttributes, lpName);
        return switch (windows.kernel32.GetLastError()) {
            .SUCCESS => handle,
            .ALREADY_EXISTS => CreateJobObjectError.AlreadyExists,
            else => |err| windows.unexpectedError(err),
        };
    }

    pub fn AssignProcessToJobObject(hJob: windows.HANDLE, hProcess: windows.HANDLE) posix.UnexpectedError!void {
        const result: windows.BOOL = exp.kernel32.AssignProcessToJobObject(hJob, hProcess);
        if (result == windows.FALSE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                else => windows.unexpectedError(err),
            };
        }
    }

    pub fn SetInformationJobObject(
        hJob: windows.HANDLE,
        JobObjectInformationClass: JOBOBJECT_INFORMATION_CLASS,
        lpJobObjectInformation: windows.LPVOID,
        cbJobObjectInformationLength: windows.DWORD,
    ) posix.UnexpectedError!void {
        const result: windows.BOOL = exp.kernel32.SetInformationJobObject(
            hJob,
            JobObjectInformationClass,
            lpJobObjectInformation,
            cbJobObjectInformationLength,
        );

        if (result == windows.FALSE) {
            const err = windows.kernel32.GetLastError();
            return switch (err) {
                else => windows.unexpectedError(err),
            };
        }
    }
};

// all remaining content in this file is a replacement for `pub usingnamespace std.os.windows;`

pub const advapi32 = std.os.windows.advapi32;
pub const kernel32 = std.os.windows.kernel32;
pub const ntdll = std.os.windows.ntdll;
pub const ws2_32 = std.os.windows.ws2_32;
pub const crypt32 = std.os.windows.crypt32;
pub const nls = std.os.windows.nls;
pub const self_process_handle = std.os.windows.self_process_handle;
pub const OpenError = std.os.windows.OpenError;
pub const OpenFileOptions = std.os.windows.OpenFileOptions;
pub const CreatePipeError = std.os.windows.CreatePipeError;
pub const DeviceIoControlError = std.os.windows.DeviceIoControlError;
pub const SetHandleInformationError = std.os.windows.SetHandleInformationError;
pub const RtlGenRandomError = std.os.windows.RtlGenRandomError;
pub const WaitForSingleObjectError = std.os.windows.WaitForSingleObjectError;
pub const CreateIoCompletionPortError = std.os.windows.CreateIoCompletionPortError;
pub const PostQueuedCompletionStatusError = std.os.windows.PostQueuedCompletionStatusError;
pub const GetQueuedCompletionStatusResult = std.os.windows.GetQueuedCompletionStatusResult;
pub const GetQueuedCompletionStatusError = std.os.windows.GetQueuedCompletionStatusError;
pub const ReadFileError = std.os.windows.ReadFileError;
pub const WriteFileError = std.os.windows.WriteFileError;
pub const SetCurrentDirectoryError = std.os.windows.SetCurrentDirectoryError;
pub const GetCurrentDirectoryError = std.os.windows.GetCurrentDirectoryError;
pub const CreateSymbolicLinkError = std.os.windows.CreateSymbolicLinkError;
pub const ReadLinkError = std.os.windows.ReadLinkError;
pub const DeleteFileError = std.os.windows.DeleteFileError;
pub const DeleteFileOptions = std.os.windows.DeleteFileOptions;
pub const MoveFileError = std.os.windows.MoveFileError;
pub const GetStdHandleError = std.os.windows.GetStdHandleError;
pub const SetFilePointerError = std.os.windows.SetFilePointerError;
pub const QueryObjectNameError = std.os.windows.QueryObjectNameError;
pub const GetFinalPathNameByHandleError = std.os.windows.GetFinalPathNameByHandleError;
pub const GetFinalPathNameByHandleFormat = std.os.windows.GetFinalPathNameByHandleFormat;
pub const GetFileSizeError = std.os.windows.GetFileSizeError;
pub const GetFileAttributesError = std.os.windows.GetFileAttributesError;
pub const TerminateProcessError = std.os.windows.TerminateProcessError;
pub const VirtualAllocError = std.os.windows.VirtualAllocError;
pub const VirtualProtectError = std.os.windows.VirtualProtectError;
pub const VirtualQueryError = std.os.windows.VirtualQueryError;
pub const SetConsoleTextAttributeError = std.os.windows.SetConsoleTextAttributeError;
pub const GetEnvironmentStringsError = std.os.windows.GetEnvironmentStringsError;
pub const GetEnvironmentVariableError = std.os.windows.GetEnvironmentVariableError;
pub const CreateProcessError = std.os.windows.CreateProcessError;
pub const LoadLibraryError = std.os.windows.LoadLibraryError;
pub const LoadLibraryFlags = std.os.windows.LoadLibraryFlags;
pub const SetFileTimeError = std.os.windows.SetFileTimeError;
pub const LockFileError = std.os.windows.LockFileError;
pub const UnlockFileError = std.os.windows.UnlockFileError;
pub const PathSpace = std.os.windows.PathSpace;
pub const RemoveDotDirsError = std.os.windows.RemoveDotDirsError;
pub const Wtf8ToPrefixedFileWError = std.os.windows.Wtf8ToPrefixedFileWError;
pub const Wtf16ToPrefixedFileWError = std.os.windows.Wtf16ToPrefixedFileWError;
pub const NamespacePrefix = std.os.windows.NamespacePrefix;
pub const UnprefixedPathType = std.os.windows.UnprefixedPathType;
pub const Win32Error = std.os.windows.Win32Error;
pub const NTSTATUS = std.os.windows.NTSTATUS;
pub const LANG = std.os.windows.LANG;
pub const SUBLANG = std.os.windows.SUBLANG;
pub const STD_INPUT_HANDLE = std.os.windows.STD_INPUT_HANDLE;
pub const STD_OUTPUT_HANDLE = std.os.windows.STD_OUTPUT_HANDLE;
pub const STD_ERROR_HANDLE = std.os.windows.STD_ERROR_HANDLE;
pub const WINAPI = std.os.windows.WINAPI;
pub const BOOL = std.os.windows.BOOL;
pub const BOOLEAN = std.os.windows.BOOLEAN;
pub const BYTE = std.os.windows.BYTE;
pub const CHAR = std.os.windows.CHAR;
pub const UCHAR = std.os.windows.UCHAR;
pub const FLOAT = std.os.windows.FLOAT;
pub const HANDLE = std.os.windows.HANDLE;
pub const HCRYPTPROV = std.os.windows.HCRYPTPROV;
pub const ATOM = std.os.windows.ATOM;
pub const HBRUSH = std.os.windows.HBRUSH;
pub const HCURSOR = std.os.windows.HCURSOR;
pub const HICON = std.os.windows.HICON;
pub const HINSTANCE = std.os.windows.HINSTANCE;
pub const HMENU = std.os.windows.HMENU;
pub const HMODULE = std.os.windows.HMODULE;
pub const HWND = std.os.windows.HWND;
pub const HDC = std.os.windows.HDC;
pub const HGLRC = std.os.windows.HGLRC;
pub const FARPROC = std.os.windows.FARPROC;
pub const PROC = std.os.windows.PROC;
pub const INT = std.os.windows.INT;
pub const LPCSTR = std.os.windows.LPCSTR;
pub const LPCVOID = std.os.windows.LPCVOID;
pub const LPSTR = std.os.windows.LPSTR;
pub const LPVOID = std.os.windows.LPVOID;
pub const LPWSTR = std.os.windows.LPWSTR;
pub const LPCWSTR = std.os.windows.LPCWSTR;
pub const PVOID = std.os.windows.PVOID;
pub const PWSTR = std.os.windows.PWSTR;
pub const PCWSTR = std.os.windows.PCWSTR;
pub const BSTR = std.os.windows.BSTR;
pub const SIZE_T = std.os.windows.SIZE_T;
pub const UINT = std.os.windows.UINT;
pub const ULONG_PTR = std.os.windows.ULONG_PTR;
pub const LONG_PTR = std.os.windows.LONG_PTR;
pub const DWORD_PTR = std.os.windows.DWORD_PTR;
pub const WCHAR = std.os.windows.WCHAR;
pub const WORD = std.os.windows.WORD;
pub const DWORD = std.os.windows.DWORD;
pub const DWORD64 = std.os.windows.DWORD64;
pub const LARGE_INTEGER = std.os.windows.LARGE_INTEGER;
pub const ULARGE_INTEGER = std.os.windows.ULARGE_INTEGER;
pub const USHORT = std.os.windows.USHORT;
pub const SHORT = std.os.windows.SHORT;
pub const ULONG = std.os.windows.ULONG;
pub const LONG = std.os.windows.LONG;
pub const ULONG64 = std.os.windows.ULONG64;
pub const ULONGLONG = std.os.windows.ULONGLONG;
pub const LONGLONG = std.os.windows.LONGLONG;
pub const HLOCAL = std.os.windows.HLOCAL;
pub const LANGID = std.os.windows.LANGID;
pub const WPARAM = std.os.windows.WPARAM;
pub const LPARAM = std.os.windows.LPARAM;
pub const LRESULT = std.os.windows.LRESULT;
pub const va_list = std.os.windows.va_list;
pub const TCHAR = std.os.windows.TCHAR;
pub const LPTSTR = std.os.windows.LPTSTR;
pub const LPCTSTR = std.os.windows.LPCTSTR;
pub const PTSTR = std.os.windows.PTSTR;
pub const PCTSTR = std.os.windows.PCTSTR;
pub const TRUE = std.os.windows.TRUE;
pub const FALSE = std.os.windows.FALSE;
pub const DEVICE_TYPE = std.os.windows.DEVICE_TYPE;
pub const FILE_DEVICE_BEEP = std.os.windows.FILE_DEVICE_BEEP;
pub const FILE_DEVICE_CD_ROM = std.os.windows.FILE_DEVICE_CD_ROM;
pub const FILE_DEVICE_CD_ROM_FILE_SYSTEM = std.os.windows.FILE_DEVICE_CD_ROM_FILE_SYSTEM;
pub const FILE_DEVICE_CONTROLLER = std.os.windows.FILE_DEVICE_CONTROLLER;
pub const FILE_DEVICE_DATALINK = std.os.windows.FILE_DEVICE_DATALINK;
pub const FILE_DEVICE_DFS = std.os.windows.FILE_DEVICE_DFS;
pub const FILE_DEVICE_DISK = std.os.windows.FILE_DEVICE_DISK;
pub const FILE_DEVICE_DISK_FILE_SYSTEM = std.os.windows.FILE_DEVICE_DISK_FILE_SYSTEM;
pub const FILE_DEVICE_FILE_SYSTEM = std.os.windows.FILE_DEVICE_FILE_SYSTEM;
pub const FILE_DEVICE_INPORT_PORT = std.os.windows.FILE_DEVICE_INPORT_PORT;
pub const FILE_DEVICE_KEYBOARD = std.os.windows.FILE_DEVICE_KEYBOARD;
pub const FILE_DEVICE_MAILSLOT = std.os.windows.FILE_DEVICE_MAILSLOT;
pub const FILE_DEVICE_MIDI_IN = std.os.windows.FILE_DEVICE_MIDI_IN;
pub const FILE_DEVICE_MIDI_OUT = std.os.windows.FILE_DEVICE_MIDI_OUT;
pub const FILE_DEVICE_MOUSE = std.os.windows.FILE_DEVICE_MOUSE;
pub const FILE_DEVICE_MULTI_UNC_PROVIDER = std.os.windows.FILE_DEVICE_MULTI_UNC_PROVIDER;
pub const FILE_DEVICE_NAMED_PIPE = std.os.windows.FILE_DEVICE_NAMED_PIPE;
pub const FILE_DEVICE_NETWORK = std.os.windows.FILE_DEVICE_NETWORK;
pub const FILE_DEVICE_NETWORK_BROWSER = std.os.windows.FILE_DEVICE_NETWORK_BROWSER;
pub const FILE_DEVICE_NETWORK_FILE_SYSTEM = std.os.windows.FILE_DEVICE_NETWORK_FILE_SYSTEM;
pub const FILE_DEVICE_NULL = std.os.windows.FILE_DEVICE_NULL;
pub const FILE_DEVICE_PARALLEL_PORT = std.os.windows.FILE_DEVICE_PARALLEL_PORT;
pub const FILE_DEVICE_PHYSICAL_NETCARD = std.os.windows.FILE_DEVICE_PHYSICAL_NETCARD;
pub const FILE_DEVICE_PRINTER = std.os.windows.FILE_DEVICE_PRINTER;
pub const FILE_DEVICE_SCANNER = std.os.windows.FILE_DEVICE_SCANNER;
pub const FILE_DEVICE_SERIAL_MOUSE_PORT = std.os.windows.FILE_DEVICE_SERIAL_MOUSE_PORT;
pub const FILE_DEVICE_SERIAL_PORT = std.os.windows.FILE_DEVICE_SERIAL_PORT;
pub const FILE_DEVICE_SCREEN = std.os.windows.FILE_DEVICE_SCREEN;
pub const FILE_DEVICE_SOUND = std.os.windows.FILE_DEVICE_SOUND;
pub const FILE_DEVICE_STREAMS = std.os.windows.FILE_DEVICE_STREAMS;
pub const FILE_DEVICE_TAPE = std.os.windows.FILE_DEVICE_TAPE;
pub const FILE_DEVICE_TAPE_FILE_SYSTEM = std.os.windows.FILE_DEVICE_TAPE_FILE_SYSTEM;
pub const FILE_DEVICE_TRANSPORT = std.os.windows.FILE_DEVICE_TRANSPORT;
pub const FILE_DEVICE_UNKNOWN = std.os.windows.FILE_DEVICE_UNKNOWN;
pub const FILE_DEVICE_VIDEO = std.os.windows.FILE_DEVICE_VIDEO;
pub const FILE_DEVICE_VIRTUAL_DISK = std.os.windows.FILE_DEVICE_VIRTUAL_DISK;
pub const FILE_DEVICE_WAVE_IN = std.os.windows.FILE_DEVICE_WAVE_IN;
pub const FILE_DEVICE_WAVE_OUT = std.os.windows.FILE_DEVICE_WAVE_OUT;
pub const FILE_DEVICE_8042_PORT = std.os.windows.FILE_DEVICE_8042_PORT;
pub const FILE_DEVICE_NETWORK_REDIRECTOR = std.os.windows.FILE_DEVICE_NETWORK_REDIRECTOR;
pub const FILE_DEVICE_BATTERY = std.os.windows.FILE_DEVICE_BATTERY;
pub const FILE_DEVICE_BUS_EXTENDER = std.os.windows.FILE_DEVICE_BUS_EXTENDER;
pub const FILE_DEVICE_MODEM = std.os.windows.FILE_DEVICE_MODEM;
pub const FILE_DEVICE_VDM = std.os.windows.FILE_DEVICE_VDM;
pub const FILE_DEVICE_MASS_STORAGE = std.os.windows.FILE_DEVICE_MASS_STORAGE;
pub const FILE_DEVICE_SMB = std.os.windows.FILE_DEVICE_SMB;
pub const FILE_DEVICE_KS = std.os.windows.FILE_DEVICE_KS;
pub const FILE_DEVICE_CHANGER = std.os.windows.FILE_DEVICE_CHANGER;
pub const FILE_DEVICE_SMARTCARD = std.os.windows.FILE_DEVICE_SMARTCARD;
pub const FILE_DEVICE_ACPI = std.os.windows.FILE_DEVICE_ACPI;
pub const FILE_DEVICE_DVD = std.os.windows.FILE_DEVICE_DVD;
pub const FILE_DEVICE_FULLSCREEN_VIDEO = std.os.windows.FILE_DEVICE_FULLSCREEN_VIDEO;
pub const FILE_DEVICE_DFS_FILE_SYSTEM = std.os.windows.FILE_DEVICE_DFS_FILE_SYSTEM;
pub const FILE_DEVICE_DFS_VOLUME = std.os.windows.FILE_DEVICE_DFS_VOLUME;
pub const FILE_DEVICE_SERENUM = std.os.windows.FILE_DEVICE_SERENUM;
pub const FILE_DEVICE_TERMSRV = std.os.windows.FILE_DEVICE_TERMSRV;
pub const FILE_DEVICE_KSEC = std.os.windows.FILE_DEVICE_KSEC;
pub const FILE_DEVICE_FIPS = std.os.windows.FILE_DEVICE_FIPS;
pub const FILE_DEVICE_INFINIBAND = std.os.windows.FILE_DEVICE_INFINIBAND;
pub const FILE_DEVICE_VMBUS = std.os.windows.FILE_DEVICE_VMBUS;
pub const FILE_DEVICE_CRYPT_PROVIDER = std.os.windows.FILE_DEVICE_CRYPT_PROVIDER;
pub const FILE_DEVICE_WPD = std.os.windows.FILE_DEVICE_WPD;
pub const FILE_DEVICE_BLUETOOTH = std.os.windows.FILE_DEVICE_BLUETOOTH;
pub const FILE_DEVICE_MT_COMPOSITE = std.os.windows.FILE_DEVICE_MT_COMPOSITE;
pub const FILE_DEVICE_MT_TRANSPORT = std.os.windows.FILE_DEVICE_MT_TRANSPORT;
pub const FILE_DEVICE_BIOMETRIC = std.os.windows.FILE_DEVICE_BIOMETRIC;
pub const FILE_DEVICE_PMI = std.os.windows.FILE_DEVICE_PMI;
pub const FILE_DEVICE_EHSTOR = std.os.windows.FILE_DEVICE_EHSTOR;
pub const FILE_DEVICE_DEVAPI = std.os.windows.FILE_DEVICE_DEVAPI;
pub const FILE_DEVICE_GPIO = std.os.windows.FILE_DEVICE_GPIO;
pub const FILE_DEVICE_USBEX = std.os.windows.FILE_DEVICE_USBEX;
pub const FILE_DEVICE_CONSOLE = std.os.windows.FILE_DEVICE_CONSOLE;
pub const FILE_DEVICE_NFP = std.os.windows.FILE_DEVICE_NFP;
pub const FILE_DEVICE_SYSENV = std.os.windows.FILE_DEVICE_SYSENV;
pub const FILE_DEVICE_VIRTUAL_BLOCK = std.os.windows.FILE_DEVICE_VIRTUAL_BLOCK;
pub const FILE_DEVICE_POINT_OF_SERVICE = std.os.windows.FILE_DEVICE_POINT_OF_SERVICE;
pub const FILE_DEVICE_STORAGE_REPLICATION = std.os.windows.FILE_DEVICE_STORAGE_REPLICATION;
pub const FILE_DEVICE_TRUST_ENV = std.os.windows.FILE_DEVICE_TRUST_ENV;
pub const FILE_DEVICE_UCM = std.os.windows.FILE_DEVICE_UCM;
pub const FILE_DEVICE_UCMTCPCI = std.os.windows.FILE_DEVICE_UCMTCPCI;
pub const FILE_DEVICE_PERSISTENT_MEMORY = std.os.windows.FILE_DEVICE_PERSISTENT_MEMORY;
pub const FILE_DEVICE_NVDIMM = std.os.windows.FILE_DEVICE_NVDIMM;
pub const FILE_DEVICE_HOLOGRAPHIC = std.os.windows.FILE_DEVICE_HOLOGRAPHIC;
pub const FILE_DEVICE_SDFXHCI = std.os.windows.FILE_DEVICE_SDFXHCI;
pub const TransferType = std.os.windows.TransferType;
pub const FILE_ANY_ACCESS = std.os.windows.FILE_ANY_ACCESS;
pub const FILE_READ_ACCESS = std.os.windows.FILE_READ_ACCESS;
pub const FILE_WRITE_ACCESS = std.os.windows.FILE_WRITE_ACCESS;
pub const INVALID_HANDLE_VALUE = std.os.windows.INVALID_HANDLE_VALUE;
pub const INVALID_FILE_ATTRIBUTES = std.os.windows.INVALID_FILE_ATTRIBUTES;
pub const FILE_ALL_INFORMATION = std.os.windows.FILE_ALL_INFORMATION;
pub const FILE_BASIC_INFORMATION = std.os.windows.FILE_BASIC_INFORMATION;
pub const FILE_STANDARD_INFORMATION = std.os.windows.FILE_STANDARD_INFORMATION;
pub const FILE_INTERNAL_INFORMATION = std.os.windows.FILE_INTERNAL_INFORMATION;
pub const FILE_EA_INFORMATION = std.os.windows.FILE_EA_INFORMATION;
pub const FILE_ACCESS_INFORMATION = std.os.windows.FILE_ACCESS_INFORMATION;
pub const FILE_POSITION_INFORMATION = std.os.windows.FILE_POSITION_INFORMATION;
pub const FILE_END_OF_FILE_INFORMATION = std.os.windows.FILE_END_OF_FILE_INFORMATION;
pub const FILE_MODE_INFORMATION = std.os.windows.FILE_MODE_INFORMATION;
pub const FILE_ALIGNMENT_INFORMATION = std.os.windows.FILE_ALIGNMENT_INFORMATION;
pub const FILE_NAME_INFORMATION = std.os.windows.FILE_NAME_INFORMATION;
pub const FILE_DISPOSITION_INFORMATION_EX = std.os.windows.FILE_DISPOSITION_INFORMATION_EX;
pub const FILE_RENAME_REPLACE_IF_EXISTS = std.os.windows.FILE_RENAME_REPLACE_IF_EXISTS;
pub const FILE_RENAME_POSIX_SEMANTICS = std.os.windows.FILE_RENAME_POSIX_SEMANTICS;
pub const FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE = std.os.windows.FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE;
pub const FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE = std.os.windows.FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE;
pub const FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE = std.os.windows.FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE;
pub const FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE = std.os.windows.FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE;
pub const FILE_RENAME_PRESERVE_AVAILABLE_SPACE = std.os.windows.FILE_RENAME_PRESERVE_AVAILABLE_SPACE;
pub const FILE_RENAME_IGNORE_READONLY_ATTRIBUTE = std.os.windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE;
pub const FILE_RENAME_FORCE_RESIZE_TARGET_SR = std.os.windows.FILE_RENAME_FORCE_RESIZE_TARGET_SR;
pub const FILE_RENAME_FORCE_RESIZE_SOURCE_SR = std.os.windows.FILE_RENAME_FORCE_RESIZE_SOURCE_SR;
pub const FILE_RENAME_FORCE_RESIZE_SR = std.os.windows.FILE_RENAME_FORCE_RESIZE_SR;
pub const FILE_RENAME_INFORMATION = std.os.windows.FILE_RENAME_INFORMATION;
pub const FILE_RENAME_INFORMATION_EX = std.os.windows.FILE_RENAME_INFORMATION_EX;
pub const IO_STATUS_BLOCK = std.os.windows.IO_STATUS_BLOCK;
pub const FILE_INFORMATION_CLASS = std.os.windows.FILE_INFORMATION_CLASS;
pub const FILE_ATTRIBUTE_TAG_INFO = std.os.windows.FILE_ATTRIBUTE_TAG_INFO;
pub const reparse_tag_name_surrogate_bit = std.os.windows.reparse_tag_name_surrogate_bit;
pub const FILE_DISPOSITION_INFORMATION = std.os.windows.FILE_DISPOSITION_INFORMATION;
pub const FILE_FS_DEVICE_INFORMATION = std.os.windows.FILE_FS_DEVICE_INFORMATION;
pub const FILE_FS_VOLUME_INFORMATION = std.os.windows.FILE_FS_VOLUME_INFORMATION;
pub const FS_INFORMATION_CLASS = std.os.windows.FS_INFORMATION_CLASS;
pub const OVERLAPPED = std.os.windows.OVERLAPPED;
pub const OVERLAPPED_ENTRY = std.os.windows.OVERLAPPED_ENTRY;
pub const MAX_PATH = std.os.windows.MAX_PATH;
pub const FILE_INFO_BY_HANDLE_CLASS = std.os.windows.FILE_INFO_BY_HANDLE_CLASS;
pub const BY_HANDLE_FILE_INFORMATION = std.os.windows.BY_HANDLE_FILE_INFORMATION;
pub const FILE_NAME_INFO = std.os.windows.FILE_NAME_INFO;
pub const FILE_NAME_NORMALIZED = std.os.windows.FILE_NAME_NORMALIZED;
pub const FILE_NAME_OPENED = std.os.windows.FILE_NAME_OPENED;
pub const VOLUME_NAME_DOS = std.os.windows.VOLUME_NAME_DOS;
pub const VOLUME_NAME_GUID = std.os.windows.VOLUME_NAME_GUID;
pub const VOLUME_NAME_NONE = std.os.windows.VOLUME_NAME_NONE;
pub const VOLUME_NAME_NT = std.os.windows.VOLUME_NAME_NT;
pub const SECURITY_ATTRIBUTES = std.os.windows.SECURITY_ATTRIBUTES;
pub const PIPE_ACCESS_INBOUND = std.os.windows.PIPE_ACCESS_INBOUND;
pub const PIPE_ACCESS_OUTBOUND = std.os.windows.PIPE_ACCESS_OUTBOUND;
pub const PIPE_ACCESS_DUPLEX = std.os.windows.PIPE_ACCESS_DUPLEX;
pub const PIPE_TYPE_BYTE = std.os.windows.PIPE_TYPE_BYTE;
pub const PIPE_TYPE_MESSAGE = std.os.windows.PIPE_TYPE_MESSAGE;
pub const PIPE_READMODE_BYTE = std.os.windows.PIPE_READMODE_BYTE;
pub const PIPE_READMODE_MESSAGE = std.os.windows.PIPE_READMODE_MESSAGE;
pub const PIPE_WAIT = std.os.windows.PIPE_WAIT;
pub const PIPE_NOWAIT = std.os.windows.PIPE_NOWAIT;
pub const GENERIC_READ = std.os.windows.GENERIC_READ;
pub const GENERIC_WRITE = std.os.windows.GENERIC_WRITE;
pub const GENERIC_EXECUTE = std.os.windows.GENERIC_EXECUTE;
pub const GENERIC_ALL = std.os.windows.GENERIC_ALL;
pub const FILE_SHARE_DELETE = std.os.windows.FILE_SHARE_DELETE;
pub const FILE_SHARE_READ = std.os.windows.FILE_SHARE_READ;
pub const FILE_SHARE_WRITE = std.os.windows.FILE_SHARE_WRITE;
pub const DELETE = std.os.windows.DELETE;
pub const READ_CONTROL = std.os.windows.READ_CONTROL;
pub const WRITE_DAC = std.os.windows.WRITE_DAC;
pub const WRITE_OWNER = std.os.windows.WRITE_OWNER;
pub const SYNCHRONIZE = std.os.windows.SYNCHRONIZE;
pub const STANDARD_RIGHTS_READ = std.os.windows.STANDARD_RIGHTS_READ;
pub const STANDARD_RIGHTS_WRITE = std.os.windows.STANDARD_RIGHTS_WRITE;
pub const STANDARD_RIGHTS_EXECUTE = std.os.windows.STANDARD_RIGHTS_EXECUTE;
pub const STANDARD_RIGHTS_REQUIRED = std.os.windows.STANDARD_RIGHTS_REQUIRED;
pub const MAXIMUM_ALLOWED = std.os.windows.MAXIMUM_ALLOWED;
pub const FILE_SUPERSEDE = std.os.windows.FILE_SUPERSEDE;
pub const FILE_OPEN = std.os.windows.FILE_OPEN;
pub const FILE_CREATE = std.os.windows.FILE_CREATE;
pub const FILE_OPEN_IF = std.os.windows.FILE_OPEN_IF;
pub const FILE_OVERWRITE = std.os.windows.FILE_OVERWRITE;
pub const FILE_OVERWRITE_IF = std.os.windows.FILE_OVERWRITE_IF;
pub const FILE_MAXIMUM_DISPOSITION = std.os.windows.FILE_MAXIMUM_DISPOSITION;
pub const FILE_READ_DATA = std.os.windows.FILE_READ_DATA;
pub const FILE_LIST_DIRECTORY = std.os.windows.FILE_LIST_DIRECTORY;
pub const FILE_WRITE_DATA = std.os.windows.FILE_WRITE_DATA;
pub const FILE_ADD_FILE = std.os.windows.FILE_ADD_FILE;
pub const FILE_APPEND_DATA = std.os.windows.FILE_APPEND_DATA;
pub const FILE_ADD_SUBDIRECTORY = std.os.windows.FILE_ADD_SUBDIRECTORY;
pub const FILE_CREATE_PIPE_INSTANCE = std.os.windows.FILE_CREATE_PIPE_INSTANCE;
pub const FILE_READ_EA = std.os.windows.FILE_READ_EA;
pub const FILE_WRITE_EA = std.os.windows.FILE_WRITE_EA;
pub const FILE_EXECUTE = std.os.windows.FILE_EXECUTE;
pub const FILE_TRAVERSE = std.os.windows.FILE_TRAVERSE;
pub const FILE_DELETE_CHILD = std.os.windows.FILE_DELETE_CHILD;
pub const FILE_READ_ATTRIBUTES = std.os.windows.FILE_READ_ATTRIBUTES;
pub const FILE_WRITE_ATTRIBUTES = std.os.windows.FILE_WRITE_ATTRIBUTES;
pub const FILE_DIRECTORY_FILE = std.os.windows.FILE_DIRECTORY_FILE;
pub const FILE_WRITE_THROUGH = std.os.windows.FILE_WRITE_THROUGH;
pub const FILE_SEQUENTIAL_ONLY = std.os.windows.FILE_SEQUENTIAL_ONLY;
pub const FILE_NO_INTERMEDIATE_BUFFERING = std.os.windows.FILE_NO_INTERMEDIATE_BUFFERING;
pub const FILE_SYNCHRONOUS_IO_ALERT = std.os.windows.FILE_SYNCHRONOUS_IO_ALERT;
pub const FILE_SYNCHRONOUS_IO_NONALERT = std.os.windows.FILE_SYNCHRONOUS_IO_NONALERT;
pub const FILE_NON_DIRECTORY_FILE = std.os.windows.FILE_NON_DIRECTORY_FILE;
pub const FILE_CREATE_TREE_CONNECTION = std.os.windows.FILE_CREATE_TREE_CONNECTION;
pub const FILE_COMPLETE_IF_OPLOCKED = std.os.windows.FILE_COMPLETE_IF_OPLOCKED;
pub const FILE_NO_EA_KNOWLEDGE = std.os.windows.FILE_NO_EA_KNOWLEDGE;
pub const FILE_OPEN_FOR_RECOVERY = std.os.windows.FILE_OPEN_FOR_RECOVERY;
pub const FILE_RANDOM_ACCESS = std.os.windows.FILE_RANDOM_ACCESS;
pub const FILE_DELETE_ON_CLOSE = std.os.windows.FILE_DELETE_ON_CLOSE;
pub const FILE_OPEN_BY_FILE_ID = std.os.windows.FILE_OPEN_BY_FILE_ID;
pub const FILE_OPEN_FOR_BACKUP_INTENT = std.os.windows.FILE_OPEN_FOR_BACKUP_INTENT;
pub const FILE_NO_COMPRESSION = std.os.windows.FILE_NO_COMPRESSION;
pub const FILE_RESERVE_OPFILTER = std.os.windows.FILE_RESERVE_OPFILTER;
pub const FILE_OPEN_REPARSE_POINT = std.os.windows.FILE_OPEN_REPARSE_POINT;
pub const FILE_OPEN_OFFLINE_FILE = std.os.windows.FILE_OPEN_OFFLINE_FILE;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY = std.os.windows.FILE_OPEN_FOR_FREE_SPACE_QUERY;
pub const CREATE_ALWAYS = std.os.windows.CREATE_ALWAYS;
pub const CREATE_NEW = std.os.windows.CREATE_NEW;
pub const OPEN_ALWAYS = std.os.windows.OPEN_ALWAYS;
pub const OPEN_EXISTING = std.os.windows.OPEN_EXISTING;
pub const TRUNCATE_EXISTING = std.os.windows.TRUNCATE_EXISTING;
pub const FILE_ATTRIBUTE_ARCHIVE = std.os.windows.FILE_ATTRIBUTE_ARCHIVE;
pub const FILE_ATTRIBUTE_COMPRESSED = std.os.windows.FILE_ATTRIBUTE_COMPRESSED;
pub const FILE_ATTRIBUTE_DEVICE = std.os.windows.FILE_ATTRIBUTE_DEVICE;
pub const FILE_ATTRIBUTE_DIRECTORY = std.os.windows.FILE_ATTRIBUTE_DIRECTORY;
pub const FILE_ATTRIBUTE_ENCRYPTED = std.os.windows.FILE_ATTRIBUTE_ENCRYPTED;
pub const FILE_ATTRIBUTE_HIDDEN = std.os.windows.FILE_ATTRIBUTE_HIDDEN;
pub const FILE_ATTRIBUTE_INTEGRITY_STREAM = std.os.windows.FILE_ATTRIBUTE_INTEGRITY_STREAM;
pub const FILE_ATTRIBUTE_NORMAL = std.os.windows.FILE_ATTRIBUTE_NORMAL;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = std.os.windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
pub const FILE_ATTRIBUTE_NO_SCRUB_DATA = std.os.windows.FILE_ATTRIBUTE_NO_SCRUB_DATA;
pub const FILE_ATTRIBUTE_OFFLINE = std.os.windows.FILE_ATTRIBUTE_OFFLINE;
pub const FILE_ATTRIBUTE_READONLY = std.os.windows.FILE_ATTRIBUTE_READONLY;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = std.os.windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN = std.os.windows.FILE_ATTRIBUTE_RECALL_ON_OPEN;
pub const FILE_ATTRIBUTE_REPARSE_POINT = std.os.windows.FILE_ATTRIBUTE_REPARSE_POINT;
pub const FILE_ATTRIBUTE_SPARSE_FILE = std.os.windows.FILE_ATTRIBUTE_SPARSE_FILE;
pub const FILE_ATTRIBUTE_SYSTEM = std.os.windows.FILE_ATTRIBUTE_SYSTEM;
pub const FILE_ATTRIBUTE_TEMPORARY = std.os.windows.FILE_ATTRIBUTE_TEMPORARY;
pub const FILE_ATTRIBUTE_VIRTUAL = std.os.windows.FILE_ATTRIBUTE_VIRTUAL;
pub const FILE_ALL_ACCESS = std.os.windows.FILE_ALL_ACCESS;
pub const FILE_GENERIC_READ = std.os.windows.FILE_GENERIC_READ;
pub const FILE_GENERIC_WRITE = std.os.windows.FILE_GENERIC_WRITE;
pub const FILE_GENERIC_EXECUTE = std.os.windows.FILE_GENERIC_EXECUTE;
pub const FILE_PIPE_BYTE_STREAM_TYPE = std.os.windows.FILE_PIPE_BYTE_STREAM_TYPE;
pub const FILE_PIPE_MESSAGE_TYPE = std.os.windows.FILE_PIPE_MESSAGE_TYPE;
pub const FILE_PIPE_ACCEPT_REMOTE_CLIENTS = std.os.windows.FILE_PIPE_ACCEPT_REMOTE_CLIENTS;
pub const FILE_PIPE_REJECT_REMOTE_CLIENTS = std.os.windows.FILE_PIPE_REJECT_REMOTE_CLIENTS;
pub const FILE_PIPE_TYPE_VALID_MASK = std.os.windows.FILE_PIPE_TYPE_VALID_MASK;
pub const FILE_PIPE_QUEUE_OPERATION = std.os.windows.FILE_PIPE_QUEUE_OPERATION;
pub const FILE_PIPE_COMPLETE_OPERATION = std.os.windows.FILE_PIPE_COMPLETE_OPERATION;
pub const FILE_PIPE_BYTE_STREAM_MODE = std.os.windows.FILE_PIPE_BYTE_STREAM_MODE;
pub const FILE_PIPE_MESSAGE_MODE = std.os.windows.FILE_PIPE_MESSAGE_MODE;
pub const CREATE_EVENT_INITIAL_SET = std.os.windows.CREATE_EVENT_INITIAL_SET;
pub const CREATE_EVENT_MANUAL_RESET = std.os.windows.CREATE_EVENT_MANUAL_RESET;
pub const EVENT_ALL_ACCESS = std.os.windows.EVENT_ALL_ACCESS;
pub const EVENT_MODIFY_STATE = std.os.windows.EVENT_MODIFY_STATE;
pub const MEM_IMAGE = std.os.windows.MEM_IMAGE;
pub const MEM_MAPPED = std.os.windows.MEM_MAPPED;
pub const MEM_PRIVATE = std.os.windows.MEM_PRIVATE;
pub const PROCESS_INFORMATION = std.os.windows.PROCESS_INFORMATION;
pub const STARTUPINFOW = std.os.windows.STARTUPINFOW;
pub const STARTF_FORCEONFEEDBACK = std.os.windows.STARTF_FORCEONFEEDBACK;
pub const STARTF_FORCEOFFFEEDBACK = std.os.windows.STARTF_FORCEOFFFEEDBACK;
pub const STARTF_PREVENTPINNING = std.os.windows.STARTF_PREVENTPINNING;
pub const STARTF_RUNFULLSCREEN = std.os.windows.STARTF_RUNFULLSCREEN;
pub const STARTF_TITLEISAPPID = std.os.windows.STARTF_TITLEISAPPID;
pub const STARTF_TITLEISLINKNAME = std.os.windows.STARTF_TITLEISLINKNAME;
pub const STARTF_UNTRUSTEDSOURCE = std.os.windows.STARTF_UNTRUSTEDSOURCE;
pub const STARTF_USECOUNTCHARS = std.os.windows.STARTF_USECOUNTCHARS;
pub const STARTF_USEFILLATTRIBUTE = std.os.windows.STARTF_USEFILLATTRIBUTE;
pub const STARTF_USEHOTKEY = std.os.windows.STARTF_USEHOTKEY;
pub const STARTF_USEPOSITION = std.os.windows.STARTF_USEPOSITION;
pub const STARTF_USESHOWWINDOW = std.os.windows.STARTF_USESHOWWINDOW;
pub const STARTF_USESIZE = std.os.windows.STARTF_USESIZE;
pub const STARTF_USESTDHANDLES = std.os.windows.STARTF_USESTDHANDLES;
pub const INFINITE = std.os.windows.INFINITE;
pub const MAXIMUM_WAIT_OBJECTS = std.os.windows.MAXIMUM_WAIT_OBJECTS;
pub const WAIT_ABANDONED = std.os.windows.WAIT_ABANDONED;
pub const WAIT_ABANDONED_0 = std.os.windows.WAIT_ABANDONED_0;
pub const WAIT_OBJECT_0 = std.os.windows.WAIT_OBJECT_0;
pub const WAIT_TIMEOUT = std.os.windows.WAIT_TIMEOUT;
pub const WAIT_FAILED = std.os.windows.WAIT_FAILED;
pub const HANDLE_FLAG_INHERIT = std.os.windows.HANDLE_FLAG_INHERIT;
pub const HANDLE_FLAG_PROTECT_FROM_CLOSE = std.os.windows.HANDLE_FLAG_PROTECT_FROM_CLOSE;
pub const MOVEFILE_COPY_ALLOWED = std.os.windows.MOVEFILE_COPY_ALLOWED;
pub const MOVEFILE_CREATE_HARDLINK = std.os.windows.MOVEFILE_CREATE_HARDLINK;
pub const MOVEFILE_DELAY_UNTIL_REBOOT = std.os.windows.MOVEFILE_DELAY_UNTIL_REBOOT;
pub const MOVEFILE_FAIL_IF_NOT_TRACKABLE = std.os.windows.MOVEFILE_FAIL_IF_NOT_TRACKABLE;
pub const MOVEFILE_REPLACE_EXISTING = std.os.windows.MOVEFILE_REPLACE_EXISTING;
pub const MOVEFILE_WRITE_THROUGH = std.os.windows.MOVEFILE_WRITE_THROUGH;
pub const FILE_BEGIN = std.os.windows.FILE_BEGIN;
pub const FILE_CURRENT = std.os.windows.FILE_CURRENT;
pub const FILE_END = std.os.windows.FILE_END;
pub const HEAP_CREATE_ENABLE_EXECUTE = std.os.windows.HEAP_CREATE_ENABLE_EXECUTE;
pub const HEAP_REALLOC_IN_PLACE_ONLY = std.os.windows.HEAP_REALLOC_IN_PLACE_ONLY;
pub const HEAP_GENERATE_EXCEPTIONS = std.os.windows.HEAP_GENERATE_EXCEPTIONS;
pub const HEAP_NO_SERIALIZE = std.os.windows.HEAP_NO_SERIALIZE;
pub const MEM_COMMIT = std.os.windows.MEM_COMMIT;
pub const MEM_RESERVE = std.os.windows.MEM_RESERVE;
pub const MEM_FREE = std.os.windows.MEM_FREE;
pub const MEM_RESET = std.os.windows.MEM_RESET;
pub const MEM_RESET_UNDO = std.os.windows.MEM_RESET_UNDO;
pub const MEM_LARGE_PAGES = std.os.windows.MEM_LARGE_PAGES;
pub const MEM_PHYSICAL = std.os.windows.MEM_PHYSICAL;
pub const MEM_TOP_DOWN = std.os.windows.MEM_TOP_DOWN;
pub const MEM_WRITE_WATCH = std.os.windows.MEM_WRITE_WATCH;
pub const PAGE_EXECUTE = std.os.windows.PAGE_EXECUTE;
pub const PAGE_EXECUTE_READ = std.os.windows.PAGE_EXECUTE_READ;
pub const PAGE_EXECUTE_READWRITE = std.os.windows.PAGE_EXECUTE_READWRITE;
pub const PAGE_EXECUTE_WRITECOPY = std.os.windows.PAGE_EXECUTE_WRITECOPY;
pub const PAGE_NOACCESS = std.os.windows.PAGE_NOACCESS;
pub const PAGE_READONLY = std.os.windows.PAGE_READONLY;
pub const PAGE_READWRITE = std.os.windows.PAGE_READWRITE;
pub const PAGE_WRITECOPY = std.os.windows.PAGE_WRITECOPY;
pub const PAGE_TARGETS_INVALID = std.os.windows.PAGE_TARGETS_INVALID;
pub const PAGE_TARGETS_NO_UPDATE = std.os.windows.PAGE_TARGETS_NO_UPDATE;
pub const PAGE_GUARD = std.os.windows.PAGE_GUARD;
pub const PAGE_NOCACHE = std.os.windows.PAGE_NOCACHE;
pub const PAGE_WRITECOMBINE = std.os.windows.PAGE_WRITECOMBINE;
pub const MEM_COALESCE_PLACEHOLDERS = std.os.windows.MEM_COALESCE_PLACEHOLDERS;
pub const MEM_RESERVE_PLACEHOLDERS = std.os.windows.MEM_RESERVE_PLACEHOLDERS;
pub const MEM_DECOMMIT = std.os.windows.MEM_DECOMMIT;
pub const MEM_RELEASE = std.os.windows.MEM_RELEASE;
pub const PTHREAD_START_ROUTINE = std.os.windows.PTHREAD_START_ROUTINE;
pub const LPTHREAD_START_ROUTINE = std.os.windows.LPTHREAD_START_ROUTINE;
pub const WIN32_FIND_DATAW = std.os.windows.WIN32_FIND_DATAW;
pub const FILETIME = std.os.windows.FILETIME;
pub const SYSTEM_INFO = std.os.windows.SYSTEM_INFO;
pub const HRESULT = std.os.windows.HRESULT;
pub const KNOWNFOLDERID = std.os.windows.KNOWNFOLDERID;
pub const GUID = std.os.windows.GUID;
pub const FOLDERID_LocalAppData = std.os.windows.FOLDERID_LocalAppData;
pub const KF_FLAG_DEFAULT = std.os.windows.KF_FLAG_DEFAULT;
pub const KF_FLAG_NO_APPCONTAINER_REDIRECTION = std.os.windows.KF_FLAG_NO_APPCONTAINER_REDIRECTION;
pub const KF_FLAG_CREATE = std.os.windows.KF_FLAG_CREATE;
pub const KF_FLAG_DONT_VERIFY = std.os.windows.KF_FLAG_DONT_VERIFY;
pub const KF_FLAG_DONT_UNEXPAND = std.os.windows.KF_FLAG_DONT_UNEXPAND;
pub const KF_FLAG_NO_ALIAS = std.os.windows.KF_FLAG_NO_ALIAS;
pub const KF_FLAG_INIT = std.os.windows.KF_FLAG_INIT;
pub const KF_FLAG_DEFAULT_PATH = std.os.windows.KF_FLAG_DEFAULT_PATH;
pub const KF_FLAG_NOT_PARENT_RELATIVE = std.os.windows.KF_FLAG_NOT_PARENT_RELATIVE;
pub const KF_FLAG_SIMPLE_IDLIST = std.os.windows.KF_FLAG_SIMPLE_IDLIST;
pub const KF_FLAG_ALIAS_ONLY = std.os.windows.KF_FLAG_ALIAS_ONLY;
pub const S_OK = std.os.windows.S_OK;
pub const S_FALSE = std.os.windows.S_FALSE;
pub const E_NOTIMPL = std.os.windows.E_NOTIMPL;
pub const E_NOINTERFACE = std.os.windows.E_NOINTERFACE;
pub const E_POINTER = std.os.windows.E_POINTER;
pub const E_ABORT = std.os.windows.E_ABORT;
pub const E_FAIL = std.os.windows.E_FAIL;
pub const E_UNEXPECTED = std.os.windows.E_UNEXPECTED;
pub const E_ACCESSDENIED = std.os.windows.E_ACCESSDENIED;
pub const E_HANDLE = std.os.windows.E_HANDLE;
pub const E_OUTOFMEMORY = std.os.windows.E_OUTOFMEMORY;
pub const E_INVALIDARG = std.os.windows.E_INVALIDARG;
pub const FILE_FLAG_BACKUP_SEMANTICS = std.os.windows.FILE_FLAG_BACKUP_SEMANTICS;
pub const FILE_FLAG_DELETE_ON_CLOSE = std.os.windows.FILE_FLAG_DELETE_ON_CLOSE;
pub const FILE_FLAG_NO_BUFFERING = std.os.windows.FILE_FLAG_NO_BUFFERING;
pub const FILE_FLAG_OPEN_NO_RECALL = std.os.windows.FILE_FLAG_OPEN_NO_RECALL;
pub const FILE_FLAG_OPEN_REPARSE_POINT = std.os.windows.FILE_FLAG_OPEN_REPARSE_POINT;
pub const FILE_FLAG_OVERLAPPED = std.os.windows.FILE_FLAG_OVERLAPPED;
pub const FILE_FLAG_POSIX_SEMANTICS = std.os.windows.FILE_FLAG_POSIX_SEMANTICS;
pub const FILE_FLAG_RANDOM_ACCESS = std.os.windows.FILE_FLAG_RANDOM_ACCESS;
pub const FILE_FLAG_SESSION_AWARE = std.os.windows.FILE_FLAG_SESSION_AWARE;
pub const FILE_FLAG_SEQUENTIAL_SCAN = std.os.windows.FILE_FLAG_SEQUENTIAL_SCAN;
pub const FILE_FLAG_WRITE_THROUGH = std.os.windows.FILE_FLAG_WRITE_THROUGH;
pub const RECT = std.os.windows.RECT;
pub const SMALL_RECT = std.os.windows.SMALL_RECT;
pub const POINT = std.os.windows.POINT;
pub const COORD = std.os.windows.COORD;
pub const CREATE_UNICODE_ENVIRONMENT = std.os.windows.CREATE_UNICODE_ENVIRONMENT;
pub const TLS_OUT_OF_INDEXES = std.os.windows.TLS_OUT_OF_INDEXES;
pub const IMAGE_TLS_DIRECTORY = std.os.windows.IMAGE_TLS_DIRECTORY;
pub const IMAGE_TLS_DIRECTORY64 = std.os.windows.IMAGE_TLS_DIRECTORY64;
pub const IMAGE_TLS_DIRECTORY32 = std.os.windows.IMAGE_TLS_DIRECTORY32;
pub const PIMAGE_TLS_CALLBACK = std.os.windows.PIMAGE_TLS_CALLBACK;
pub const PROV_RSA_FULL = std.os.windows.PROV_RSA_FULL;
pub const REGSAM = std.os.windows.REGSAM;
pub const ACCESS_MASK = std.os.windows.ACCESS_MASK;
pub const LSTATUS = std.os.windows.LSTATUS;
pub const SECTION_INHERIT = std.os.windows.SECTION_INHERIT;
pub const SECTION_QUERY = std.os.windows.SECTION_QUERY;
pub const SECTION_MAP_WRITE = std.os.windows.SECTION_MAP_WRITE;
pub const SECTION_MAP_READ = std.os.windows.SECTION_MAP_READ;
pub const SECTION_MAP_EXECUTE = std.os.windows.SECTION_MAP_EXECUTE;
pub const SECTION_EXTEND_SIZE = std.os.windows.SECTION_EXTEND_SIZE;
pub const SECTION_ALL_ACCESS = std.os.windows.SECTION_ALL_ACCESS;
pub const SEC_64K_PAGES = std.os.windows.SEC_64K_PAGES;
pub const SEC_FILE = std.os.windows.SEC_FILE;
pub const SEC_IMAGE = std.os.windows.SEC_IMAGE;
pub const SEC_PROTECTED_IMAGE = std.os.windows.SEC_PROTECTED_IMAGE;
pub const SEC_RESERVE = std.os.windows.SEC_RESERVE;
pub const SEC_COMMIT = std.os.windows.SEC_COMMIT;
pub const SEC_IMAGE_NO_EXECUTE = std.os.windows.SEC_IMAGE_NO_EXECUTE;
pub const SEC_NOCACHE = std.os.windows.SEC_NOCACHE;
pub const SEC_WRITECOMBINE = std.os.windows.SEC_WRITECOMBINE;
pub const SEC_LARGE_PAGES = std.os.windows.SEC_LARGE_PAGES;
pub const HKEY = std.os.windows.HKEY;
pub const HKEY_CLASSES_ROOT = std.os.windows.HKEY_CLASSES_ROOT;
pub const HKEY_CURRENT_USER = std.os.windows.HKEY_CURRENT_USER;
pub const HKEY_LOCAL_MACHINE = std.os.windows.HKEY_LOCAL_MACHINE;
pub const HKEY_USERS = std.os.windows.HKEY_USERS;
pub const HKEY_PERFORMANCE_DATA = std.os.windows.HKEY_PERFORMANCE_DATA;
pub const HKEY_PERFORMANCE_TEXT = std.os.windows.HKEY_PERFORMANCE_TEXT;
pub const HKEY_PERFORMANCE_NLSTEXT = std.os.windows.HKEY_PERFORMANCE_NLSTEXT;
pub const HKEY_CURRENT_CONFIG = std.os.windows.HKEY_CURRENT_CONFIG;
pub const HKEY_DYN_DATA = std.os.windows.HKEY_DYN_DATA;
pub const HKEY_CURRENT_USER_LOCAL_SETTINGS = std.os.windows.HKEY_CURRENT_USER_LOCAL_SETTINGS;
pub const KEY_ALL_ACCESS = std.os.windows.KEY_ALL_ACCESS;
pub const KEY_CREATE_LINK = std.os.windows.KEY_CREATE_LINK;
pub const KEY_CREATE_SUB_KEY = std.os.windows.KEY_CREATE_SUB_KEY;
pub const KEY_ENUMERATE_SUB_KEYS = std.os.windows.KEY_ENUMERATE_SUB_KEYS;
pub const KEY_EXECUTE = std.os.windows.KEY_EXECUTE;
pub const KEY_NOTIFY = std.os.windows.KEY_NOTIFY;
pub const KEY_QUERY_VALUE = std.os.windows.KEY_QUERY_VALUE;
pub const KEY_READ = std.os.windows.KEY_READ;
pub const KEY_SET_VALUE = std.os.windows.KEY_SET_VALUE;
pub const KEY_WOW64_32KEY = std.os.windows.KEY_WOW64_32KEY;
pub const KEY_WOW64_64KEY = std.os.windows.KEY_WOW64_64KEY;
pub const KEY_WRITE = std.os.windows.KEY_WRITE;
pub const REG_OPTION_OPEN_LINK = std.os.windows.REG_OPTION_OPEN_LINK;
pub const RTL_QUERY_REGISTRY_TABLE = std.os.windows.RTL_QUERY_REGISTRY_TABLE;
pub const RTL_QUERY_REGISTRY_ROUTINE = std.os.windows.RTL_QUERY_REGISTRY_ROUTINE;
pub const RTL_REGISTRY_ABSOLUTE = std.os.windows.RTL_REGISTRY_ABSOLUTE;
pub const RTL_REGISTRY_SERVICES = std.os.windows.RTL_REGISTRY_SERVICES;
pub const RTL_REGISTRY_CONTROL = std.os.windows.RTL_REGISTRY_CONTROL;
pub const RTL_REGISTRY_WINDOWS_NT = std.os.windows.RTL_REGISTRY_WINDOWS_NT;
pub const RTL_REGISTRY_DEVICEMAP = std.os.windows.RTL_REGISTRY_DEVICEMAP;
pub const RTL_REGISTRY_USER = std.os.windows.RTL_REGISTRY_USER;
pub const RTL_REGISTRY_MAXIMUM = std.os.windows.RTL_REGISTRY_MAXIMUM;
pub const RTL_REGISTRY_HANDLE = std.os.windows.RTL_REGISTRY_HANDLE;
pub const RTL_REGISTRY_OPTIONAL = std.os.windows.RTL_REGISTRY_OPTIONAL;
pub const RTL_QUERY_REGISTRY_SUBKEY = std.os.windows.RTL_QUERY_REGISTRY_SUBKEY;
pub const RTL_QUERY_REGISTRY_TOPKEY = std.os.windows.RTL_QUERY_REGISTRY_TOPKEY;
pub const RTL_QUERY_REGISTRY_REQUIRED = std.os.windows.RTL_QUERY_REGISTRY_REQUIRED;
pub const RTL_QUERY_REGISTRY_NOVALUE = std.os.windows.RTL_QUERY_REGISTRY_NOVALUE;
pub const RTL_QUERY_REGISTRY_NOEXPAND = std.os.windows.RTL_QUERY_REGISTRY_NOEXPAND;
pub const RTL_QUERY_REGISTRY_DIRECT = std.os.windows.RTL_QUERY_REGISTRY_DIRECT;
pub const RTL_QUERY_REGISTRY_DELETE = std.os.windows.RTL_QUERY_REGISTRY_DELETE;
pub const RTL_QUERY_REGISTRY_TYPECHECK = std.os.windows.RTL_QUERY_REGISTRY_TYPECHECK;
pub const REG = std.os.windows.REG;
pub const FILE_NOTIFY_INFORMATION = std.os.windows.FILE_NOTIFY_INFORMATION;
pub const FILE_ACTION_ADDED = std.os.windows.FILE_ACTION_ADDED;
pub const FILE_ACTION_REMOVED = std.os.windows.FILE_ACTION_REMOVED;
pub const FILE_ACTION_MODIFIED = std.os.windows.FILE_ACTION_MODIFIED;
pub const FILE_ACTION_RENAMED_OLD_NAME = std.os.windows.FILE_ACTION_RENAMED_OLD_NAME;
pub const FILE_ACTION_RENAMED_NEW_NAME = std.os.windows.FILE_ACTION_RENAMED_NEW_NAME;
pub const LPOVERLAPPED_COMPLETION_ROUTINE = std.os.windows.LPOVERLAPPED_COMPLETION_ROUTINE;
pub const FileNotifyChangeFilter = std.os.windows.FileNotifyChangeFilter;
pub const CONSOLE_SCREEN_BUFFER_INFO = std.os.windows.CONSOLE_SCREEN_BUFFER_INFO;
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING = std.os.windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING;
pub const DISABLE_NEWLINE_AUTO_RETURN = std.os.windows.DISABLE_NEWLINE_AUTO_RETURN;
pub const FOREGROUND_BLUE = std.os.windows.FOREGROUND_BLUE;
pub const FOREGROUND_GREEN = std.os.windows.FOREGROUND_GREEN;
pub const FOREGROUND_RED = std.os.windows.FOREGROUND_RED;
pub const FOREGROUND_INTENSITY = std.os.windows.FOREGROUND_INTENSITY;
pub const LIST_ENTRY = std.os.windows.LIST_ENTRY;
pub const RTL_CRITICAL_SECTION_DEBUG = std.os.windows.RTL_CRITICAL_SECTION_DEBUG;
pub const RTL_CRITICAL_SECTION = std.os.windows.RTL_CRITICAL_SECTION;
pub const CRITICAL_SECTION = std.os.windows.CRITICAL_SECTION;
pub const INIT_ONCE = std.os.windows.INIT_ONCE;
pub const INIT_ONCE_STATIC_INIT = std.os.windows.INIT_ONCE_STATIC_INIT;
pub const INIT_ONCE_FN = std.os.windows.INIT_ONCE_FN;
pub const RTL_RUN_ONCE = std.os.windows.RTL_RUN_ONCE;
pub const RTL_RUN_ONCE_INIT = std.os.windows.RTL_RUN_ONCE_INIT;
pub const COINIT = std.os.windows.COINIT;
pub const MEMORY_BASIC_INFORMATION = std.os.windows.MEMORY_BASIC_INFORMATION;
pub const PMEMORY_BASIC_INFORMATION = std.os.windows.PMEMORY_BASIC_INFORMATION;
pub const PATH_MAX_WIDE = std.os.windows.PATH_MAX_WIDE;
pub const NAME_MAX = std.os.windows.NAME_MAX;
pub const FORMAT_MESSAGE_ALLOCATE_BUFFER = std.os.windows.FORMAT_MESSAGE_ALLOCATE_BUFFER;
pub const FORMAT_MESSAGE_ARGUMENT_ARRAY = std.os.windows.FORMAT_MESSAGE_ARGUMENT_ARRAY;
pub const FORMAT_MESSAGE_FROM_HMODULE = std.os.windows.FORMAT_MESSAGE_FROM_HMODULE;
pub const FORMAT_MESSAGE_FROM_STRING = std.os.windows.FORMAT_MESSAGE_FROM_STRING;
pub const FORMAT_MESSAGE_FROM_SYSTEM = std.os.windows.FORMAT_MESSAGE_FROM_SYSTEM;
pub const FORMAT_MESSAGE_IGNORE_INSERTS = std.os.windows.FORMAT_MESSAGE_IGNORE_INSERTS;
pub const FORMAT_MESSAGE_MAX_WIDTH_MASK = std.os.windows.FORMAT_MESSAGE_MAX_WIDTH_MASK;
pub const EXCEPTION_DATATYPE_MISALIGNMENT = std.os.windows.EXCEPTION_DATATYPE_MISALIGNMENT;
pub const EXCEPTION_ACCESS_VIOLATION = std.os.windows.EXCEPTION_ACCESS_VIOLATION;
pub const EXCEPTION_ILLEGAL_INSTRUCTION = std.os.windows.EXCEPTION_ILLEGAL_INSTRUCTION;
pub const EXCEPTION_STACK_OVERFLOW = std.os.windows.EXCEPTION_STACK_OVERFLOW;
pub const EXCEPTION_CONTINUE_SEARCH = std.os.windows.EXCEPTION_CONTINUE_SEARCH;
pub const EXCEPTION_RECORD = std.os.windows.EXCEPTION_RECORD;
pub const FLOATING_SAVE_AREA = std.os.windows.FLOATING_SAVE_AREA;
pub const M128A = std.os.windows.M128A;
pub const XMM_SAVE_AREA32 = std.os.windows.XMM_SAVE_AREA32;
pub const NEON128 = std.os.windows.NEON128;
pub const CONTEXT = std.os.windows.CONTEXT;
pub const RUNTIME_FUNCTION = std.os.windows.RUNTIME_FUNCTION;
pub const KNONVOLATILE_CONTEXT_POINTERS = std.os.windows.KNONVOLATILE_CONTEXT_POINTERS;
pub const EXCEPTION_POINTERS = std.os.windows.EXCEPTION_POINTERS;
pub const VECTORED_EXCEPTION_HANDLER = std.os.windows.VECTORED_EXCEPTION_HANDLER;
pub const EXCEPTION_DISPOSITION = std.os.windows.EXCEPTION_DISPOSITION;
pub const EXCEPTION_ROUTINE = std.os.windows.EXCEPTION_ROUTINE;
pub const UNWIND_HISTORY_TABLE_SIZE = std.os.windows.UNWIND_HISTORY_TABLE_SIZE;
pub const UNWIND_HISTORY_TABLE_ENTRY = std.os.windows.UNWIND_HISTORY_TABLE_ENTRY;
pub const UNWIND_HISTORY_TABLE = std.os.windows.UNWIND_HISTORY_TABLE;
pub const UNW_FLAG_NHANDLER = std.os.windows.UNW_FLAG_NHANDLER;
pub const UNW_FLAG_EHANDLER = std.os.windows.UNW_FLAG_EHANDLER;
pub const UNW_FLAG_UHANDLER = std.os.windows.UNW_FLAG_UHANDLER;
pub const UNW_FLAG_CHAININFO = std.os.windows.UNW_FLAG_CHAININFO;
pub const OBJECT_ATTRIBUTES = std.os.windows.OBJECT_ATTRIBUTES;
pub const OBJ_INHERIT = std.os.windows.OBJ_INHERIT;
pub const OBJ_PERMANENT = std.os.windows.OBJ_PERMANENT;
pub const OBJ_EXCLUSIVE = std.os.windows.OBJ_EXCLUSIVE;
pub const OBJ_CASE_INSENSITIVE = std.os.windows.OBJ_CASE_INSENSITIVE;
pub const OBJ_OPENIF = std.os.windows.OBJ_OPENIF;
pub const OBJ_OPENLINK = std.os.windows.OBJ_OPENLINK;
pub const OBJ_KERNEL_HANDLE = std.os.windows.OBJ_KERNEL_HANDLE;
pub const OBJ_VALID_ATTRIBUTES = std.os.windows.OBJ_VALID_ATTRIBUTES;
pub const UNICODE_STRING = std.os.windows.UNICODE_STRING;
pub const ACTIVATION_CONTEXT_DATA = std.os.windows.ACTIVATION_CONTEXT_DATA;
pub const ASSEMBLY_STORAGE_MAP = std.os.windows.ASSEMBLY_STORAGE_MAP;
pub const FLS_CALLBACK_INFO = std.os.windows.FLS_CALLBACK_INFO;
pub const RTL_BITMAP = std.os.windows.RTL_BITMAP;
pub const KAFFINITY = std.os.windows.KAFFINITY;
pub const KPRIORITY = std.os.windows.KPRIORITY;
pub const CLIENT_ID = std.os.windows.CLIENT_ID;
pub const THREAD_BASIC_INFORMATION = std.os.windows.THREAD_BASIC_INFORMATION;
pub const TEB = std.os.windows.TEB;
pub const EXCEPTION_REGISTRATION_RECORD = std.os.windows.EXCEPTION_REGISTRATION_RECORD;
pub const NT_TIB = std.os.windows.NT_TIB;
pub const PEB = std.os.windows.PEB;
pub const PEB_LDR_DATA = std.os.windows.PEB_LDR_DATA;
pub const LDR_DATA_TABLE_ENTRY = std.os.windows.LDR_DATA_TABLE_ENTRY;
pub const RTL_USER_PROCESS_PARAMETERS = std.os.windows.RTL_USER_PROCESS_PARAMETERS;
pub const RTL_DRIVE_LETTER_CURDIR = std.os.windows.RTL_DRIVE_LETTER_CURDIR;
pub const PPS_POST_PROCESS_INIT_ROUTINE = std.os.windows.PPS_POST_PROCESS_INIT_ROUTINE;
pub const FILE_DIRECTORY_INFORMATION = std.os.windows.FILE_DIRECTORY_INFORMATION;
pub const FILE_BOTH_DIR_INFORMATION = std.os.windows.FILE_BOTH_DIR_INFORMATION;
pub const FILE_BOTH_DIRECTORY_INFORMATION = std.os.windows.FILE_BOTH_DIRECTORY_INFORMATION;
pub const IO_APC_ROUTINE = std.os.windows.IO_APC_ROUTINE;
pub const CURDIR = std.os.windows.CURDIR;
pub const DUPLICATE_SAME_ACCESS = std.os.windows.DUPLICATE_SAME_ACCESS;
pub const MODULEINFO = std.os.windows.MODULEINFO;
pub const PSAPI_WS_WATCH_INFORMATION = std.os.windows.PSAPI_WS_WATCH_INFORMATION;
pub const VM_COUNTERS = std.os.windows.VM_COUNTERS;
pub const PROCESS_MEMORY_COUNTERS = std.os.windows.PROCESS_MEMORY_COUNTERS;
pub const PROCESS_MEMORY_COUNTERS_EX = std.os.windows.PROCESS_MEMORY_COUNTERS_EX;
pub const GetProcessMemoryInfoError = std.os.windows.GetProcessMemoryInfoError;
pub const PERFORMANCE_INFORMATION = std.os.windows.PERFORMANCE_INFORMATION;
pub const ENUM_PAGE_FILE_INFORMATION = std.os.windows.ENUM_PAGE_FILE_INFORMATION;
pub const PENUM_PAGE_FILE_CALLBACKW = std.os.windows.PENUM_PAGE_FILE_CALLBACKW;
pub const PENUM_PAGE_FILE_CALLBACKA = std.os.windows.PENUM_PAGE_FILE_CALLBACKA;
pub const PSAPI_WS_WATCH_INFORMATION_EX = std.os.windows.PSAPI_WS_WATCH_INFORMATION_EX;
pub const OSVERSIONINFOW = std.os.windows.OSVERSIONINFOW;
pub const RTL_OSVERSIONINFOW = std.os.windows.RTL_OSVERSIONINFOW;
pub const REPARSE_DATA_BUFFER = std.os.windows.REPARSE_DATA_BUFFER;
pub const SYMBOLIC_LINK_REPARSE_BUFFER = std.os.windows.SYMBOLIC_LINK_REPARSE_BUFFER;
pub const MOUNT_POINT_REPARSE_BUFFER = std.os.windows.MOUNT_POINT_REPARSE_BUFFER;
pub const MAXIMUM_REPARSE_DATA_BUFFER_SIZE = std.os.windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE;
pub const FSCTL_SET_REPARSE_POINT = std.os.windows.FSCTL_SET_REPARSE_POINT;
pub const FSCTL_GET_REPARSE_POINT = std.os.windows.FSCTL_GET_REPARSE_POINT;
pub const IO_REPARSE_TAG_SYMLINK = std.os.windows.IO_REPARSE_TAG_SYMLINK;
pub const IO_REPARSE_TAG_MOUNT_POINT = std.os.windows.IO_REPARSE_TAG_MOUNT_POINT;
pub const SYMLINK_FLAG_RELATIVE = std.os.windows.SYMLINK_FLAG_RELATIVE;
pub const SYMBOLIC_LINK_FLAG_DIRECTORY = std.os.windows.SYMBOLIC_LINK_FLAG_DIRECTORY;
pub const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = std.os.windows.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
pub const MOUNTMGRCONTROLTYPE = std.os.windows.MOUNTMGRCONTROLTYPE;
pub const MOUNTMGR_MOUNT_POINT = std.os.windows.MOUNTMGR_MOUNT_POINT;
pub const MOUNTMGR_MOUNT_POINTS = std.os.windows.MOUNTMGR_MOUNT_POINTS;
pub const IOCTL_MOUNTMGR_QUERY_POINTS = std.os.windows.IOCTL_MOUNTMGR_QUERY_POINTS;
pub const MOUNTMGR_TARGET_NAME = std.os.windows.MOUNTMGR_TARGET_NAME;
pub const MOUNTMGR_VOLUME_PATHS = std.os.windows.MOUNTMGR_VOLUME_PATHS;
pub const IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH = std.os.windows.IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH;
pub const OBJECT_INFORMATION_CLASS = std.os.windows.OBJECT_INFORMATION_CLASS;
pub const OBJECT_NAME_INFORMATION = std.os.windows.OBJECT_NAME_INFORMATION;
pub const SRWLOCK_INIT = std.os.windows.SRWLOCK_INIT;
pub const SRWLOCK = std.os.windows.SRWLOCK;
pub const CONDITION_VARIABLE_INIT = std.os.windows.CONDITION_VARIABLE_INIT;
pub const CONDITION_VARIABLE = std.os.windows.CONDITION_VARIABLE;
pub const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = std.os.windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE = std.os.windows.FILE_SKIP_SET_EVENT_ON_HANDLE;
pub const CTRL_C_EVENT = std.os.windows.CTRL_C_EVENT;
pub const CTRL_BREAK_EVENT = std.os.windows.CTRL_BREAK_EVENT;
pub const CTRL_CLOSE_EVENT = std.os.windows.CTRL_CLOSE_EVENT;
pub const CTRL_LOGOFF_EVENT = std.os.windows.CTRL_LOGOFF_EVENT;
pub const CTRL_SHUTDOWN_EVENT = std.os.windows.CTRL_SHUTDOWN_EVENT;
pub const HANDLER_ROUTINE = std.os.windows.HANDLER_ROUTINE;
pub const PF = std.os.windows.PF;
pub const MAX_WOW64_SHARED_ENTRIES = std.os.windows.MAX_WOW64_SHARED_ENTRIES;
pub const PROCESSOR_FEATURE_MAX = std.os.windows.PROCESSOR_FEATURE_MAX;
pub const MAXIMUM_XSTATE_FEATURES = std.os.windows.MAXIMUM_XSTATE_FEATURES;
pub const KSYSTEM_TIME = std.os.windows.KSYSTEM_TIME;
pub const NT_PRODUCT_TYPE = std.os.windows.NT_PRODUCT_TYPE;
pub const ALTERNATIVE_ARCHITECTURE_TYPE = std.os.windows.ALTERNATIVE_ARCHITECTURE_TYPE;
pub const XSTATE_FEATURE = std.os.windows.XSTATE_FEATURE;
pub const XSTATE_CONFIGURATION = std.os.windows.XSTATE_CONFIGURATION;
pub const KUSER_SHARED_DATA = std.os.windows.KUSER_SHARED_DATA;
pub const SharedUserData = std.os.windows.SharedUserData;
pub const TH32CS_SNAPHEAPLIST = std.os.windows.TH32CS_SNAPHEAPLIST;
pub const TH32CS_SNAPPROCESS = std.os.windows.TH32CS_SNAPPROCESS;
pub const TH32CS_SNAPTHREAD = std.os.windows.TH32CS_SNAPTHREAD;
pub const TH32CS_SNAPMODULE = std.os.windows.TH32CS_SNAPMODULE;
pub const TH32CS_SNAPMODULE32 = std.os.windows.TH32CS_SNAPMODULE32;
pub const TH32CS_SNAPALL = std.os.windows.TH32CS_SNAPALL;
pub const TH32CS_INHERIT = std.os.windows.TH32CS_INHERIT;
pub const MAX_MODULE_NAME32 = std.os.windows.MAX_MODULE_NAME32;
pub const MODULEENTRY32 = std.os.windows.MODULEENTRY32;
pub const SYSTEM_INFORMATION_CLASS = std.os.windows.SYSTEM_INFORMATION_CLASS;
pub const SYSTEM_BASIC_INFORMATION = std.os.windows.SYSTEM_BASIC_INFORMATION;
pub const THREADINFOCLASS = std.os.windows.THREADINFOCLASS;
pub const PROCESSINFOCLASS = std.os.windows.PROCESSINFOCLASS;
pub const PROCESS_BASIC_INFORMATION = std.os.windows.PROCESS_BASIC_INFORMATION;
pub const ReadMemoryError = std.os.windows.ReadMemoryError;
pub const WriteMemoryError = std.os.windows.WriteMemoryError;
pub const ProcessBaseAddressError = std.os.windows.ProcessBaseAddressError;

// functions

pub const OpenFile = std.os.windows.OpenFile;
pub const GetCurrentProcess = std.os.windows.GetCurrentProcess;
pub const GetCurrentProcessId = std.os.windows.GetCurrentProcessId;
pub const GetCurrentThread = std.os.windows.GetCurrentThread;
pub const GetCurrentThreadId = std.os.windows.GetCurrentThreadId;
pub const GetLastError = std.os.windows.GetLastError;
pub const CreatePipe = std.os.windows.CreatePipe;
pub const CreateEventEx = std.os.windows.CreateEventEx;
pub const CreateEventExW = std.os.windows.CreateEventExW;
pub const DeviceIoControl = std.os.windows.DeviceIoControl;
pub const GetOverlappedResult = std.os.windows.GetOverlappedResult;
pub const SetHandleInformation = std.os.windows.SetHandleInformation;
pub const RtlGenRandom = std.os.windows.RtlGenRandom;
pub const WaitForSingleObject = std.os.windows.WaitForSingleObject;
pub const WaitForSingleObjectEx = std.os.windows.WaitForSingleObjectEx;
pub const WaitForMultipleObjectsEx = std.os.windows.WaitForMultipleObjectsEx;
pub const CreateIoCompletionPort = std.os.windows.CreateIoCompletionPort;
pub const PostQueuedCompletionStatus = std.os.windows.PostQueuedCompletionStatus;
pub const GetQueuedCompletionStatus = std.os.windows.GetQueuedCompletionStatus;
pub const GetQueuedCompletionStatusEx = std.os.windows.GetQueuedCompletionStatusEx;
pub const CloseHandle = std.os.windows.CloseHandle;
pub const FindClose = std.os.windows.FindClose;
pub const ReadFile = std.os.windows.ReadFile;
pub const WriteFile = std.os.windows.WriteFile;
pub const SetCurrentDirectory = std.os.windows.SetCurrentDirectory;
pub const GetCurrentDirectory = std.os.windows.GetCurrentDirectory;
pub const CreateSymbolicLink = std.os.windows.CreateSymbolicLink;
pub const ReadLink = std.os.windows.ReadLink;
pub const DeleteFile = std.os.windows.DeleteFile;
pub const MoveFileEx = std.os.windows.MoveFileEx;
pub const MoveFileExW = std.os.windows.MoveFileExW;
pub const GetStdHandle = std.os.windows.GetStdHandle;
pub const SetFilePointerEx_BEGIN = std.os.windows.SetFilePointerEx_BEGIN;
pub const SetFilePointerEx_CURRENT = std.os.windows.SetFilePointerEx_CURRENT;
pub const SetFilePointerEx_END = std.os.windows.SetFilePointerEx_END;
pub const SetFilePointerEx_CURRENT_get = std.os.windows.SetFilePointerEx_CURRENT_get;
pub const QueryObjectName = std.os.windows.QueryObjectName;
pub const GetFinalPathNameByHandle = std.os.windows.GetFinalPathNameByHandle;
pub const GetFileSizeEx = std.os.windows.GetFileSizeEx;
pub const GetFileAttributes = std.os.windows.GetFileAttributes;
pub const GetFileAttributesW = std.os.windows.GetFileAttributesW;
pub const WSAStartup = std.os.windows.WSAStartup;
pub const WSACleanup = std.os.windows.WSACleanup;
pub const callWSAStartup = std.os.windows.callWSAStartup;
pub const WSASocketW = std.os.windows.WSASocketW;
pub const bind = std.os.windows.bind;
pub const listen = std.os.windows.listen;
pub const closesocket = std.os.windows.closesocket;
pub const accept = std.os.windows.accept;
pub const getsockname = std.os.windows.getsockname;
pub const getpeername = std.os.windows.getpeername;
pub const sendmsg = std.os.windows.sendmsg;
pub const sendto = std.os.windows.sendto;
pub const recvfrom = std.os.windows.recvfrom;
pub const poll = std.os.windows.poll;
pub const WSAIoctl = std.os.windows.WSAIoctl;
pub const GetModuleFileNameW = std.os.windows.GetModuleFileNameW;
pub const TerminateProcess = std.os.windows.TerminateProcess;
pub const VirtualAlloc = std.os.windows.VirtualAlloc;
pub const VirtualFree = std.os.windows.VirtualFree;
pub const VirtualProtect = std.os.windows.VirtualProtect;
pub const VirtualProtectEx = std.os.windows.VirtualProtectEx;
pub const VirtualQuery = std.os.windows.VirtualQuery;
pub const SetConsoleTextAttribute = std.os.windows.SetConsoleTextAttribute;
pub const SetConsoleCtrlHandler = std.os.windows.SetConsoleCtrlHandler;
pub const SetFileCompletionNotificationModes = std.os.windows.SetFileCompletionNotificationModes;
pub const GetEnvironmentStringsW = std.os.windows.GetEnvironmentStringsW;
pub const FreeEnvironmentStringsW = std.os.windows.FreeEnvironmentStringsW;
pub const GetEnvironmentVariableW = std.os.windows.GetEnvironmentVariableW;
pub const CreateProcessW = std.os.windows.CreateProcessW;
pub const LoadLibraryW = std.os.windows.LoadLibraryW;
pub const LoadLibraryExW = std.os.windows.LoadLibraryExW;
pub const FreeLibrary = std.os.windows.FreeLibrary;
pub const QueryPerformanceFrequency = std.os.windows.QueryPerformanceFrequency;
pub const QueryPerformanceCounter = std.os.windows.QueryPerformanceCounter;
pub const InitOnceExecuteOnce = std.os.windows.InitOnceExecuteOnce;
pub const SetFileTime = std.os.windows.SetFileTime;
pub const LockFile = std.os.windows.LockFile;
pub const UnlockFile = std.os.windows.UnlockFile;
pub const teb = std.os.windows.teb;
pub const peb = std.os.windows.peb;
pub const fromSysTime = std.os.windows.fromSysTime;
pub const toSysTime = std.os.windows.toSysTime;
pub const fileTimeToNanoSeconds = std.os.windows.fileTimeToNanoSeconds;
pub const nanoSecondsToFileTime = std.os.windows.nanoSecondsToFileTime;
pub const eqlIgnoreCaseWTF16 = std.os.windows.eqlIgnoreCaseWTF16;
pub const eqlIgnoreCaseWtf8 = std.os.windows.eqlIgnoreCaseWtf8;
pub const removeDotDirsSanitized = std.os.windows.removeDotDirsSanitized;
pub const normalizePath = std.os.windows.normalizePath;
pub const cStrToPrefixedFileW = std.os.windows.cStrToPrefixedFileW;
pub const sliceToPrefixedFileW = std.os.windows.sliceToPrefixedFileW;
pub const wToPrefixedFileW = std.os.windows.wToPrefixedFileW;
pub const getNamespacePrefix = std.os.windows.getNamespacePrefix;
pub const getUnprefixedPathType = std.os.windows.getUnprefixedPathType;
pub const ntToWin32Namespace = std.os.windows.ntToWin32Namespace;
pub const loadWinsockExtensionFunction = std.os.windows.loadWinsockExtensionFunction;
pub const unexpectedError = std.os.windows.unexpectedError;
pub const unexpectedWSAError = std.os.windows.unexpectedWSAError;
pub const unexpectedStatus = std.os.windows.unexpectedStatus;
pub const CTL_CODE = std.os.windows.CTL_CODE;
pub const HRESULT_CODE = std.os.windows.HRESULT_CODE;
pub const FileInformationIterator = std.os.windows.FileInformationIterator;
pub const GetProcessMemoryInfo = std.os.windows.GetProcessMemoryInfo;
pub const IsProcessorFeaturePresent = std.os.windows.IsProcessorFeaturePresent;
pub const ReadProcessMemory = std.os.windows.ReadProcessMemory;
pub const WriteProcessMemory = std.os.windows.WriteProcessMemory;
pub const ProcessBaseAddress = std.os.windows.ProcessBaseAddress;
