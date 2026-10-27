//go:build windows

package winfilepicker

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	coinitApartmentThreaded = 0x2
	clsctxInprocServer      = 0x1
	fosPickFolders          = 0x00000020
	fosAllowMultiSelect     = 0x00000200
	fosFileMustExist        = 0x00001000
	sigdnFileSysPath        = 0x80028000
	hrCancelled             = 0x800704C7

	smCxIcon   = 11
	smCxSmIcon = 49

	whCBT        = 5
	hcbtActivate = 5
	wmSetIcon    = 0x0080
	iconSmall    = 0
	iconBig      = 1

	dpiAwarenessContextPerMonitorAwareV2 = ^uintptr(3)
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCoInitializeEx               = ole32.NewProc("CoInitializeEx")
	procCoUninitialize               = ole32.NewProc("CoUninitialize")
	procCoCreateInstance             = ole32.NewProc("CoCreateInstance")
	procCoTaskMemFree                = ole32.NewProc("CoTaskMemFree")
	procSetWindowsHookExW            = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx          = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx               = user32.NewProc("CallNextHookEx")
	procSendMessageW                 = user32.NewProc("SendMessageW")
	procGetWindowsDirectoryW         = kernel32.NewProc("GetWindowsDirectoryW")
	procGetCurrentThreadId           = kernel32.NewProc("GetCurrentThreadId")
	procSHDefExtractIconW            = shell32.NewProc("SHDefExtractIconW")
	procSetThreadDpiAwarenessContext = user32.NewProc("SetThreadDpiAwarenessContext")
	procGetDpiForWindow              = user32.NewProc("GetDpiForWindow")
	procGetSystemMetricsForDpi       = user32.NewProc("GetSystemMetricsForDpi")
	procGetSystemMetrics             = user32.NewProc("GetSystemMetrics")
)

type guid struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

var (
	clsidFileOpenDialog = guid{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog  = guid{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

type comdlgFilterSpec struct {
	pszName *uint16
	pszSpec *uint16
}

type iFileOpenDialogVtbl struct {
	queryInterface      uintptr
	addRef              uintptr
	release             uintptr
	show                uintptr
	setFileTypes        uintptr
	setFileTypeIndex    uintptr
	getFileTypeIndex    uintptr
	advise              uintptr
	unadvise            uintptr
	setOptions          uintptr
	getOptions          uintptr
	setDefaultFolder    uintptr
	setFolder           uintptr
	getFolder           uintptr
	getCurrentSelection uintptr
	setFileName         uintptr
	getFileName         uintptr
	setTitle            uintptr
	setOkButtonLabel    uintptr
	setFileNameLabel    uintptr
	getResult           uintptr
	addPlace            uintptr
	setDefaultExtension uintptr
	close               uintptr
	setClientGuid       uintptr
	clearClientData     uintptr
	setFilter           uintptr
	getResults          uintptr
	getSelectedItems    uintptr
}

type iFileOpenDialog struct {
	lpVtbl *iFileOpenDialogVtbl
}

type iShellItemVtbl struct {
	queryInterface uintptr
	addRef         uintptr
	release        uintptr
	bindToHandler  uintptr
	getParent      uintptr
	getDisplayName uintptr
	getAttributes  uintptr
	compare        uintptr
}

type iShellItem struct {
	lpVtbl *iShellItemVtbl
}

type iShellItemArrayVtbl struct {
	queryInterface             uintptr
	addRef                     uintptr
	release                    uintptr
	bindToHandler              uintptr
	getPropertyStore           uintptr
	getPropertyDescriptionList uintptr
	getAttributes              uintptr
	getCount                   uintptr
	getItemAt                  uintptr
	enumItems                  uintptr
}

type iShellItemArray struct {
	lpVtbl *iShellItemArrayVtbl
}

func failed(hr uintptr) bool {
	return int32(hr) < 0
}

func newHRError(op string, hr uintptr) error {
	return fmt.Errorf("winfilepicker: %s failed (HRESULT 0x%08X)", op, uint32(hr))
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	for *(*uint16)(end) != 0 {
		end = unsafe.Add(end, 2)
	}
	length := int(uintptr(end)-uintptr(unsafe.Pointer(p))) / 2
	return syscall.UTF16ToString(unsafe.Slice(p, length))
}

func (dialog *iFileOpenDialog) release() {
	syscall.SyscallN(dialog.lpVtbl.release, uintptr(unsafe.Pointer(dialog)))
}

func (dialog *iFileOpenDialog) showDialog(owner uintptr) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.show, uintptr(unsafe.Pointer(dialog)), owner)
	return hr
}

func (dialog *iFileOpenDialog) getOptions(options *uint32) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.getOptions, uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(options)))
	return hr
}

func (dialog *iFileOpenDialog) setOptions(options uint32) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.setOptions, uintptr(unsafe.Pointer(dialog)), uintptr(options))
	return hr
}

func (dialog *iFileOpenDialog) setTitle(title *uint16) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.setTitle, uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(title)))
	return hr
}

func (dialog *iFileOpenDialog) setFileTypes(specs []comdlgFilterSpec) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.setFileTypes, uintptr(unsafe.Pointer(dialog)), uintptr(len(specs)), uintptr(unsafe.Pointer(&specs[0])))
	return hr
}

func (dialog *iFileOpenDialog) getResult(item **iShellItem) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.getResult, uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(item)))
	return hr
}

func (dialog *iFileOpenDialog) getResults(items **iShellItemArray) uintptr {
	hr, _, _ := syscall.SyscallN(dialog.lpVtbl.getResults, uintptr(unsafe.Pointer(dialog)), uintptr(unsafe.Pointer(items)))
	return hr
}

func (item *iShellItem) release() {
	syscall.SyscallN(item.lpVtbl.release, uintptr(unsafe.Pointer(item)))
}

func (item *iShellItem) filePath() (string, error) {
	var pszPath *uint16
	hr, _, _ := syscall.SyscallN(item.lpVtbl.getDisplayName, uintptr(unsafe.Pointer(item)), sigdnFileSysPath, uintptr(unsafe.Pointer(&pszPath)))
	if failed(hr) {
		return "", newHRError("IShellItem::GetDisplayName", hr)
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(pszPath)))
	if pszPath == nil {
		return "", nil
	}
	return utf16PtrToString(pszPath), nil
}

func (items *iShellItemArray) release() {
	syscall.SyscallN(items.lpVtbl.release, uintptr(unsafe.Pointer(items)))
}

func (items *iShellItemArray) count() (uint32, error) {
	var n uint32
	hr, _, _ := syscall.SyscallN(items.lpVtbl.getCount, uintptr(unsafe.Pointer(items)), uintptr(unsafe.Pointer(&n)))
	if failed(hr) {
		return 0, newHRError("IShellItemArray::GetCount", hr)
	}
	return n, nil
}

func (items *iShellItemArray) itemAt(index uint32) (*iShellItem, error) {
	var item *iShellItem
	hr, _, _ := syscall.SyscallN(items.lpVtbl.getItemAt, uintptr(unsafe.Pointer(items)), uintptr(index), uintptr(unsafe.Pointer(&item)))
	if failed(hr) {
		return nil, newHRError("IShellItemArray::GetItemAt", hr)
	}
	return item, nil
}

type iconSize struct {
	big   uint32
	small uint32
}

type iconPair struct {
	big   uintptr
	small uintptr
}

var (
	explorerIconsMu sync.Mutex
	explorerIcons   = make(map[iconSize]iconPair)
)

func enablePerMonitorDPI() uintptr {
	if err := procSetThreadDpiAwarenessContext.Find(); err != nil {
		return 0
	}
	previous, _, _ := procSetThreadDpiAwarenessContext.Call(dpiAwarenessContextPerMonitorAwareV2)
	return previous
}

func windowDPI(hwnd uintptr) uint32 {
	if err := procGetDpiForWindow.Find(); err != nil {
		return 96
	}
	dpi, _, _ := procGetDpiForWindow.Call(hwnd)
	if dpi == 0 {
		return 96
	}
	return uint32(dpi)
}

func dpiMetric(index int, dpi uint32) uint32 {
	if err := procGetSystemMetricsForDpi.Find(); err == nil {
		v, _, _ := procGetSystemMetricsForDpi.Call(uintptr(index), uintptr(dpi))
		if v != 0 {
			return uint32(v)
		}
	}
	v, _, _ := procGetSystemMetrics.Call(uintptr(index))
	if v == 0 {
		return 32
	}
	return uint32(v)
}

func explorerIconsFor(sizes iconSize) (iconPair, error) {
	explorerIconsMu.Lock()
	defer explorerIconsMu.Unlock()
	if pair, ok := explorerIcons[sizes]; ok {
		return pair, nil
	}
	pair, err := loadExplorerIcons(sizes)
	if err != nil {
		return iconPair{}, err
	}
	explorerIcons[sizes] = pair
	return pair, nil
}

func loadExplorerIcons(sizes iconSize) (iconPair, error) {
	if err := procSHDefExtractIconW.Find(); err != nil {
		return iconPair{}, err
	}
	path, err := explorerPath()
	if err != nil {
		return iconPair{}, err
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return iconPair{}, err
	}
	var pair iconPair
	packed := uintptr(sizes.big) | uintptr(sizes.small)<<16
	hr, _, _ := procSHDefExtractIconW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0,
		uintptr(unsafe.Pointer(&pair.big)),
		uintptr(unsafe.Pointer(&pair.small)),
		packed,
	)
	if failed(hr) || pair.big == 0 || pair.small == 0 {
		return iconPair{}, fmt.Errorf("winfilepicker: SHDefExtractIconW failed for %s", path)
	}
	return pair, nil
}

func explorerPath() (string, error) {
	buf := make([]uint16, 260)
	n, _, _ := procGetWindowsDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return "", fmt.Errorf("winfilepicker: GetWindowsDirectoryW failed")
	}
	return syscall.UTF16ToString(buf[:n]) + `\explorer.exe`, nil
}

var cbtHookProcAddr = syscall.NewCallback(cbtProc)

func cbtProc(nCode, wParam, lParam uintptr) uintptr {
	defer func() {
		_ = recover()
	}()
	if nCode == hcbtActivate {
		setExplorerIcon(wParam)
	}
	next, _, _ := procCallNextHookEx.Call(0, nCode, wParam, lParam)
	return next
}

func setExplorerIcon(hwnd uintptr) {
	dpi := windowDPI(hwnd)
	sizes := iconSize{big: dpiMetric(smCxIcon, dpi), small: dpiMetric(smCxSmIcon, dpi)}
	pair, err := explorerIconsFor(sizes)
	if err != nil {
		return
	}
	procSendMessageW.Call(hwnd, wmSetIcon, iconBig, pair.big)
	procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, pair.small)
}

func normalizeExt(ext string) string {
	e := strings.TrimSpace(ext)
	e = strings.TrimPrefix(e, "*.")
	e = strings.TrimPrefix(e, ".")
	return e
}

func buildFilterSpec(extensions []string) ([]comdlgFilterSpec, error) {
	patterns := make([]string, 0, len(extensions))
	for _, ext := range extensions {
		e := normalizeExt(ext)
		if e == "" {
			continue
		}
		patterns = append(patterns, "*."+e)
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	name, err := syscall.UTF16PtrFromString("Supported Files")
	if err != nil {
		return nil, fmt.Errorf("winfilepicker: invalid extension filter: %w", err)
	}
	spec, err := syscall.UTF16PtrFromString(strings.Join(patterns, ";"))
	if err != nil {
		return nil, fmt.Errorf("winfilepicker: invalid extension filter: %w", err)
	}
	return []comdlgFilterSpec{{pszName: name, pszSpec: spec}}, nil
}

func showOpenDialog(title string, multiSelect bool, pickFolders bool, extensions []string) ([]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	previousDPI := enablePerMonitorDPI()
	if previousDPI != 0 {
		defer procSetThreadDpiAwarenessContext.Call(previousDPI)
	}

	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	if failed(hr) {
		return nil, newHRError("CoInitializeEx", hr)
	}
	defer procCoUninitialize.Call()

	var dialog *iFileOpenDialog
	hr, _, _ = procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidFileOpenDialog)),
		0,
		clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIFileOpenDialog)),
		uintptr(unsafe.Pointer(&dialog)),
	)
	if failed(hr) {
		return nil, newHRError("CoCreateInstance", hr)
	}
	defer dialog.release()

	var options uint32
	hr = dialog.getOptions(&options)
	if failed(hr) {
		return nil, newHRError("IFileOpenDialog::GetOptions", hr)
	}

	options |= fosFileMustExist
	if pickFolders {
		options |= fosPickFolders
	}
	if multiSelect {
		options |= fosAllowMultiSelect
	}

	hr = dialog.setOptions(options)
	if failed(hr) {
		return nil, newHRError("IFileOpenDialog::SetOptions", hr)
	}

	if title != "" {
		titlePtr, err := syscall.UTF16PtrFromString(title)
		if err != nil {
			return nil, fmt.Errorf("winfilepicker: invalid title: %w", err)
		}
		hr = dialog.setTitle(titlePtr)
		if failed(hr) {
			return nil, newHRError("IFileOpenDialog::SetTitle", hr)
		}
	}

	if len(extensions) > 0 && !pickFolders {
		specs, err := buildFilterSpec(extensions)
		if err != nil {
			return nil, err
		}
		if len(specs) > 0 {
			hr = dialog.setFileTypes(specs)
			if failed(hr) {
				return nil, newHRError("IFileOpenDialog::SetFileTypes", hr)
			}
		}
	}

	threadID, _, _ := procGetCurrentThreadId.Call()
	hook, _, _ := procSetWindowsHookExW.Call(whCBT, cbtHookProcAddr, 0, threadID)
	if hook != 0 {
		defer procUnhookWindowsHookEx.Call(hook)
	}

	hr = dialog.showDialog(0)
	if hr == hrCancelled {
		return nil, ErrCancelled
	}
	if failed(hr) {
		return nil, newHRError("IFileOpenDialog::Show", hr)
	}

	if multiSelect {
		var items *iShellItemArray
		hr = dialog.getResults(&items)
		if failed(hr) {
			return nil, newHRError("IFileOpenDialog::GetResults", hr)
		}
		defer items.release()

		n, err := items.count()
		if err != nil {
			return nil, err
		}

		results := make([]string, 0, n)
		for i := range n {
			item, err := items.itemAt(i)
			if err != nil {
				return nil, err
			}
			path, err := item.filePath()
			item.release()
			if err != nil || path == "" {
				continue
			}
			results = append(results, path)
		}
		return results, nil
	}

	var item *iShellItem
	hr = dialog.getResult(&item)
	if failed(hr) {
		return nil, newHRError("IFileOpenDialog::GetResult", hr)
	}
	defer item.release()

	path, err := item.filePath()
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("winfilepicker: selected item has no filesystem path")
	}
	return []string{path}, nil
}
