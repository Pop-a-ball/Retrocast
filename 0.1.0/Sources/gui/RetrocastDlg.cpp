// RetrocastDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Retrocast.h"
#include "RetrocastDlg.h"
#include "afxdialogex.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRetrocastDlg dialog



CRetrocastDlg::CRetrocastDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_RETROCAST_DIALOG, pParent)
	, m_windivertProcess(nullptr)
	, m_mitmProcess(nullptr)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRetrocastDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LOG_EDIT, m_logEdit);
}

BEGIN_MESSAGE_MAP(CRetrocastDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START_WINDIVERT, &CRetrocastDlg::OnBnClickedStartWindivert)
	ON_BN_CLICKED(IDC_START_MITM, &CRetrocastDlg::OnBnClickedStartMitm)
	ON_BN_CLICKED(IDC_STOP_ALL, &CRetrocastDlg::OnBnClickedStopAll)
END_MESSAGE_MAP()


// CRetrocastDlg message handlers

BOOL CRetrocastDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CRetrocastDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CRetrocastDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CRetrocastDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CRetrocastDlg::LogMessage(const CString& message)
{
	CString currentText;
	m_logEdit.GetWindowText(currentText);
	currentText += message + _T("\r\n");
	m_logEdit.SetWindowText(currentText);
	m_logEdit.LineScroll(m_logEdit.GetLineCount());
}

void CRetrocastDlg::OnBnClickedStartWindivert()
{
	// Get exe directory (where Retrocast.exe is located)
	TCHAR exePath[MAX_PATH];
	GetModuleFileName(nullptr, exePath, MAX_PATH);
	PathRemoveFileSpec(exePath);

	// Build path: windivert_redirect.exe (relative to exe directory)
	TCHAR windivertPath[MAX_PATH];
	PathCombine(windivertPath, exePath, _T("windivert_redirect.exe"));

	StartBackgroundProcess(CString(windivertPath), CString(exePath), m_windivertProcess, _T("WinDivert Redirector"));
}

void CRetrocastDlg::OnBnClickedStartMitm()
{
	// Get exe directory (where Retrocast.exe is located)
	TCHAR exePath[MAX_PATH];
	GetModuleFileName(nullptr, exePath, MAX_PATH);
	PathRemoveFileSpec(exePath);

	// Build mitmproxy working directory: mitmproxy/ (relative to exe)
	TCHAR workingDir[MAX_PATH];
	PathCombine(workingDir, exePath, _T("mitmproxy"));

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	LogMessage(_T("Starting mitmproxy..."));
	LogMessage(_T("Working Dir: ") + CString(workingDir));

	CString cmd = _T("cmd.exe /c mitmdump -v -s mitm_addon.py");
	
	if (CreateProcess(nullptr, cmd.GetBuffer(), nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP, nullptr,
		workingDir, &si, &pi))
	{
		cmd.ReleaseBuffer();
		m_mitmProcess = pi.hProcess;
		CloseHandle(pi.hThread);
		CString pidMsg;
		pidMsg.Format(_T(" started successfully (PID: %u)"), pi.dwProcessId);
		LogMessage(_T("mitmproxy") + pidMsg);
	}
	else
	{
		cmd.ReleaseBuffer();
		DWORD err = GetLastError();
		CString errMsg;
		errMsg.Format(_T("Failed to start mitmproxy (Error: %d)"), err);
		LogMessage(errMsg);
	}
}

void CRetrocastDlg::OnBnClickedStopAll()
{
	LogMessage(_T("Stopping all processes..."));
	TerminateBackgroundProcess(m_windivertProcess, _T("WinDivert Redirector"));
	TerminateBackgroundProcess(m_mitmProcess, _T("mitmproxy"));
	LogMessage(_T("All processes stopped"));
}

void CRetrocastDlg::StartBackgroundProcess(const CString& exePath, const CString& workingDir, HANDLE& hProcess, const CString& processName)
{
	if (hProcess != nullptr && WaitForSingleObject(hProcess, 0) == WAIT_TIMEOUT)
	{
		LogMessage(processName + _T(" already running"));
		return;
	}

	LogMessage(_T("Starting ") + processName + _T("..."));
	LogMessage(_T("Path: ") + exePath);
	LogMessage(_T("Working Dir: ") + workingDir);

	// Check if file exists
	WIN32_FIND_DATA findFileData;
	HANDLE findHandle = FindFirstFile(exePath, &findFileData);
	if (findHandle == INVALID_HANDLE_VALUE)
	{
		LogMessage(_T("ERROR: File not found - ") + exePath);
		return;
	}
	FindClose(findHandle);

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// Create a mutable copy of exePath for CreateProcess
	CString cmd = exePath;
	
	if (CreateProcess(nullptr, cmd.GetBuffer(), nullptr, nullptr, FALSE, CREATE_NEW_PROCESS_GROUP, nullptr,
		workingDir.IsEmpty() ? nullptr : workingDir.GetString(), &si, &pi))
	{
		cmd.ReleaseBuffer();
		
		// Wait a bit to check if process crashes immediately
		DWORD waitResult = WaitForSingleObject(pi.hProcess, 500);
		
		if (waitResult == WAIT_OBJECT_0)
		{
			// Process already exited - get exit code
			DWORD exitCode;
			GetExitCodeProcess(pi.hProcess, &exitCode);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			CString errMsg;
			errMsg.Format(_T("ERROR: %s crashed immediately (Exit Code: %d)"), processName, exitCode);
			LogMessage(errMsg);
		}
		else
		{
			// Process still running
			hProcess = pi.hProcess;
			CloseHandle(pi.hThread);
			CString pidMsg;
			pidMsg.Format(_T(" started successfully (PID: %u)"), pi.dwProcessId);
			LogMessage(processName + pidMsg);
		}
	}
	else
	{
		cmd.ReleaseBuffer();
		DWORD err = GetLastError();
		CString errMsg;
		errMsg.Format(_T("ERROR: Failed to start %s (Error: %d)"), processName, err);
		LogMessage(errMsg);
	}
}

void CRetrocastDlg::TerminateBackgroundProcess(HANDLE& hProcess, const CString& processName)
{
	// First, try to terminate via stored handle
	if (hProcess != nullptr)
	{
		DWORD waitResult = WaitForSingleObject(hProcess, 0);
		if (waitResult == WAIT_TIMEOUT)
		{
			// Process is still running
			if (TerminateProcess(hProcess, 0))
			{
				WaitForSingleObject(hProcess, INFINITE);
				LogMessage(processName + _T(" terminated successfully (via handle)"));
			}
		}
		CloseHandle(hProcess);
		hProcess = nullptr;
	}

	// Also try to terminate by process name (for robustness)
	CString exeName;
	if (processName == _T("WinDivert Redirector"))
		exeName = _T("windivert_redirect.exe");
	else if (processName == _T("mitmproxy"))
		exeName = _T("mitmdump.exe");
	else
		return;

	// Use taskkill command to ensure process is killed
	CString cmd;
	cmd.Format(_T("taskkill /IM %s /F"), exeName);
	
	STARTUPINFO si = { sizeof(si) };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	
	if (CreateProcess(nullptr, cmd.GetBuffer(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
	{
		cmd.ReleaseBuffer();
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		LogMessage(processName + _T(" terminated (via taskkill)"));
	}
	else
	{
		cmd.ReleaseBuffer();
	}
}