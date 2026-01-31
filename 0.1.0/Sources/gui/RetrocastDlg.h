// RetrocastDlg.h : header file
//

#pragma once


// CRetrocastDlg dialog
class CRetrocastDlg : public CDialogEx
{
// Construction
public:
	CRetrocastDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_RETROCAST_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedStartWindivert();
	afx_msg void OnBnClickedStartMitm();
	afx_msg void OnBnClickedStopAll();

private:
	CEdit m_logEdit;
	CButton m_startWindivertBtn;
	CButton m_startMitmBtn;
	CButton m_stopAllBtn;

	HANDLE m_windivertProcess;
	HANDLE m_mitmProcess;

	void LogMessage(const CString& message);
	void StartBackgroundProcess(const CString& exePath, const CString& workingDir, HANDLE& hProcess, const CString& processName);
	void TerminateBackgroundProcess(HANDLE& hProcess, const CString& processName);
};