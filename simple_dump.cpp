#include<stdio.h>
#include<stdlib.h>
#include<string.h>
typedef          long long ll;
typedef unsigned long long ull;
typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;
typedef ll              int64;
typedef ll              sint64;
typedef ull             uint64;
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
    
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;
    
 typedef struct _IMAGE_DOS_HEADER {
  WORD e_magic;                                   //所有MS-DOS兼容的可执行文件都将此值设为0X5A4D(MZ)
  WORD e_cblp;                                    //文件最后页的字节数
  WORD e_cp;                                      //文件页数
  WORD e_crlc;                                    //重定义元素个数
  WORD e_cparhdr;                                 //头部尺寸，以段落为单位
  WORD e_minalloc;                                //所需的最小附加段
  WORD e_maxalloc;                                //所需的最大附加段
  WORD e_ss;                                      //初始的SS值(相对偏移量)
  WORD e_sp;                                      //初始的SP值
  WORD e_csum;                                    //校验和
  WORD e_ip;                                      //初始的IP值
  WORD e_cs;                                      //初始的CS值(相对偏移量)
  WORD e_lfarlc;                                  //重分配表文件地址
  WORD e_ovno;                                    ///覆盖号
  WORD e_res[4];                                  //保留字
  WORD e_oemid;                                   //OEM标识符(相对e_oeminfo)
  WORD e_oeminfo;                                 //OEM信息
  WORD e_res2[10];                                //保留字
  LONG e_lfanew;                                  //新exe头部的文件地址
} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;
    

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;    


typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;




int main()
{
	/*
	unsigned char *buffer = (unsigned char*)malloc(sizeof(char)*1000);
	
	printf("%d %d %d %d\n",sizeof(char),sizeof(int),sizeof(double),sizeof(long));
	
	memset(buffer,0,sizeof(char)*1000);
	fread(buffer,sizeof(char),1000,fp);
	for(int i=1;i<= 1000;i++){
		printf("%2x ", buffer[i-1]); 
		if( i % 8 ==0 && i!=0)
			printf("\n");
	}
    */
    
	char filename[] ="test.exe";
	FILE *fp = fopen(filename,"r");						
	IMAGE_DOS_HEADER image_dos_header;    
	IMAGE_NT_HEADERS32	image_nt_headers32;    
	fread(&image_dos_header, sizeof(image_dos_header),1,fp);
	
	//image_dos_header info
	printf("e_magic:		%2x\n"		,	image_dos_header.e_magic); 
	printf("e_cblp:			%2x\n"		,	image_dos_header.e_cblp);
	printf("e_cp:			%2x\n"		,	image_dos_header.e_cp);   
	printf("e_crlc:			%2x\n"		,	image_dos_header.e_crlc);       
	printf("e_cparhdr:		%2x\n"		,	image_dos_header.e_cparhdr);       
	printf("e_minalloc:		%2x\n"		,	image_dos_header.e_minalloc);       
	printf("e_maxalloc:		%2x\n"		,	image_dos_header.e_maxalloc);    
	printf("e_ss:			%2x\n"		,	image_dos_header.e_ss);    
	printf("e_sp:			%2x\n"		,	image_dos_header.e_sp);    
	printf("e_csum:			%2x\n"		,	image_dos_header.e_csum);    
	printf("e_ip:			%2x\n"		,	image_dos_header.e_ip);   
	printf("e_cs:			%2x\n"		,	image_dos_header.e_cs);   
	printf("e_lfarlc:		%2x\n"		,	image_dos_header.e_lfarlc);
	printf("e_ovno:			%2x\n"		,	image_dos_header.e_ovno);   
	
	printf("e_res:			"	);
	for(int i=0;i<4;i++)
		printf("%2x "				,	image_dos_header.e_res[i]);
	printf("\n");	
	
	printf("e_oemid:		%2x\n"		,	image_dos_header.e_oemid);
	printf("e_oeminfo:		%2x\n"	,	image_dos_header.e_oeminfo);
	
	printf("e_res2:");
	for(int i=0;i<10;i++)
		printf("%2x "				,	image_dos_header.e_res2[i]);	
	printf("\n");
	
	printf("e_lfanew:		%2x\n"		,	image_dos_header.e_lfanew);   
	                                   
	fseek(fp, image_dos_header.e_lfanew, SEEK_SET);
	fread(&image_nt_headers32, sizeof(image_nt_headers32),1,fp);
	//_IMAGE_NT_HEADERS		IMAGE_FILE_HEADER	IMAGE_OPTIONAL_HEADER32
    printf("image_nt_headers32.Signature						%2x\n",	image_nt_headers32.Signature						);
    printf("image_nt_headers32.FileHeader.Machine				%2x\n",	image_nt_headers32.FileHeader.Machine				);
    printf("image_nt_headers32.FileHeader.NumberOfSections		%2x\n",	image_nt_headers32.FileHeader.NumberOfSections		); 
    printf("image_nt_headers32.FileHeader.TimeDateStamp			%2x\n",	image_nt_headers32.FileHeader.TimeDateStamp			);
    printf("image_nt_headers32.FileHeader.PointerToSymbolTable	%2x\n",	image_nt_headers32.FileHeader.PointerToSymbolTable	);
    printf("image_nt_headers32.FileHeader.NumberOfSymbols		%2x\n",	image_nt_headers32.FileHeader.NumberOfSymbols		);
    printf("image_nt_headers32.FileHeader.SizeOfOptionalHeader	%2x\n",	image_nt_headers32.FileHeader.SizeOfOptionalHeader	);
    printf("image_nt_headers32.FileHeader.Characteristics		%2x\n",	image_nt_headers32.FileHeader.Characteristics		);

	printf("image_nt_headers32.OptionalHeader.Magic							%2x\n",	image_nt_headers32.OptionalHeader.Magic							);
	printf("image_nt_headers32.OptionalHeader.MajorLinkerVersion			%2x\n",	image_nt_headers32.OptionalHeader.MajorLinkerVersion			);
	printf("image_nt_headers32.OptionalHeader.MinorLinkerVersion			%2x\n",	image_nt_headers32.OptionalHeader.MinorLinkerVersion			);
	printf("image_nt_headers32.OptionalHeader.SizeOfCode					%2x\n",	image_nt_headers32.OptionalHeader.SizeOfCode					);
	printf("image_nt_headers32.OptionalHeader.SizeOfInitializedData			%2x\n",	image_nt_headers32.OptionalHeader.SizeOfInitializedData			);
	printf("image_nt_headers32.OptionalHeader.SizeOfUninitializedData		%2x\n",	image_nt_headers32.OptionalHeader.SizeOfUninitializedData		);
	printf("image_nt_headers32.OptionalHeader.AddressOfEntryPoint			%2x\n",	image_nt_headers32.OptionalHeader.AddressOfEntryPoint			);
	printf("image_nt_headers32.OptionalHeader.BaseOfCode					%2x\n",	image_nt_headers32.OptionalHeader.BaseOfCode					);
	printf("image_nt_headers32.OptionalHeader.BaseOfData					%2x\n",	image_nt_headers32.OptionalHeader.BaseOfData					);
	printf("image_nt_headers32.OptionalHeader.ImageBase						%2x\n",	image_nt_headers32.OptionalHeader.ImageBase						);
	printf("image_nt_headers32.OptionalHeader.SectionAlignment				%2x\n",	image_nt_headers32.OptionalHeader.SectionAlignment				);
	printf("image_nt_headers32.OptionalHeader.FileAlignment					%2x\n",	image_nt_headers32.OptionalHeader.FileAlignment					);
	printf("image_nt_headers32.OptionalHeader.MajorOperatingSystemVersion	%2x\n",	image_nt_headers32.OptionalHeader.MajorOperatingSystemVersion	);
	printf("image_nt_headers32.OptionalHeader.MinorOperatingSystemVersion	%2x\n",	image_nt_headers32.OptionalHeader.MinorOperatingSystemVersion	);
	printf("image_nt_headers32.OptionalHeader.MajorImageVersion				%2x\n",	image_nt_headers32.OptionalHeader.MajorImageVersion				);
	printf("image_nt_headers32.OptionalHeader.MinorImageVersion				%2x\n",	image_nt_headers32.OptionalHeader.MinorImageVersion				);
	printf("image_nt_headers32.OptionalHeader.MajorSubsystemVersion			%2x\n",	image_nt_headers32.OptionalHeader.MajorSubsystemVersion			);
	printf("image_nt_headers32.OptionalHeader.MinorSubsystemVersion			%2x\n",	image_nt_headers32.OptionalHeader.MinorSubsystemVersion			);
	printf("image_nt_headers32.OptionalHeader.Win32VersionValue				%2x\n",	image_nt_headers32.OptionalHeader.Win32VersionValue				);
	printf("image_nt_headers32.OptionalHeader.SizeOfImage					%2x\n",	image_nt_headers32.OptionalHeader.SizeOfImage					);
	printf("image_nt_headers32.OptionalHeader.SizeOfHeaders					%2x\n",	image_nt_headers32.OptionalHeader.SizeOfHeaders					);
	printf("image_nt_headers32.OptionalHeader.CheckSum						%2x\n",	image_nt_headers32.OptionalHeader.CheckSum						);
	printf("image_nt_headers32.OptionalHeader.Subsystem						%2x\n",	image_nt_headers32.OptionalHeader.Subsystem						);
	printf("image_nt_headers32.OptionalHeader.DllCharacteristics			%2x\n",	image_nt_headers32.OptionalHeader.DllCharacteristics			);
	printf("image_nt_headers32.OptionalHeader.SizeOfStackReserve			%2x\n",	image_nt_headers32.OptionalHeader.SizeOfStackReserve			);
	printf("image_nt_headers32.OptionalHeader.SizeOfStackCommit				%2x\n",	image_nt_headers32.OptionalHeader.SizeOfStackCommit				);
	printf("image_nt_headers32.OptionalHeader.SizeOfHeapReserve				%2x\n",	image_nt_headers32.OptionalHeader.SizeOfHeapReserve				);
	printf("image_nt_headers32.OptionalHeader.SizeOfHeapCommit				%2x\n",	image_nt_headers32.OptionalHeader.SizeOfHeapCommit				);
	printf("image_nt_headers32.OptionalHeader.LoaderFlags					%2x\n",	image_nt_headers32.OptionalHeader.LoaderFlags					);
	printf("image_nt_headers32.OptionalHeader.NumberOfRvaAndSizes			%2x\n",	image_nt_headers32.OptionalHeader.NumberOfRvaAndSizes			);
	
	printf("image_nt_headers32.OptionalHeader.DataDirectory:");
	for(int i=0;i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++)
		printf("%2x ",	image_nt_headers32.OptionalHeader.DataDirectory[i]);
	return 0;                          
}                                   
