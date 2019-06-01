#include<stdio.h>
#include<sys/types.h>
#include<windows.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<iostream>
//#include<iomanip>
#include<conio.h>
#include<io.h>
#include<stdlib.h>


using namespace std;

long int OffDosHeader=0;
long int OffFileHeader=0;
long int OffOptHeader=0;
long int OffSecHeader=0;


void CalculateOffSet(int fd)
{
	IMAGE_DOS_HEADER dosheader;
	_read(fd,&dosheader,sizeof(dosheader));
	
	OffDosHeader=0;
	OffFileHeader=dosheader.e_lfanew+4;
	cout<<endl<<OffFileHeader<<endl;
	OffOptHeader=OffFileHeader+0x14;
	OffSecHeader=OffOptHeader+sizeof(IMAGE_OPTIONAL_HEADER);
	cout<<endl<<sizeof(IMAGE_OPTIONAL_HEADER)<<endl;
	_lseek(fd,0,0);
}



class dos_header
{
public:
	IMAGE_DOS_HEADER dosheader;

	int fp;

	dos_header(int f)
	{
		fp=f;
		_lseek(fp,OffDosHeader,0);
		_read(f,&dosheader,sizeof(dosheader));
	}

	void show_header()
	{
		cout<<endl<<"--------------DOS HEADER----------------"<<endl;
		cout<<"Magic Number:"<<dosheader.e_magic<<endl;//<<std::hex
		if(dosheader.e_magic==0x5a4d)
			cout<<"Windows Exe..."<<endl;
		else
			cout<<"Alien Exe..."<<endl;
		cout<<"Bytes on the last page:"<<dosheader.e_cblp<<endl;
			cout<<"Pages in file:"<<dosheader.e_cp<<endl;
		cout<<"Relocation:"<<dosheader.e_crlc<<endl;
		cout<<"Size of header in paragraphs:"<<dosheader.e_cparhdr<<endl;
		cout<<"Maximum extra paragraphs needed:"<<dosheader.e_minalloc<<endl;
		cout<<"Minimum extra paragraphs needed:"<<dosheader.e_maxalloc<<endl;
		cout<<"Initial(relative) SS value:"<<dosheader.e_ss<<endl;
		cout<<"Initial SP value:"<<dosheader.e_sp<<endl;
		cout<<"Checksum:"<<dosheader.e_csum<<endl;
		cout<<"Initial IP value:"<<dosheader.e_ip<<endl;
		cout<<"Initial (reltive) CS:"<<dosheader.e_cs<<endl;
		cout<<"File address of rellocation table:"<<dosheader.e_lfarlc<<endl;
		cout<<"Overlay number:"<<dosheader.e_ovno<<endl;
		cout<<"OEM number:"<<dosheader.e_oemid<<endl;
		cout<<"OEM information(e_oemid specific):"<<dosheader.e_oeminfo<<endl;
		cout<<"RVA address of PE header:"<<dosheader.e_lfanew<<endl;

	}
};


class file_header
{
public:
	IMAGE_FILE_HEADER fileHeader;
	int fp;

	file_header(int f)
	{
		fp=f;
		_lseek(fp,OffFileHeader,0);
		_read(f,&fileHeader,sizeof(fileHeader));
	}

	void show_header()
	{
		short int iMask=0x0000000000000001;
		cout<<endl<<"--------------FILE HEADER---------------"<<endl;
		cout<<"Machine:"<<fileHeader.Machine<<endl;
		cout<<"Number of Sections:"<<fileHeader.NumberOfSections<<endl;
		cout<<"Time Date Stamp:"<<fileHeader.TimeDateStamp<<endl;
		cout<<"Pointer to Symbol Table"<<fileHeader.PointerToSymbolTable<<endl;
		cout<<"Number of symbols:"<<fileHeader.NumberOfSymbols<<endl;
		cout<<"Size of Optional header"<<fileHeader.SizeOfOptionalHeader<<endl;
		cout<<"Characteristics:"<<fileHeader.Characteristics<<endl;
		{
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"*Relocation Information Stripped From File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"File Is Executable!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Line Numbres Are Stripped From File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Symbols Are Stripped From File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Agressively Trim Working Set!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Application Can Handle >2gb Address Space!"<<endl;
			iMask=iMask<<2;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Bytes Of Machine Words Are Reversed!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"32 Bit Word Machine!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Debugging Information Stripped From File In .DGB File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"If Image Is On Removable Media,Copy And Run From The Swap File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"If Image Is On Net.,Copy And Run It From The Swap File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"System File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"File Is A DLL File!"<<endl;
			iMask=iMask<<1;
			if((iMask&fileHeader.Characteristics)==iMask)
				cout<<"Bytes Of Machine Words Are Reversed!"<<endl;
		}
	}

};



class opt_header
{
public:
	IMAGE_OPTIONAL_HEADER optHeader;
	int fp;

	opt_header(int f)
	{
		fp=f;
		_lseek(fp,OffOptHeader,0);
		_read(f,&optHeader,sizeof(optHeader));
	}

	void show_header()
	{
		cout<<"-----------------OPTION HEADER---------------"<<endl;
		cout<<"Magic:"<<optHeader.Magic<<endl;
		cout<<"Size of Code:"<<optHeader.SizeOfCode<<endl;
		cout<<"Size of Initialized Data:"<<optHeader.SizeOfInitializedData<<endl;
		cout<<"Size of Uninitialized Data:"<<optHeader.SizeOfUninitializedData<<endl;
		cout<<"Address of Entry Point:"<<optHeader.AddressOfEntryPoint<<endl;
		cout<<"Base of Code:"<<optHeader.BaseOfCode<<endl;
		cout<<"Base of Data:"<<optHeader.BaseOfData<<endl;
		cout<<"Image Base:"<<optHeader.ImageBase<<endl;
		cout<<"Section Alignment:"<<optHeader.SectionAlignment<<endl;
		cout<<"File Alignment:"<<optHeader.FileAlignment<<endl;
		cout<<"Major OS Version:"<<optHeader.MajorOperatingSystemVersion<<endl;
		cout<<"Minor OS Version:"<<optHeader.MinorOperatingSystemVersion<<endl;
		cout<<"Major Image Version:"<<optHeader.MajorImageVersion<<endl;
		cout<<"Minor Image Version:"<<optHeader.MinorImageVersion<<endl;
		cout<<"Major Subsystem Version:"<<optHeader.MajorSubsystemVersion<<endl;
		cout<<"Minor Subsystem Version:"<<optHeader.MinorSubsystemVersion<<endl;
		cout<<"Size of Image:"<<optHeader.SizeOfImage<<endl;
		cout<<"Size of Headers:"<<optHeader.SizeOfHeaders<<endl;
		cout<<"Chechsum:"<<optHeader.CheckSum<<endl;
		cout<<"Subsystem:"<<optHeader.Subsystem<<endl;
		cout<<"Dll Characteristics:"<<optHeader.DllCharacteristics<<endl;
		cout<<"Size of Stack Reserve:"<<optHeader.SizeOfStackReserve<<endl;
		cout<<"Size of Stack Commit:"<<optHeader.SizeOfStackCommit<<endl;
		cout<<"Size of Heap Reserve:"<<optHeader.SizeOfHeapReserve<<endl;
		cout<<"Size of Heap Commit:"<<optHeader.SizeOfHeapCommit<<endl;
		cout<<"Loader Flags:"<<optHeader.LoaderFlags<<endl;
		cout<<"Number of RVA and Sizes:"<<optHeader.NumberOfRvaAndSizes<<endl;
	}
};




class sec_header
{
public:
	IMAGE_SECTION_HEADER secHeader;
	int NoOfSec;
	int fp;

	sec_header(int f)
	{
		IMAGE_FILE_HEADER fileHeader;
		fp=f;
		_lseek(fp,OffFileHeader,0);
		_read(f,&fileHeader,sizeof(fileHeader));
		NoOfSec=fileHeader.NumberOfSections;

		_lseek(f,OffSecHeader,0);
		_read(f,&secHeader,sizeof(secHeader));
	}

	void show_header()
	{
		cout<<"----------------SECTION HEADER INFO.------------------"<<endl;
		while(NoOfSec!=0)
		{
			cout<<"Name:"<<secHeader.Name<<endl;
			cout<<"Virtual Address:"<<secHeader.VirtualAddress<<endl;
			cout<<"Size of Raw Data:"<<secHeader.SizeOfRawData<<endl;
			cout<<"Pointer to Raw Data:"<<secHeader.PointerToRawData<<endl;
			cout<<"Pointer to Relocations:"<<secHeader.PointerToRelocations<<endl;
			cout<<"Pointer to Line Numbers:"<<secHeader.PointerToLinenumbers<<endl;
			cout<<"Number of Relocations:"<<secHeader.NumberOfRelocations<<endl;
			cout<<"Number of Line Numbers:"<<secHeader.NumberOfLinenumbers<<endl;
			cout<<"Characteristics:"<<secHeader.Characteristics<<endl;
			NoOfSec--;
			cout<<endl<<"----------------------------------------------------"<<endl;
			_read(fp,&secHeader,sizeof(secHeader));
		}
	}
};


unsigned int swap_endian(unsigned int num)
{
	unsigned int a,b,c,d;
	a=0xff;
	a=a&num;
	a=a<<24;
	b=0xff00;
	b=b&num;
	b=b<<8;
	c=0xff0000;
	c=c&num;
	c=c>>8;
	d=0xff000000;
	d=d&num;
	d=d>>24;
	num=a|b|c|d;
	return num;
}

double pow(int x,int exp)
{
	static double res=1;
//	printf("\n-------r-%f-------\n",res);
	int i=0;
	res=1;
	for(i=0;i<exp;i++)
		res=res*x;
//	printf("\n------e--%d-------\n",exp);
//	printf("\n-------r-%f-------\n",res);
	return res;
}

int main(int argc,int argv[])
{
	int ip;
	char file_name[100];

	cout<<"Enter name of the file:";
//	cin>>file_name;
	scanf("%[^'\n']s",file_name);
	cout<<file_name;
	int fd=_open(file_name,O_BINARY,_S_IREAD);
	if(fd==-1)
	{
		cout<<strerror(errno);
		cout<<endl<<"Error:File Not Found..."<<endl;
		return -1;
	}

	CalculateOffSet(fd);
	cout << std::hex;
	IMAGE_FILE_HEADER fh;
	_lseek(fd,OffFileHeader,0);
	_read(fd,&fh,sizeof(fh));
	int num_of_sec=fh.NumberOfSections;
	cout<<endl<<"Number Of Sections:"<<num_of_sec<<endl;
	IMAGE_SECTION_HEADER sh;
	_lseek(fd,OffSecHeader,0);
	_read(fd,&sh,sizeof(sh));
	IMAGE_OPTIONAL_HEADER oh;
	_lseek(fd,OffOptHeader,0);
	_read(fd,&oh,sizeof(oh));

	while(num_of_sec)
	{
		char *x=(char *)sh.Name;
//		if(strcmp(x,"CODE")==0)
//		{
			unsigned int start=(unsigned int)sh.VirtualAddress;
			//start=swap_endian(start);
			cout<<endl<<"start:"<<start<<endl;
			unsigned int end=(unsigned int)sh.Misc.VirtualSize;
			//end=swap_endian(end);
			end=start+end;
			cout<<endl<<"end:"<<end<<endl;
			//unsigned int zzz=swap_endian(oh.AddressOfEntryPoint);
			unsigned int zzz=(unsigned int)(oh.AddressOfEntryPoint);
			cout<<endl<<"Address:"<<zzz;
//			cout<<"Addr"<<zzz<<"start"<<start<<"end"<<end;
			if((zzz>start)&&(zzz<end))
			{
				cout<<endl<<"Address Of Entry Point Checked And Valid..."<<endl;
				break;
			}
			else
			{
				cout<<"Address Of Entry Point Invalid...";
		//		exit(0);
			}
//		}
		num_of_sec--;
		_read(fd,&sh,sizeof(sh));
	}


	


	do
	{
		ip=0;
		cout<<endl<<"Enter your Choice:"<<endl<<std::hex;
		cout<<"1.Dos Header:"<<endl;
		cout<<"2.File Header:"<<endl;
		cout<<"3.Optional Header:"<<endl;
		cout<<"4.Section Header:"<<endl;
		cout<<"5.Get Section Information:"<<endl;
		cout<<"6.Import Directory:"<<endl;
		cout<<"7.Export Directory:"<<endl;
		cout<<"8.hex print:"<<endl;
		cout<<"9.Exit"<<endl;
		cout<<"Your Choice:";
		//cin>>ip;
		fflush(stdin);
		scanf("%d",&ip);
		switch(ip)
		{
			case 1:
				{
					dos_header dh(fd);
					dh.show_header();
					break;
				}
			case 2:
				{
					file_header fh(fd);
					fh.show_header();
					break;
				}
			case 3:
				{
					opt_header oh(fd);
					oh.show_header();
					break;
				}
			case 4:
				{
					sec_header sh(fd);
					sh.show_header();
					break;
				}
			case 5:
				{
					num_of_sec=fh.NumberOfSections;
					char sec_name[20];
					cout<<"Enter Section Name:"<<endl;
					cin>>sec_name;
					char *x=NULL;
					_lseek(fd,OffSecHeader,0);
					_read(fd,&sh,sizeof(sh));
					while(num_of_sec)
					{
						x=(char *)sh.Name;
						if(strcmp(x,sec_name)==0)
						{
							cout<<"Virtual Address:"<<sh.VirtualAddress<<endl;
							cout<<"Size of Raw Data:"<<sh.SizeOfRawData<<endl;
							cout<<"Pointer to Raw Data:"<<sh.PointerToRawData<<endl; 
							cout<<"Pointer to Relocations:"<<sh.PointerToRelocations<<endl;
							cout<<"Pointer to Line Numbers:"<<sh.PointerToLinenumbers<<endl;
							cout<<"Number of Relocations:"<<sh.NumberOfRelocations<<endl;
							cout<<"Number of Line Numbers:"<<sh.NumberOfLinenumbers<<endl;
							cout<<"Characteristics:"<<sh.Characteristics<<endl;
							cout<<endl<<"----------------------------------------------------"<<endl;
//							_lseek(fd,OffSecHeader,0);
							break;
						}
						num_of_sec--;
						_read(fd,&sh,sizeof(sh));
					}
//					_lseek(fd,OffSecHeader,0);
					break;
				}
			case 6:
				{
					IMAGE_OPTIONAL_HEADER io;
					IMAGE_IMPORT_DESCRIPTOR iid;
					//IMAGE_DATA_DIRECTORY id;
					int num_sec=fh.NumberOfSections;
					_lseek(fd,OffOptHeader,0);
					_read(fd,&io,sizeof(io));
					unsigned int x=0;
					cout<<endl<<"export dir:"<<io.DataDirectory[0].VirtualAddress<<endl;
					x=io.DataDirectory[1].VirtualAddress;
					_lseek(fd,OffSecHeader,0);
					_read(fd,&sh,sizeof(sh));
					unsigned int y=0;
					while(num_sec)
					{
						if((x>=sh.VirtualAddress)&&(x<=(sh.VirtualAddress+sh.SizeOfRawData)))
						{
							y=x+sh.PointerToRawData-sh.VirtualAddress;
							break;
						}
						num_sec--;
						_read(fd,&sh,sizeof(sh));
					}
					cout<<"import dir:"<<x<<endl;
					//x=swap_endian(x);
					//cout<<"swpax-"<<x<<endl;
					cout<<endl<<"sizeof(iid):"<<sizeof(iid)<<endl;
					//cout<<"op"<<OffOptHeader+420;
					//y=0xc954;//0x0016F400;//c954
					//y=swap_endian(y);
					int inc=0;
					char arr[20];
					int m=0;
					while(1)
					{
						_lseek(fd,y,0);
						_lseek(fd,inc,1);
						inc+=20;
						_read(fd,&iid,sizeof(iid));
						if(iid.Name==0)
							break;
						cout<<endl<<iid.Name;
						unsigned int addr=iid.Name-x+y;//addr conversion
						_lseek(fd,addr,0);
						_read(fd,arr,sizeof(arr));
						cout<<endl<<arr;
						memset(arr,0,sizeof(arr));
						m++;
					}
					cout<<endl<<"Number of Files imported:"<<std::dec<<m<<endl;
					break;
				}
			case 7:
				{
					IMAGE_OPTIONAL_HEADER io;
					IMAGE_EXPORT_DIRECTORY ied;
					int num_sec=fh.NumberOfSections;
					_lseek(fd,OffOptHeader,0);
					_read(fd,&io,sizeof(io));
					unsigned int x=0;
					cout<<endl<<"export dir:"<<io.DataDirectory[0].VirtualAddress<<endl;
					x=io.DataDirectory[0].VirtualAddress;
					if(x==0)
					{
						cout<<endl<<"Export Directory Empty..."<<endl;
						break;
					}
					break;
	/*				char arr[20];
					_lseek(fd,x,0);
					_read(fd,&ied,sizeof(ied));
					cout<<ied.Name<<endl;
					_lseek(fd,ied.Name,0);
					_read(fd,arr,sizeof(arr));
					cout<<arr;



					_lseek(fd,x,0);
					_lseek(fd,sizeof(ied),1);
					_read(fd,&ied,sizeof(ied));
					cout<<ied.Name<<endl;
					_lseek(fd,ied.Name,0);
					_read(fd,arr,sizeof(arr));
					cout<<arr;*/
				}
			case 8:
				{
					char arr[10];
					lseek(fd,0,0);
					int m=6;
					while(m)
					{
						_read(fd,&arr,10);
						printf("%s|",arr);
						m--;
							printf("\n");
					}
				}
			case 9:
				{
					close(fd);
					exit(0);
					break;
				}
			default:
				cout<<"Invalid Input...";
		}
	}while(1);
	return 0;
}