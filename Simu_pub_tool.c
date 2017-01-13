/*****************************************************************
 *
 * 文件名称    Simu_pub_server.c
 * 摘    要    : 中间业务平台公共socket模拟器
 *
 * 当前版本    ：1.0
 * 作    者    ： guojy
 * 完成日期    ：2016年4月14日
 *
 *****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>

void bsWPubDebug(char *aLog_file_name,char *fmt,...);
int nAnalyseCfgFilePubDeal(char *aConfig_type,char *aServ_name,char *aOut_str);
int nListCfgFileServType(char *aProg_nm);
int nGetServerStat(char *aProg_nm,char *aServ_nm,long *lPid);
int nConvertStrToHex(char *aSrc_str,int *iHex_val);
int nFilterStrHexNum(char *aIn_str,char *aOut_str,int *iOut_len);
typedef struct
{
	long lPort_no;			/*端口号*/
	int  iShift_start;		/*交易类型值在请求报文起始位置*/
	int  iShift_len;		/*交易类型值的长度*/
	char aTran_type_format[16+1];	/*交易类型*/
	char aTran_type[16+1];	/*交易类型值*/
	int  iTran_type;		/*交易类型值*/
	unsigned char aResp_info[4096];	/*应答报文*/
}cfg_info;
char aServ_name[16+1];		/*本次处理的服务类型*/
#define sWPubDebug(...) bsWPubDebug(__FILE__,__VA_ARGS__)

int main(int argc,char **argv)
{
	unsigned char aRecv_msg[4096];
	char aPort_no[16];
	cfg_info stResp_dtl;
	char aShift_start[16];
	char aShift_len[16];
	char aShift_str[24];
	char aSearch_serv_name[64];
	char aStr_tmp[1024];
	long lPid = 0;
	int ret = 0;
	unsigned short iMsg_len = 0;
	short int iTmp;
	char *pStart,*pEnd;
	int iResp_len;
	
	char aDelay_time_cfg[64];
	long lDelay_time;
	
	int nServerSocketId, nClientSocketId;/*声明套接字描述符*/
	struct sockaddr_in SServerAddr;
	struct sockaddr_in SClientAddr;
	
	memset(aRecv_msg,0x00,sizeof(aRecv_msg));
	memset(aServ_name,0x00,sizeof(aServ_name));
	memset(aPort_no,0x00,sizeof(aPort_no));
	memset(&stResp_dtl,0x00,sizeof(stResp_dtl));
	memset(aShift_str,0x00,sizeof(aShift_str));
	memset(aShift_start,0x00,sizeof(aShift_start));
	memset(aShift_len,0x00,sizeof(aShift_len));
	memset(aSearch_serv_name,0x00,sizeof(aSearch_serv_name));
	memset(aStr_tmp,0x00,sizeof(aStr_tmp));
	
	if(argc == 1)
	{
		printf("usage %s server name,server_list:\n",argv[0]);
		ret = nListCfgFileServType(argv[0]);
		if(ret)
		{
			printf("get server list fail\n");
			return -1;
		}
		return 0;
	}
	
	strcpy(aServ_name,argv[1]);
	sprintf(aSearch_serv_name,"[%s]",aServ_name);
	
	/*判断该服务启动实例数*/
	ret = nGetServerStat(argv[0],aServ_name,&lPid);
	if(ret)
	{
		sWPubDebug("%d get server handle num fail",__LINE__);
		return -1;
	}
	if(lPid != 0)
	{
		printf("server:[%s] is executing,pid:[%ld]\n",argv[1],lPid);
		return 0;
	}
		
	/*获取端口号*/
	ret = nAnalyseCfgFilePubDeal("PORT",aSearch_serv_name,aPort_no);
	if(ret)
	{
		sWPubDebug("get port no fail");
		return -1;
	}
	stResp_dtl.lPort_no = atol(aPort_no);
	sWPubDebug("port no is:[%ld]",stResp_dtl.lPort_no);
	
	/*获取交易类型字段的偏移值*/
	ret = nAnalyseCfgFilePubDeal("SPILT_PLACE",aSearch_serv_name,aShift_str);
	if(ret)
	{
		sWPubDebug("get shift value fail");
		return -1;
	}
	
	strncpy(aShift_start,aShift_str,strchr(aShift_str,',') - aShift_str);
	strcpy(aShift_len,strchr(aShift_str,',') + 1);
	stResp_dtl.iShift_start = atoi(aShift_start);
	stResp_dtl.iShift_len = atoi(aShift_len);
	sWPubDebug("shift start value=[%d] shift len=[%d]",stResp_dtl.iShift_start,stResp_dtl.iShift_len);
	
	/*获取交易类型值格式*/
	ret = nAnalyseCfgFilePubDeal("TRAN_TYPE_FORMAT",aSearch_serv_name,stResp_dtl.aTran_type_format);
	if(ret)
	{
		sWPubDebug("get tran type format fail");
		return -1;
	}
	sWPubDebug("tran type format:[%s]\n",stResp_dtl.aTran_type_format);
	
	if ((nServerSocketId = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		sWPubDebug("调用socket函数失败");
		return(-1);
	}

	SServerAddr.sin_family = AF_INET;
	SServerAddr.sin_port = htons(stResp_dtl.lPort_no);
	SServerAddr.sin_addr.s_addr = htons(INADDR_ANY);
	bzero(&(SServerAddr.sin_zero), 0);

	bind(nServerSocketId, (struct sockaddr*) &SServerAddr, sizeof(SServerAddr));

	listen(nServerSocketId, 5);
	while(1)
	{
		memset(aStr_tmp,0x00,sizeof(aStr_tmp));
		memset(&stResp_dtl.iTran_type,0x00,sizeof(stResp_dtl.iTran_type));
		memset(stResp_dtl.aTran_type,0x00,sizeof(stResp_dtl.aTran_type));
		memset(aDelay_time_cfg,0x00,sizeof(aDelay_time_cfg));
		iResp_len = 0;
		
		int nLen = sizeof(SClientAddr);
		nClientSocketId = accept(nServerSocketId, (struct sockaddr*) &SClientAddr, &nLen);
		sWPubDebug("**************accept a connection**************");
		memset(aRecv_msg, 0, sizeof(aRecv_msg));
		if(strcmp(aServ_name,"HBFCDT") == 0)
		{
			read(nClientSocketId, &iMsg_len, sizeof(unsigned short));	/*如果为河北福彩定投,读取开头的报文长度*/
			iMsg_len = ntohs(iMsg_len);
			sWPubDebug("%s get accept info success,length=[%u]\n",aServ_name,iMsg_len);
		}
		
		read(nClientSocketId, aRecv_msg, sizeof(aRecv_msg));
		sWPubDebug("get a message from bank:[%s],length[%d]", aRecv_msg,strlen(aRecv_msg));

		if(strlen(aRecv_msg) == 0)
		{
			printf("receive message is empty,continue listen");
			continue;
		}
		/*根据请求报文解析交易类型数据*/
		if(strcmp(stResp_dtl.aTran_type_format,"str") == 0)
		{
			memcpy(stResp_dtl.aTran_type,aRecv_msg + stResp_dtl.iShift_start,stResp_dtl.iShift_len);
			if(strlen(stResp_dtl.aTran_type) == 0)
			{
				sWPubDebug("tran_type is null,invalid");
				continue;
			}
		}
		else if(strcmp(stResp_dtl.aTran_type_format,"hex") == 0)
		{
			memcpy(&stResp_dtl.iTran_type,aRecv_msg + stResp_dtl.iShift_start,stResp_dtl.iShift_len);
			stResp_dtl.iTran_type = ntohs(stResp_dtl.iTran_type);
			sprintf(stResp_dtl.aTran_type,"%x",stResp_dtl.iTran_type);
		}
		sWPubDebug("tran_type:[%s]",stResp_dtl.aTran_type);
		
		/*获取应答报文*/
		memset(aStr_tmp,0x00,sizeof(aStr_tmp));
		ret = nAnalyseCfgFilePubDeal(stResp_dtl.aTran_type,aSearch_serv_name,aStr_tmp);
		if(ret)
		{
			sWPubDebug("get resp info fail");
			continue;
		}
		/*判断是否存在十六进制值*/
		memset(stResp_dtl.aResp_info,0x00,sizeof(stResp_dtl.aResp_info));
		nFilterStrHexNum(aStr_tmp,stResp_dtl.aResp_info,&iResp_len);
		sWPubDebug("the resp info length:[%d]",iResp_len);
		
		/*判断是否配置了应答的延迟时间*/
		memset(aStr_tmp,0x00,sizeof(aStr_tmp));
		sprintf(aDelay_time_cfg,"RET_DELAY_TIME_%s",stResp_dtl.aTran_type);
		ret = nAnalyseCfgFilePubDeal(aDelay_time_cfg,aSearch_serv_name,aStr_tmp);
		if(ret == 0)	/*如果配置了延迟时间*/
		{
			lDelay_time = atol(aStr_tmp);
			sleep(lDelay_time);
		}
		
		if(send(nClientSocketId, stResp_dtl.aResp_info, iResp_len, 0) < 0)
		{
			sWPubDebug("send resp info fail\n");
			continue;
		}
		sWPubDebug("resp info:[%s]",aStr_tmp);
		
		close(nClientSocketId);
		sWPubDebug("**************connection complete**************\n\n");
	}
	
	return 0;
}

/*********************************************************
 ** 函数名  :   nAnalyseCfgFilePubDeal(char *aConfig_type,char *aServ_name,char *aOut_str) 
 ** 功能    :   解析配置文件内容
 ** 作者    :   guojy
 ** 建立日期:   2016年4月14日15:29:00
 ** 全局变量:
 ** 参数含义:   
 ** 返回值:
 ***********************************************************/
int nAnalyseCfgFilePubDeal(char *aConfig_type,char *aServ_name,char *aOut_str)
{
	FILE *fp = NULL;
	char aStr_tmp[4096+1];
	long lStart_flag = 0; /*0-未起始 1-起始*/
	char *aTmp;
	fp = fopen("Simu_pub_tool.cfg","r");
	if (fp == NULL)
	{
		sWPubDebug("open config file Simu_pub_tool.cfg fail");
		return -1;
	}
	while(feof(fp) == 0)
	{
		memset (aStr_tmp,0x00,sizeof(aStr_tmp));
		aTmp = NULL;
		fgets(aStr_tmp,4096,fp);
		aTmp = strchr(aStr_tmp,'\n');
		if(aTmp)
			aStr_tmp[strlen(aStr_tmp) - 1] = '\0';
					
		if (aStr_tmp[0] == '#' || strlen(aStr_tmp) == 0)
			continue;
		
		if(strncmp(aStr_tmp,aServ_name,strlen(aServ_name)) == 0)	/*锁定到具体服务所在区域*/
			lStart_flag = 1;
		else if((aStr_tmp[0] == '[' || aStr_tmp[0] == ']') && lStart_flag == 1)
			break;
		else if (lStart_flag == 1 && strncmp(aStr_tmp,aConfig_type,strlen(aConfig_type)) == 0)
		{
			aTmp = strchr(aStr_tmp,'=');
			if(aTmp == NULL)
			{
				sWPubDebug("config file is invalid,without \"=\"");
				return -1;
			}
			else if(strcmp(aTmp+1,"") == 0)
			{
				sWPubDebug("config file is invalid");
				return -1;
			}
			strcpy(aOut_str,aTmp + 1);
		}
	}
	
	if (strlen(aOut_str) == 0)
	{
		sWPubDebug("config_type[%s] is not exist,please confirm\n",aConfig_type);
		return -1;
	}
	return 0;
}

/*********************************************************
 ** 函数名  :   nListCfgFileServType(char *aProg_nm)
 ** 功能    :   列出配置文件中的服务类型
 ** 作者    :   guojy
 ** 建立日期:   2016年4月15日12:52:04
 ** 全局变量:
 ** 参数含义:   
 ** 返回值:
 ***********************************************************/
int nListCfgFileServType(char *aProg_nm)
{
	FILE *fp = NULL;
	char *aTmp;
	char aStr_tmp[4096+1];
	char aServ_name[64];
	char aServ_name_desc[64];
	char aSearch_serv_name[64];
	char aPort_no[16];
	char aBlank_str[3][64];
	long lPid;
	int ret = 0;
	
	fp = fopen("Simu_pub_tool.cfg","r");
	if (fp == NULL)
	{
		printf("open config file Simu_pub_tool.cfg fail");
		return -1;
	}
	printf("--------------------------------------------------------------------------------------\n");
	while(feof(fp) == 0)
	{
		memset (aStr_tmp,0x00,sizeof(aStr_tmp));
		memset (aServ_name,0x00,sizeof(aServ_name));
		memset (aPort_no,0x00,sizeof(aPort_no));
		memset (aServ_name_desc,0x00,sizeof(aServ_name_desc));
		memset (aSearch_serv_name,0x00,sizeof(aSearch_serv_name));
		memset (aBlank_str,0x00,sizeof(aBlank_str));
		lPid = 0;
		fgets(aStr_tmp,4096,fp);
		aTmp = strchr(aStr_tmp,'\n');
		if(aTmp)
			aStr_tmp[strlen(aStr_tmp) - 1] = '\0';
					
		if (aStr_tmp[0] != '[')
			continue;
		
		strncpy(aServ_name,aStr_tmp+1,strchr(aStr_tmp,']') - aStr_tmp - 1);
		ret = nGetServerStat(aProg_nm,aServ_name,&lPid);
		if(ret)
		{
			printf("%d get server handle num fail\n",__LINE__);
			return -1;
		}
		sprintf(aSearch_serv_name,"[%s]",aServ_name);
		ret = nAnalyseCfgFilePubDeal("PORT",aSearch_serv_name,aPort_no);
		if(ret)
		{
			printf("%d get server port_no fail\n",__LINE__);
			return -1;
		}
		
		ret = nAnalyseCfgFilePubDeal("DESC",aSearch_serv_name,aServ_name_desc);
		if(ret)
		{
			printf("%d get server desc fail,serv_name:%s\n",__LINE__,aSearch_serv_name);
			return -1;
		}
		memset(aBlank_str[0],' ',32-(strlen(aServ_name) + strlen(aServ_name_desc) + 2));
		if(lPid != 0)
			printf("%s[%s]%s执行		端口号:%s		进程号:%ld\n",
					aServ_name,aServ_name_desc,aBlank_str[0],aPort_no,lPid);
		else
			printf("%s[%s]%s未执行		端口号:%s		进程号:null\n",
					aServ_name,aServ_name_desc,aBlank_str[0],aPort_no);
		
		printf("--------------------------------------------------------------------------------------\n");
	}
	return 0;
}

/*********************************************************
 ** 函数名  :   nGetServerStat(char *aProg_nm,char *aServ_nm,long *lPid)
 ** 功能    :   判断一个服务是否已经启动
 ** 作者    :   guojy
 ** 建立日期:   2016年4月15日12:52:04
 ** 全局变量:	
 ** 入口参数:	aProg_nm:程序名称
 ** 入口参数:	aServ_nm:服务名称
 ** 出口参数:	aStat:0-未启动 1-已启动
 ** 返回值:
 ***********************************************************/
int nGetServerStat(char *aProg_nm,char *aServ_nm,long *lPid)
{
	char aCommand_str[128];
	char aBuf[16];
	char *aTmp = NULL;
	int i = 0;
	long lPid_tmp = 0;
	FILE *fp = NULL;
	
	lPid_tmp = getpid();
	memset(aCommand_str,0x00,sizeof(aCommand_str));
	memset(aBuf,0x00,sizeof(aBuf));
	*lPid = 0;
	sprintf(aCommand_str,"ps -ef | grep \"%s %s\" | grep -v grep | grep -v %ld | awk '{if($8==\"%s\" && $9==\"%s\") print $2}'",
						  aProg_nm,aServ_nm,getpid(),aProg_nm,aServ_nm);
	fp = popen(aCommand_str,"r");
	if(fp == NULL)
	{
		printf("error command line:[%s]\n",aCommand_str);
		return -1;
	}
	while( (aBuf[i] = fgetc(fp)) != EOF)
	{
		if(aBuf[i] == '\n')
		{
			aBuf[i] = '\0';
			break;
		}
		i++;
	}
	pclose(fp);
	*lPid = atol(aBuf);
	return 0;
}

/*********************************************************
 ** 函数名  :   bsWPubDebug(char *aFile_name,char *fmt,...) 
 ** 功能    :   日志打印公共函数
 ** 作者    :   guojy
 ** 建立日期:   2016年4月14日20:39:49
 ** 全局变量:
 ** 参数含义:   
 ** 返回值:
 ***********************************************************/
void bsWPubDebug(char *aLog_file_name,char *fmt,...)
{
	FILE *fp;
	char aFile_name[64];
	va_list ap;
	char aStr_tmp[256];
	char aTime_stamp[24+1];		/*时间戳*/
	struct  tm *systime;
    time_t  t;
    time(&t);
    systime = localtime(&t);
    sprintf(aTime_stamp,"%04d%02d%02d-%02d:%02d:%02d",
    					systime->tm_year+1900,systime->tm_mon+1,systime->tm_mday,
    					systime->tm_hour,systime->tm_min,systime->tm_sec);
	memset(aFile_name,0x00,sizeof(aFile_name));
	memset(aStr_tmp,0x00,sizeof(aStr_tmp));
	fp = NULL;
	sprintf(aFile_name,"./log/%s.log",aServ_name);
	fp = fopen(aFile_name,"a+");
	if(fp == NULL)
	{
		printf("打开文件[%s]失败",aFile_name);
		return;
	}
	va_start(ap,fmt);
	vsnprintf(aStr_tmp,sizeof(aStr_tmp),fmt,ap);
	va_end(ap);
	fprintf(fp,"[%s]FILE:[%s] %s\n",aTime_stamp,aLog_file_name,aStr_tmp);
	fclose(fp);
}

/*********************************************************
 ** 函数名  :   nConvertStrToHex(char *aSrc_str,int *iHex_val) 
 ** 功能    :   将字符串转换为十六进制值
 ** 作者    :   guojy
 ** 建立日期:   2016年4月28日11:13:01
 ** 全局变量:
 ** 参数含义:   
 ** 返回值:
 ***********************************************************/
int nConvertStrToHex(char *aSrc_str,int *iHex_val) 
{
	int iTmp,i,iPow_num;
	
	memset(&iTmp,0x00,sizeof(iTmp));
	for(i = strlen(aSrc_str) - 1;i >= 0;i--)
	{
		iPow_num = strlen(aSrc_str) - 1 - i;
		iTmp += (aSrc_str[i] - '0') * pow(16,iPow_num);
	}
	*iHex_val = iTmp;
	return 0;
}

/*********************************************************
 ** 函数名  :   int nFilterStrHexNum(char *aIn_str,char *aOut_str,int *iOut_len)
 ** 功能    :   将字符串中的字符型十六进制值转换为真正的十六进制值
 ** 作者    :   guojy
 ** 建立日期:   2016年4月28日11:13:01
 ** 全局变量:
 ** 参数含义:   
 ** 返回值:
 ***********************************************************/
int nFilterStrHexNum(char *aIn_str,char *aOut_str,int *iOut_len)
{
	char *pStart,*pEnd,*pTmp;
	char aStr_tmp[1024];
	int i,iLen = 0,iTmp;
	int iNum_idx = 0;
	pStart = aIn_str;
	
	while((pEnd = strchr(pStart,'{')) != NULL)
	{
		memset(aStr_tmp,0x00,sizeof(aStr_tmp));
		memcpy(aStr_tmp,pStart,pEnd - pStart);
		iNum_idx = pEnd - aIn_str;
		iLen += strlen(aStr_tmp);
		memcpy(aOut_str + iLen,aStr_tmp,pEnd - pStart);
		
		pStart = pEnd + 1;
		pEnd = strchr(pStart,'}');
		memset(aStr_tmp,0x00,sizeof(aStr_tmp));
		memcpy(aStr_tmp,pStart,pEnd - pStart);
		memset(&iTmp,0x00,sizeof(iTmp));
		nConvertStrToHex(aStr_tmp,&iTmp);
		aOut_str[iLen] = iTmp;
		iLen++;
		pStart = pEnd + 1;
	}
	memcpy(aOut_str+iLen,pStart,aIn_str + strlen(aIn_str) - pStart);
	iLen += (aIn_str + strlen(aIn_str) - pStart);
	*iOut_len = iLen;
	return 0;
}

