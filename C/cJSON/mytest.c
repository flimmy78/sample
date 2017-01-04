#include <stdio.h>
#include "cJSON.h"

#if 0
{
    "id": "e90d519e3f2244bb83597cf434d857b3",
        "owner": "145454544452454",
        "source": "",
        "blockSize": 2048,
        "version": 0,
        "cipher": {
            "algorithm": "AES",
            "encryptedKey": "d4cd6b1c52b64b23b248b45ab240bf9ec1c81905fdb043a2871fb2087ce702aa",
            "mode": "CFB",
            "padding": "NoPadding"
        },
        "thumb": {
            "exists": "false",
            "size": "0"
        }
}
#endif
int main()
{
	cJSON *root,*cipher, *thumb;
    char szSource[8] = {0};
	root=cJSON_CreateObject();	
	cJSON_AddStringToObject(root, "id", "e90d519e3f2244bb83597cf434d857b3");
	cJSON_AddStringToObject(root, "owner", szSource);
	cJSON_AddStringToObject(root, "source", szSource);
	cJSON_AddNumberToObject(root,"block size",	2048);
	cJSON_AddNumberToObject(root,"version",	0);

    cipher = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "cipher", cipher);
	cJSON_AddStringToObject(cipher,"algorithm", "AES");
	cJSON_AddStringToObject(cipher,"encrypted", "d4cd6b1c52b64b23b248b45ab240bf9ec1c81905fdb043a2871fb2087ce702aa");
	cJSON_AddStringToObject(cipher,"mode", "CFB");
	cJSON_AddStringToObject(cipher,"padding", "NoPadding");

    thumb = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "thumb", thumb);
	cJSON_AddStringToObject(thumb,"exists", "false");
	cJSON_AddStringToObject(thumb, "size", "0");

	char *rendered=cJSON_Print(root);
    printf ("output:%s\n", rendered);

    root = cJSON_Parse(rendered);
    printf ("root:%d\n", root);
    char* pcId = cJSON_GetObjectItem(root,"id")->valuestring;
    printf ("pcId:%s\n", pcId);
	cJSON_Delete(root);

    return 0;
}
