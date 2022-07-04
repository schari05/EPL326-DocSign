/**
* docsign.c: This is a program that uses OPENSSL for cryptographically signing
* any file that we give as an argument (argument[2]). If the argument[1] is -s it means 
* we run the signing mode and if the argument[1] is -v it means we run the validation 
* mode. In signing mode we get the document and compute the digital signature. We save 
* the signed document in a new file with the name of the previous file and .signed in the 
* end. If we already have private.pem and public.pem in the folder, we don't overwrite them
* but read them. In the validation mode the third argument has to be the signed document because
* we want to check if the signature is valid.
* How to compile : make
* How to run for mode 1: ./docsign -s file.txt
* How to run for mode 2: ./docsign -v file.txt.signed
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int OpenReadDocument(char *,char **,int *);
int digest(char[],int,unsigned char[]);

int main(int argc,char *argv[]){

	OpenSSL_add_all_algorithms();  
	//private key file
	FILE *fp;
	char *document=argv[2];
	EVP_MD_CTX md_ctx;
	char *signed_Doc=NULL;
	//terminal : ./docsign
	//the mode option and the file is missing
	if(argc!=3){
		printf("Usage: docsign -sv\n-s sign document\n-v validate signature\n");
		exit(-1);
	}else{
		//if we choose -s it means we have to sign the document
		if(strcmp(argv[1],"-s")==0){
			EVP_PKEY *privateK = EVP_PKEY_new();
			//rsa key with RSA
			RSA *rsaK = NULL;
			//to generate rsa key we must allocate EVP_KEY with EVP_PKEY_new 
			EVP_PKEY *signatureKey=EVP_PKEY_new();
			EVP_PKEY *validationKey=EVP_PKEY_new();
			//private.pem doesnt exists in folder
			if (access( "private.pem", 0 ) != 0 ){
				//create file for the private key
				fp = fopen("private.pem","wt");
			 	if (fp == NULL) {
					printf("Error: can't open file\n");
					exit (-1);
				}
				//create file for the public key
				FILE *publicKeyFile;
				publicKeyFile = fopen("public.pem","wt");
				if (publicKeyFile == NULL) {
					printf("Error: can't open file\n");
					exit (-1);
				}
				//generate keys : we create rsa with 		
				rsaK = RSA_generate_key(2048, RSA_F4, NULL, NULL);
				//we assign the new generated keys to EVP_KEY structure by calling EVP_PKEY_assign_RSA
				EVP_PKEY_assign_RSA(signatureKey, RSAPrivateKey_dup(rsaK));
		   		EVP_PKEY_assign_RSA(validationKey, RSAPublicKey_dup(rsaK));
//PEM_write_PrivateKey is used to save EVP_PKEY. fp: private key file, signatureKey: EVP_PKEY structure
				PEM_write_PrivateKey(fp,signatureKey,NULL,NULL,0,0,NULL);
//publicKeyFile: the file of the public key, validationKey: EVP_PKEY structure				
PEM_write_PUBKEY(publicKeyFile,validationKey);
			}else{
				//if we already have private.pem in the folder, read it
				fp = fopen("private.pem","r");
				if(fp==NULL){
					printf("Error: can't open file\n");
					return -1;
				}
				//load private key by using PEM_read_PrivateKey. fp: file of private key, &privateK: pointer to EVP_KEY structure
				PEM_read_PrivateKey(fp,&privateK,NULL,NULL);
				fclose(fp);
				//EVP_PKEY_get1_RSA: return the private key
				rsaK = EVP_PKEY_get1_RSA(privateK);
				//validate private rsa keys. returns 1 if rsa is a valid rsa key or 0.
				if(!RSA_check_key(rsaK)==1)
					printf("RSA key is not valid.\n");
			}
			//array of chars for digest
			unsigned char documentDigest[65];
			//array for signed document
			char signed_document[50];
			char *text = NULL;
			int textLength;
			//the size of rsa
			int rsalength = RSA_size(rsaK);
			uint8_t signature[rsalength];
			unsigned int signatureLength;
			size_t digestLENGTH = 64;
			
			//call functions openreaddocument and digest
			OpenReadDocument(document,&text,&textLength);
			digest(text,textLength,documentDigest);
			//signs the message digest
RSA_sign(NID_sha256,documentDigest,digestLENGTH,signature,&signatureLength,rsaK);
			//copy data of document to signed document
			strcpy(signed_document,document);
			//search for character / in signed document
			if(strchr(signed_document,'/')){
			//searches for the last occurrence of the character / and copy to signed document
			strcpy(signed_document,strrchr(signed_document,'/'));   
				strcpy(signed_document,signed_document+1);
			}
			//name of the new file(signed file)
			strcat(signed_document,".signed");
			//create the signed document file
			fp=fopen(signed_document,"wb");
			if(fp==NULL){
				printf("Error: can't open file\n");
				return (-1);
			}
			//write in the new signed file
			fprintf(fp,"%d\n",textLength);
			fprintf(fp,"%d\n",signatureLength);
			fwrite(text,textLength,1,fp);
			fwrite(signature,signatureLength,1,fp);
			//close the file
			fclose(fp);
			printf("Document %s is signed.  The signed document is: %s.\n",document,signed_document);
		
		//validation mode
		}else if(strcmp(argv[1],"-v")==0){
			//allocate EVP_PKEY with EVP_PKEY_new
			EVP_PKEY *publicK;
			RSA *rsa;
			publicK=EVP_PKEY_new();
			//get the signed document from command line
			signed_Doc = argv[2];
			//open file public.pem
			fp=fopen("public.pem","r");
			if(fp==NULL){
				printf("Error: can't open file\n");
				return (-1);
			}
			//read public key from file fp
			PEM_read_PUBKEY(fp,&publicK,NULL,NULL);
			//EVP_PKEY_get1_RSA: return the public key
			rsa=EVP_PKEY_get1_RSA(publicK);		
			fclose(fp);
			//data length and signature's length
			int textLength;
			int signatureLength;
			//open the signed document
			fp=fopen(signed_Doc,"rb");
			if(fp==NULL){
				printf("Error: can't open file %s\n",signed_Doc);
				return EXIT_FAILURE;
			}
			//read from the signed document
			fscanf(fp,"%d\n",&textLength);
			fscanf(fp,"%d\n",&signatureLength);
			char text[textLength];
			uint8_t signature[signatureLength];
			unsigned char text_digest[65];
			fread(text,1,textLength,fp);
			fread(signature,1,signatureLength,fp);
			digest(text,textLength,text_digest);
			//RSA_verify() verifies that the signature
			if(RSA_verify(NID_sha256,text_digest,64,signature,signatureLength,rsa)==1)
					printf("Digital signature is valid.\n");
				else
					printf("Digital signature is invalid.\n");
					
		}
	  
	}
}

//function OpenReadDocument
int OpenReadDocument(char *document,char **text,int *text_len){
	//open the file with data
	FILE *fp = NULL;
	fp=fopen(document,"r");
	if(fp==NULL){
		printf("Error: can't open file\n");
		return EXIT_FAILURE;
	}
	int max_length=10;
	int length=0;
	//data
	text[0]=(char *)malloc(sizeof(char)*max_length);
	//store the data from the file
	char c;
	while((c=fgetc(fp))!=EOF){
		text[0][length]=c;
		length++;
		if(length==max_length){
			max_length+=10;
			text[0]=(char *)realloc(*text,sizeof(char)*max_length);
		}
	}
	text[0]=(char *)realloc(*text,sizeof(char)*length);
	*text_len=length;
	fclose(fp);
	return EXIT_SUCCESS;
}

//function digest
int digest(char text[],int text_len,unsigned char document_digest[]){
	//allocate
	SHA256_CTX sha256;
	//initialize
	SHA256_Init(&sha256);
	//run over the data
	SHA256_Update(&sha256,text,text_len);
	//extract result
	unsigned char txt_dig[SHA_DIGEST_LENGTH];
	SHA256_Final(txt_dig,&sha256);
	int i;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
		sprintf((char *)document_digest + (i * 2), "%02x", txt_dig[i]);
	}
	return EXIT_SUCCESS;
}





