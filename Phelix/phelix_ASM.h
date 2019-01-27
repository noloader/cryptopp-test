#ifndef _PHELIX_ASM_H_
#define _PHELIX_ASM_H_
    const char *PhelixAssembler_Name(void); /* name of the assembler used */
    u32b    PhelixCodeSize_ASM(void);		/* size of the assembler code */
    u32b    PhelixIncrementalCodeSize_ASM(void);
    /* perform the encryption/decryption operation */
    u32b    PhelixEncryptPacket_ASM(PhelixPacketParms);
    u32b    PhelixDecryptPacket_ASM(PhelixPacketParms);
    u32b    PhelixNop_ASM          (PhelixPacketParms);
	void	PhelixSetupKey_ASM	   (PhelixContext *ctx,const U08P keyPtr,
									u32b keySize,u32b ivSize,u32b macSize);
	void	PhelixSetupNonce_ASM   (PhelixContext *ctx,const U08P noncePtr);
	void	PhelixProcessAAD_ASM   (PhelixContext *ctx,const U08P aadPtr,u32b aadLen);
	void	PhelixEncryptBytes_ASM (PhelixContext *ctx,const U08P pt,U08P ct,u32b msgLen);
	void	PhelixDecryptBytes_ASM (PhelixContext *ctx,const U08P ct,U08P pt,u32b msgLen);
	void	PhelixFinalize_ASM	   (PhelixContext *ctx,U08P mac);
#endif