export class AWSKMSValidatorAndLogger extends AWSKMSCrypto {
    tokenUsageReason: Readonly<{
        tokenGenerated: string;
        tokenRefresh: string;
        createWatch: string;
        getMessage: string;
        modifyMessage: string;
        stopWatch: string;
        getMessageThreadAndId: string;
        sendMessage: string;
        draftMessage: string;
        createLabel: string;
        getBouncedMessages: string;
        getMessages: string;
        userHistory: string;
    }>;
    encryptToken({ tokenPayload, ipAddress, user, tokenOwner, reason, userRole, }: {
        tokenPayload: any;
        ipAddress: any;
        user: any;
        tokenOwner: any;
        reason: any;
        userRole: any;
    }): Promise<any>;
    decryptToken({ encryptedTokenPayload, ipAddress, user, tokenOwner, reason, userRole, }: {
        encryptedTokenPayload: any;
        ipAddress: any;
        user: any;
        tokenOwner: any;
        reason: any;
        userRole: any;
    }): Promise<any>;
    validator({ ipAddress, user, tokenOwner, reason, userRole }: {
        ipAddress: any;
        user: any;
        tokenOwner: any;
        reason: any;
        userRole: any;
    }): boolean;
    logger({ ipAddress, user, tokenOwner, reason, userRole }: {
        ipAddress: any;
        user: any;
        tokenOwner: any;
        reason: any;
        userRole: any;
    }): void;
}
import { AWSKMSCrypto } from "./aws-kms-crypto";
