export class AWSKMSCrypto {
    constructor({ accessKeyId, secretAccessKey, region, keyId }: {
        accessKeyId: any;
        secretAccessKey: any;
        region: any;
        keyId: any;
    });
    accessKeyId: any;
    secretAccessKey: any;
    region: any;
    KeyId: any;
    kmsClient: AWS.KMS;
    encrypt(plainText: any): any;
    decrypt(cipherText: any): any;
}
import AWS = require("aws-sdk");
