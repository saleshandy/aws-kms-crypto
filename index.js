const { AWSKMSValidatorAndLogger } = require("./aws-kms/aws-kms-crypto-logger");
const { AWSKMSCrypto } = require("./aws-kms/aws-kms-crypto");

let awsEnc = new AWSKMSValidatorAndLogger({
  accessKeyId: "AKIA2KPEZEAO6FTGOBCN",
  secretAccessKey: "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",
  region: "us-west-2",
  keyId: "3f657e82-2902-47c7-ba1e-5ed810cf867c",
});

awsEnc.decryptToken({ encryptedTokenPayload: "Jsut" });

// module.exports = { AWSKMSValidatorAndLogger, AWSKMSCrypto };
