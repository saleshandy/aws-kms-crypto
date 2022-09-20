const AWS = require("aws-sdk");
class AWSKMSCrypto {
  accessKeyId;
  secretAccessKey;
  region;
  KeyId;
  kmsClient;

  constructor({ accessKeyId, secretAccessKey, region, keyId }) {
    this.KeyId = keyId;
    this.kmsClient = new AWS.KMS({
      accessKeyId,
      secretAccessKey,
      region,
    });
  }
  encrypt(plainText) {
    return new Promise((resolve, reject) => {
      this.kmsClient.encrypt(
        {
          KeyId: this.KeyId,
          Plaintext: plainText,
        },
        (err, data) => {
          if (err) {
            reject(err + err.stack);
          } else {
            const { CiphertextBlob } = data;

            const encryptedBase64data = CiphertextBlob.toString("base64");
            resolve(encryptedBase64data);
          }
        }
      );
    });
  }

  decrypt(cipherText) {
    const buf = Buffer.from(cipherText, "base64");

    return new Promise((resolve, reject) => {
      this.kmsClient.decrypt(
        {
          CiphertextBlob: buf,
          KeyId: this.KeyId,
        },

        (err, data) => {
          if (err) {
            reject(err + err.stack);
          } else {
            const { Plaintext } = data;

            resolve(Plaintext.toString());
          }
        }
      );
    });
  }
}

module.exports = { AWSKMSCrypto };