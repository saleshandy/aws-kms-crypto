const { AWSKMSCrypto } = require("./aws-kms-crypto");
const logger = require("../logger/winston.config");

const encryptTextLimit = 4096;
const encryptionJoiner = "__SALESHANDY_ENCRYPTION_JOINER__";

class AWSKMSValidatorAndLogger extends AWSKMSCrypto {
  tokenUsageReason = Object.freeze({
    tokenGenerated: "Token generated",
    tokenRefresh: "Token Refresh",
    createWatch: "create watch for google account connected",
    getMessage: "Get message ",
    modifyMessage: "Modify message for set label",
    stopWatch: "Stop Watch",
    getMessageThreadAndId: "Get Thread ID and message thread",
    sendMessage: "Send message",
    draftMessage: "Get draft message",
    createLabel: "Create label",
    getBouncedMessages: "Get lists of bounce messages",
    getMessages: "Get lists of messages",
    userHistory: "Get user history",
  });
  constructor({ accessKeyId, secretAccessKey, region, keyId }) {
    super({ accessKeyId, secretAccessKey, region, keyId });
  }
  async encryptToken({
    tokenPayload,
    ipAddress,
    user,
    tokenOwner,
    reason,
    userRole,
  }) {
    try {
      const isCredentialsValid = this.validator({
        ipAddress,
        user,
        tokenOwner,
        reason,
        userRole,
      });

      if (!isCredentialsValid) {
        throw new Error(
          `Encryption payload invalid: ${JSON.stringify({
            ipAddress,
            user,
            tokenOwner,
            reason,
            userRole,
          })}`
        );
      }

      if (this.validateCipherText(tokenPayload)) {
        return await this.encrypt(tokenPayload);
      }

      /*
       * AWS KMS has size limit of 4KB plain text. Combination of AccessToken and Refresh token
       * can be exceeding this limit, so that we'll divide the object and encrypt it separately
       * and later store the encrypted payload in database by using encryption joiner (so later we can split it
       * and decrypt both the text separately)
       *
       * Since this size limit is not case for all the time, we want to avoid network
       * latency. Most of the time this payload will not exceed 4KB limit, so this code
       * will not be executing all the time. It's only for rare scenarios where payload size
       * is exceeded
       */

      const { firstHalfOfAccessTokenObj, remainingTokenPayloadObj } =
        this.divideAndStringifyCipherText(tokenPayload);

      const cipherTextForFirstHalfOfAccessToken = await this.encrypt(
        firstHalfOfAccessTokenObj
      );

      const cipherTextForRemainingTokenPayload = await this.encrypt(
        remainingTokenPayloadObj
      );

      return (
        cipherTextForFirstHalfOfAccessToken +
        encryptionJoiner +
        cipherTextForRemainingTokenPayload
      );
    } catch (e) {
      console.log(e);
      return e;
    }
  }

  async decryptToken({
    encryptedTokenPayload,
    ipAddress,
    user,
    tokenOwner,
    reason,
    userRole,
  }) {
    try {
      const isCredentialsValid = this.validator({
        ipAddress,
        user,
        tokenOwner,
        reason,
        userRole,
      });

      if (!isCredentialsValid) {
        throw new Error(
          `Decryption payload invalid: ${JSON.stringify({
            ipAddress,
            user,
            tokenOwner,
            reason,
            userRole,
          })}`
        );
      }

      if (!this.isTextIncludesEncryptionJoiner(encryptedTokenPayload)) {
        return await this.decrypt(encryptedTokenPayload);
      }

      // Since we are separately encrypting text which are more than 4KB
      // we are joining both cipher text with a predefined text joiner (__SALESHANDY_ENCRYPTION_JOINER__)
      // so we are checking if this encryption joiner text is available in cipher text
      // then that means it's basically 2 cipher text,
      // so we need to split it and decrypt them each separately

      const cipherArray = this.splitCipherTextByJoiner(encryptedTokenPayload);

      const cipherTextForFirstHalfOfAccessToken = await this.decrypt(
        cipherArray[0]
      );

      const cipherTextForRemainingTokenPayload = await this.decrypt(
        cipherArray[1]
      );

      return this.prepareDecryptResponse(
        cipherTextForFirstHalfOfAccessToken,
        cipherTextForRemainingTokenPayload
      );
    } catch (e) {
      console.log(`Error while decrypting token: ${e}`);
      return e;
    }
  }

  divideAndStringifyCipherText(plaintext) {
    const tokenPayload = JSON.parse(plaintext);
    const { accessToken, refreshToken, expiresIn } = tokenPayload;

    const firstHalfOfAccessToken = accessToken.substring(
      0,
      accessToken.length / 2
    );
    const secondHalfOfAccessToken = accessToken.substring(
      accessToken.length / 2
    );

    const firstHalfOfAccessTokenObj = JSON.stringify({
      accessToken: firstHalfOfAccessToken,
    });
    const remainingTokenPayloadObj = JSON.stringify({
      accessToken: secondHalfOfAccessToken,
      refreshToken,
      expiresIn,
    });

    return { firstHalfOfAccessTokenObj, remainingTokenPayloadObj };
  }

  validateCipherText(tokenPayload) {
    return tokenPayload.length < encryptTextLimit;
  }

  prepareDecryptResponse(cipherTextForFirstHalfOfAccessToken, cipherTextForRemainingTokenPayload) {
    const parsedACipherText = JSON.parse(cipherTextForFirstHalfOfAccessToken);
    const parsedBCipherText = JSON.parse(cipherTextForRemainingTokenPayload);

    const decryptedObj = {
      accessToken:
        parsedACipherText.accessToken + parsedBCipherText.accessToken,
      refreshToken: parsedBCipherText.refreshToken,
      expiresIn: parsedBCipherText.expiresIn,
    };

    return JSON.stringify(decryptedObj);
  }

  splitCipherTextByJoiner(cipherText) {
    return cipherText.split(encryptionJoiner);
  }

  isTextIncludesEncryptionJoiner(encryptedTokenPayload) {
    return encryptedTokenPayload.indexOf(encryptionJoiner) > -1;
  }

  validator({ ipAddress, user, tokenOwner, reason, userRole }) {
    let isCredentialsValid = false;
    if (ipAddress && user && tokenOwner && reason && userRole) {
      isCredentialsValid = true;
    }
    setTimeout(() => {
      this.logger({
        ipAddress,
        user,
        tokenOwner,
        reason,
        userRole,
      });
    }, 0);
    return isCredentialsValid;
  }

  logger({ ipAddress, user, tokenOwner, reason, userRole }) {
    const logJSON = JSON.stringify({
      ipAddress,
      user,
      tokenOwner,
      reason,
      userRole,
    });
    logger.info({
      level: "info",
      message: `${logJSON}`,
    });
  }
}

module.exports = { AWSKMSValidatorAndLogger };
