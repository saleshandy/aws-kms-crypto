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
  async encryptToken(
    tokenPayload
    // ipAddress,
    // user,
    // tokenOwner,
    // reason,
    // userRole,
  ) {
    try {
      tokenPayload = JSON.stringify({
        accessToken: `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`,
        refreshToken: `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`,
        expiresIn: 123123123,
      });
      // const isCredentialsValid = this.validator({
      //   ipAddress,
      //   user,
      //   tokenOwner,
      //   reason,
      //   userRole,
      // });

      // if (isCredentialsValid) {
      //   throw new Error(
      //     `Encryption payload invalid: ${JSON.stringify({
      //       ipAddress,
      //       user,
      //       tokenOwner,
      //       reason,
      //       userRole,
      //     })}`
      //   );
      // }

      if (this.isTextLengthInLimit(tokenPayload)) {
        // return await this.encrypt(tokenPayload);
        const a = await this.encrypt(tokenPayload);
        console.log(a);
        return a;
      }

      /**
       *
       * AWS KMS has size limit of 4KB plain text. Combination of AccessToken and Refresh token
       * can be exceeding this limit, so that we'll divide the object and encrypt it separately
       * and later store the encrypted payload in database by using encryption joiner (so later we can split it
       * and decrypt both the text separately)
       *
       * Since this size limit is not case for all the time, we want to avoid network
       * latency. Most of the time this payload will not exceed 4KB limit, so this code
       * will not be executing all the time. It's only for rare scenarios where payload size
       * is exceeded
       *
       */
      const { accessTokenObj, refreshTokenAndExpireInObj } =
        this.divideAndStringifyCipherText(tokenPayload);

      const aCipherText = await this.encrypt(accessTokenObj);

      const bCipherText = await this.encrypt(refreshTokenAndExpireInObj);

      console.log(aCipherText + encryptionJoiner + bCipherText);
      return aCipherText + encryptionJoiner + bCipherText;
    } catch (e) {
      console.log(e);
      return e;
    }
  }

  async decryptToken({
    encryptedTokenPayload,
    // ipAddress,
    // user,
    // tokenOwner,
    // reason,
    // userRole,
  }) {
    console.log(encryptedTokenPayload, "-------------");
    try {
      encryptedTokenPayload = `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__SALESHANDY_ENCRYPTION_JOINER__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`;
      // const isCredentialsValid = this.validator({
      //   ipAddress,
      //   user,
      //   tokenOwner,
      //   reason,
      //   userRole,
      // });

      // if (!isCredentialsValid) {
      //   throw new Error(
      //     `Decryption payload invalid: ${JSON.stringify({
      //       ipAddress,
      //       user,
      //       tokenOwner,
      //       reason,
      //       userRole,
      //     })}`
      //   );
      // }

      if (!this.isTextIncludesEncryptionJoiner(encryptedTokenPayload)) {
        const a = await this.decrypt(encryptedTokenPayload);
        console.log(a);
        return;
      }

      // Since we are separately encrypting text which are more than 4KB
      // we are joining both cipher text with a predefined text joiner (__SALESHANDY_ENCRYPTION_JOINER__)
      // so we are checking if this encryption joiner text is available in cipher text
      // then that means it's basically 2 cipher text,
      // so we need to split it and decrypt them each separately

      const cipherArray = this.splitCipherTextByJoiner(encryptedTokenPayload);

      const aCipherText = await this.decrypt(cipherArray[0]);

      const bCipherText = await this.decrypt(cipherArray[1]);

      return this.prepareDecryptResponse(aCipherText, bCipherText);
    } catch (e) {
      console.log(`Error while decrypting token: ${e}`);
      return e;
    }
  }

  divideAndStringifyCipherText(tokenPayload) {
    let { accessTokenObj, refreshTokenAndExpireInObj } =
      this.divideCipherText(tokenPayload);

    accessTokenObj = JSON.stringify(accessTokenObj);
    refreshTokenAndExpireInObj = JSON.stringify(refreshTokenAndExpireInObj);

    return { accessTokenObj, refreshTokenAndExpireInObj };
  }

  isTextLengthInLimit(tokenPayload) {
    console.log(tokenPayload.length, "---------length-----------");
    return tokenPayload.length <= encryptTextLimit;
  }

  divideCipherText(plaintext) {
    const tokenPayload = JSON.parse(plaintext);
    const { accessToken, refreshToken, expiresIn } = tokenPayload;

    return {
      accessTokenObj: { accessToken },
      refreshTokenAndExpireInObj: { refreshToken, expiresIn },
    };
  }

  prepareDecryptResponse(aCipherText, bCipherText) {
    const parsedACipherText = JSON.parse(aCipherText);
    const parsedBCipherText = JSON.parse(bCipherText);

    const decryptedObj = {
      accessToken: parsedACipherText.accessToken,
      refreshToken: parsedBCipherText.refreshToken,
      expiresIn: parsedBCipherText.expiresIn,
    };

    console.log(JSON.stringify(decryptedObj));
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
