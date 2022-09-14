const { AWSKMSCrypto } = require("./aws-kms-crypto");
const logger = require("../logger/winston.config");

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

      if (isCredentialsValid) {
        return await this.encrypt(tokenPayload);
      } else {
        throw new Error("Credentials Invalid");
      }
    } catch (e) {
      console.log(e);
      return "Invalid Credentials";
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
      if (isCredentialsValid) {
        try {
          return await this.decrypt(encryptedTokenPayload);
        } catch (e) {
          throw new Error("Error while decrypting token: ", e);
        }
      } else {
        throw new Error("Decryption payload invalid");
      }
    } catch (e) {
      console.log(e);
      return "Error while decrypting token: ", e;
    }
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
