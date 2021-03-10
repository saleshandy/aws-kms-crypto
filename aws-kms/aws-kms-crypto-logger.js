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
  constructor({ accessKeyId, secretAccessKey, region, KeyId }) {
    super({ accessKeyId, secretAccessKey, region, KeyId });
  }
  async encryptToken({
    tokenPayload,
    ipAddress,
    shUser,
    tokenOwner,
    reason,
    role,
  }) {
    try {
      const isCredentialsValid = this.validator({
        ipAddress,
        shUser,
        tokenOwner,
        reason,
        role,
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
    shUser,
    tokenOwner,
    reason,
    role,
  }) {
    try {
      const isCredentialsValid = this.validator({
        ipAddress,
        shUser,
        tokenOwner,
        reason,
        role,
      });
      if (isCredentialsValid) {
        try {
          return await this.decrypt(encryptedTokenPayload);
        } catch (e) {
          throw new Error("Invalid refresh token");
        }
      } else {
        throw new Error("Credentials Invalid");
      }
    } catch (e) {
      console.log(e);
      return "Credentials Invalid";
    }
  }

  validator({ ipAddress, shUser, tokenOwner, reason, role }) {
    let isCredentialsValid = false;
    if (ipAddress && shUser && tokenOwner && reason && role) {
      isCredentialsValid = true;
    }
    setTimeout(() => {
      this.logger({
        ipAddress,
        shUser,
        tokenOwner,
        reason,
        role,
      });
    }, 0);
    return isCredentialsValid;
  }

  logger({ ipAddress, shUser, tokenOwner, reason, role }) {
    const logJSON = JSON.stringify({
      ipAddress,
      shUser,
      tokenOwner,
      reason,
      role,
    });
    logger.info({
      level: "info",
      message: `${logJSON}`,
    });
  }
}

module.exports = { AWSKMSValidatorAndLogger };
