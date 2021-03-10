# aws-kms-crypto
A Javascript library to encrypt and decrypt plain text using [AWS KMS service](https://aws.amazon.com/kms/) 

## How to use it 

`aws-kms-crypto` contains two class and both can be used to encrypt and/or decrypt any payload for separate scenarios. 

### Method 1
This method provides simple encryption and decryption flow without any access logging or validation.

    const {AWSKMSCrypto} = require('aws-kms-crypto');
    
    // create AWSKMSCrypto object by passing aws configuration 
    const kms = new AWSKMSCrypto({  
		keyId: <AWS_KMS_KEY_ID>,  
		accessKeyId: <AWS_ACCESS_KEY_ID>,
		secretAccessKey: <AWS_SECRET_ACCESS_KEY>
		region: <AWS_REGION_NAME>  
	});
	
	const plainText = "I am about it encrypt :(";
	
	// call encrypt function 
	const cipherText = await kms.encrypt(plainText);
	console.log(cipherText); 

	// call decrypt function 
	const  decryptedPlainText = await kms.decrypt(cipherText); 
	console.log(decryptedPlainText); 
	

### Method 2
This method provides strict validation and console logging on top of encryption and decryption function. It will validate payload and check for necessary details and after validating it will call encrypt/decrypt function. 

    const {AWSKMSValidatorAndLogger} = require('aws-kms-crypto');

    
    // create AWSKMSCrypto object by passing aws configuration 
    const kms = new AWSKMSValidatorAndLogger({  
		keyId: <AWS_KMS_KEY_ID>,  
		accessKeyId: <AWS_ACCESS_KEY_ID>,
		secretAccessKey: <AWS_SECRET_ACCESS_KEY>
		region: <AWS_REGION_NAME>  
	});
	
	const plainText = "I am about it encrypt :(";
	
	// call encrypt function 
	const cipherText = await kms.encryptToken({  
		tokenPayload: plainText,  
		ipAddress: "192.168.2.5",  
		user: "rutvik@saleshandy.com",  
		userRole: "Support User"
		tokenOwner: "vishal@saleshandy.com",  
		reason: kms.tokenUsageReason.tokenGenerated 
	});
	console.log(cipherText); 

	// call decrypt function 
	const decryptedPlainText = await kms.encryptToken({  
		encryptedTokenPayload: cipherText,  
		ipAddress: "192.168.2.5",  
		user: "rutvik@saleshandy.com",  
		userRole: "Support User"
		tokenOwner: "vishal@saleshandy.com",  
		reason: kms.tokenUsageReason.tokenGenerated 
	});
	console.log(decryptedPlainText); 
	


