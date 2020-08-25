'use strict';


/**
 * Create an association between role and auth method
 * Create an association between role and auth method Options:   role-name -    The role name to associate   am-name -    The auth method name to associate   sub-claims -    key/val of sub claims, ex. group=admins,developers   token -    Access token
 *
 * roleName String The role name to associate
 * amName String The auth method name to associate
 * token String Access token
 * subClaims String key/val of sub claims, ex. group=admins,developers (optional)
 * returns ReplyObj
 **/
exports.assocRoleAm = function(roleName,amName,token,subClaims) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
 * Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication Options:   access-id -    Access ID   access-type -    Access Type (access_key/password/saml/ldap/azure_ad/aws_iam)   access-key -    Access key (relevant only for access-type=access_key)   admin-password -    Password (relevant only for access-type=password)   admin-email -    Email (relevant only for access-type=password)   cloud-id -    The cloued identity (relevant only for access-type=azure_ad,awd_im,auid)   ldap_proxy_url -    Address URL for LDAP proxy (relevant only for access-type=ldap)
 *
 * accessId String Access ID (optional)
 * accessType String Access Type (access_key/password/saml/ldap/azure_ad/aws_iam) (optional)
 * accessKey String Access key (relevant only for access-type=access_key) (optional)
 * adminPassword String Password (relevant only for access-type=password) (optional)
 * adminEmail String Email (relevant only for access-type=password) (optional)
 * cloudId String The cloued identity (relevant only for access-type=azure_ad,awd_im,auid) (optional)
 * ldap_proxy_url String Address URL for LDAP proxy (relevant only for access-type=ldap) (optional)
 * returns ReplyObj
 **/
exports.auth = function(accessId,accessType,accessKey,adminPassword,adminEmail,cloudId,ldap_proxy_url) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Configure client profile.
 * Configure client profile. Options:   access-id -    Access ID   access-key -    Access Key   admin-password -    Password (relevant only for access-type=password)   admin-email -    Email (relevant only for access-type=password)   access-type -    Access Type (access_key/password/azure_ad/saml/ldap/aws_iam)   ldap_proxy_url -    Address URL for ldap proxy (relevant only for access-type=ldap)   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)
 *
 * accessId String Access ID (optional)
 * accessKey String Access Key (optional)
 * adminPassword String Password (relevant only for access-type=password) (optional)
 * adminEmail String Email (relevant only for access-type=password) (optional)
 * accessType String Access Type (access_key/password/azure_ad/saml/ldap/aws_iam) (optional)
 * ldap_proxy_url String Address URL for ldap proxy (relevant only for access-type=ldap) (optional)
 * azure_ad_object_id String Azure Active Directory ObjectId (relevant only for access-type=azure_ad) (optional)
 * returns ReplyObj
 **/
exports.configure = function(accessId,accessKey,adminPassword,adminEmail,accessType,ldap_proxy_url,azure_ad_object_id) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method in the account
 * Create a new Auth Method in the account Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist with the IPs that the access is restricted to   token -    Access token
 *
 * name String Auth Method name
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist with the IPs that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethod = function(name,token,accessExpires,boundIps) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method that will be able to authenticate using AWS IAM credentials
 * Create a new Auth Method that will be able to authenticate using AWS IAM credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   sts-url -    sts URL   bound-AWS-account-id -    A list of AWS account-IDs that the access is restricted to   bound-arn -    A list of full arns that the access is restricted to   bound-role-name -    A list of full role-name that the access is restricted to   bound-role-id -    A list of full role ids that the access is restricted to   bound-resource-id -    A list of full resource ids that the access is restricted to   bound-user-name -    A list of full user-name that the access is restricted to   bound-user-id -    A list of full user ids that the access is restricted to   token -    Access token
 *
 * name String Auth Method name
 * boundAWSAccountId String A list of AWS account-IDs that the access is restricted to
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist of the IPs that the access is restricted to (optional)
 * stsUrl String sts URL (optional)
 * boundArn String A list of full arns that the access is restricted to (optional)
 * boundRoleName String A list of full role-name that the access is restricted to (optional)
 * boundRoleId String A list of full role ids that the access is restricted to (optional)
 * boundResourceId String A list of full resource ids that the access is restricted to (optional)
 * boundUserName String A list of full user-name that the access is restricted to (optional)
 * boundUserId String A list of full user ids that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethodAwsIam = function(name,boundAWSAccountId,token,accessExpires,boundIps,stsUrl,boundArn,boundRoleName,boundRoleId,boundResourceId,boundUserName,boundUserId) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials
 * Create a new Auth Method that will be able to authenticate using Azure Active Directory credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-tenant-id -    The Azure tenant id that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   bound-spid -    A list of service principal IDs that the access is restricted to   bound-group-id -    A list of group ids that the access is restricted to   bound-sub-id -    A list of subscription ids that the access is restricted to   bound-rg-id -    A list of resource groups that the access is restricted to   bound-providers -    A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)   bound-resource-types -    A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)   bound-resource-names -    A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).   bound-resource-id -    A list of full resource ids that the access is restricted to   token -    Access token
 *
 * name String Auth Method name
 * boundTenantId String The Azure tenant id that the access is restricted to
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist of the IPs that the access is restricted to (optional)
 * issuer String Issuer URL (optional)
 * jwksUri String The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. (optional)
 * audience String The audience in the JWT (optional)
 * boundSpid String A list of service principal IDs that the access is restricted to (optional)
 * boundGroupId String A list of group ids that the access is restricted to (optional)
 * boundSubId String A list of subscription ids that the access is restricted to (optional)
 * boundRgId String A list of resource groups that the access is restricted to (optional)
 * boundProviders String A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc) (optional)
 * boundResourceTypes String A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc) (optional)
 * boundResourceNames String A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc). (optional)
 * boundResourceId String A list of full resource ids that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethodAzureAd = function(name,boundTenantId,token,accessExpires,boundIps,issuer,jwksUri,audience,boundSpid,boundGroupId,boundSubId,boundRgId,boundProviders,boundResourceTypes,boundResourceNames,boundResourceId) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method that will be able to authenticate using LDAP
 * Create a new Auth Method that will be able to authenticate using LDAP Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   public-key-file-path -    A public key generated for LDAP authentication method on Akeyless [RSA2048]   token -    Access token
 *
 * name String Auth Method name
 * publicKeyFilePath String A public key generated for LDAP authentication method on Akeyless [RSA2048]
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist of the IPs that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethodLdap = function(name,publicKeyFilePath,token,accessExpires,boundIps) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method that will be able to authenticate using OpenId/OAuth2
 * Create a new Auth Method that will be able to authenticate using OpenId/OAuth2 Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-clients-ids -    The clients ids that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   token -    Access token
 *
 * name String Auth Method name
 * boundClientsIds String The clients ids that the access is restricted to
 * issuer String Issuer URL
 * jwksUri String The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.
 * audience String The audience in the JWT
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist of the IPs that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethodOauth2 = function(name,boundClientsIds,issuer,jwksUri,audience,token,accessExpires,boundIps) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Create a new Auth Method that will be able to authenticate using SAML
 * Create a new Auth Method that will be able to authenticate using SAML Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   idp-metadata-url -    IDP metadata url   token -    Access token
 *
 * name String Auth Method name
 * idpMetadataUrl String IDP metadata url
 * token String Access token
 * accessExpires String Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
 * boundIps String A CIDR whitelist of the IPs that the access is restricted to (optional)
 * returns ReplyObj
 **/
exports.createAuthMethodSaml = function(name,idpMetadataUrl,token,accessExpires,boundIps) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new dynamic secret item
 * Creates a new dynamic secret item Options:   name -    Dynamic secret name   metadata -    Metadata about the dynamic secret   key -    The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)   token -    Access token
 *
 * name String Dynamic secret name
 * token String Access token
 * metadata String Metadata about the dynamic secret (optional)
 * key String The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used) (optional)
 * returns ReplyObj
 **/
exports.createDynamicSecret = function(name,token,metadata,key) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new key
 * Creates a new key Options:   name -    Key name   alg -    Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]   metadata -    Metadata about the key   split-level -    The number of fragments that the item will be split into (not includes customer fragment)   customer-frg-id -    The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)   token -    Access token
 *
 * name String Key name
 * alg String Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]
 * token String Access token
 * metadata String Metadata about the key (optional)
 * splitLevel String The number of fragments that the item will be split into (not includes customer fragment) (optional)
 * customerFrgId String The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment) (optional)
 * returns ReplyObj
 **/
exports.createKey = function(name,alg,token,metadata,splitLevel,customerFrgId) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new PKI certificate issuer
 * Creates a new PKI certificate issuer Options:   name -    PKI certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-domains -    A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)   allowed-uri-sans -    A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)   allow-subdomains -    If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains   not-enforce-hostnames -    If set, any names are allowed for CN and SANs in the certificate and not only a valid host name   allow-any-name -    If set, clients can request certificates for any CN   not-require-cn -    If set, clients can request certificates without a CN   server-flag -    If set, certificates will be flagged for server auth use   client-flag -    If set, certificates will be flagged for client auth use   code-signing-flag -    If set, certificates will be flagged for code signing use   key-usage -    A comma-separated string or list of key usages   organization-units -    A comma-separated list of organizational units (OU) that will be set in the issued certificate   organizations -    A comma-separated list of organizations (O) that will be set in the issued certificate   country -    A comma-separated list of the country that will be set in the issued certificate   locality -    A comma-separated list of the locality that will be set in the issued certificate   province -    A comma-separated list of the province that will be set in the issued certificate   street-address -    A comma-separated list of the street address that will be set in the issued certificate   postal-code -    A comma-separated list of the postal code that will be set in the issued certificate   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token
 *
 * name String PKI certificate issuer name
 * signerKeyName String A key to sign the certificate with
 * ttl String The requested Time To Live for the certificate, use second units
 * token String Access token
 * allowedDomains String A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list) (optional)
 * allowedUriSans String A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list) (optional)
 * allowSubdomains String If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains (optional)
 * notEnforceHostnames String If set, any names are allowed for CN and SANs in the certificate and not only a valid host name (optional)
 * allowAnyName String If set, clients can request certificates for any CN (optional)
 * notRequireCn String If set, clients can request certificates without a CN (optional)
 * serverFlag String If set, certificates will be flagged for server auth use (optional)
 * clientFlag String If set, certificates will be flagged for client auth use (optional)
 * codeSigningFlag String If set, certificates will be flagged for code signing use (optional)
 * keyUsage String A comma-separated string or list of key usages (optional)
 * organizationUnits String A comma-separated list of organizational units (OU) that will be set in the issued certificate (optional)
 * organizations String A comma-separated list of organizations (O) that will be set in the issued certificate (optional)
 * country String A comma-separated list of the country that will be set in the issued certificate (optional)
 * locality String A comma-separated list of the locality that will be set in the issued certificate (optional)
 * province String A comma-separated list of the province that will be set in the issued certificate (optional)
 * streetAddress String A comma-separated list of the street address that will be set in the issued certificate (optional)
 * postalCode String A comma-separated list of the postal code that will be set in the issued certificate (optional)
 * metadata String A metadata about the issuer (optional)
 * returns ReplyObj
 **/
exports.createPkiCertIssuer = function(name,signerKeyName,ttl,token,allowedDomains,allowedUriSans,allowSubdomains,notEnforceHostnames,allowAnyName,notRequireCn,serverFlag,clientFlag,codeSigningFlag,keyUsage,organizationUnits,organizations,country,locality,province,streetAddress,postalCode,metadata) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new role
 * Creates a new role Options:   name -    Role name   comment -    Comment about the role   token -    Access token
 *
 * name String Role name
 * token String Access token
 * comment String Comment about the role (optional)
 * returns ReplyObj
 **/
exports.createRole = function(name,token,comment) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new secret item
 * Creates a new secret item Options:   name -    Secret name   value -    The secret value   metadata -    Metadata about the secret   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token
 *
 * name String Secret name
 * value String The secret value
 * token String Access token
 * metadata String Metadata about the secret (optional)
 * key String The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) (optional)
 * multiline Boolean The provided value is a multiline value (separated by '\\n') (optional)
 * returns ReplyObj
 **/
exports.createSecret = function(name,value,token,metadata,key,multiline) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Creates a new SSH certificate issuer
 * Creates a new SSH certificate issuer Options:   name -    SSH certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-users -    Users allowed to fetch the certificate, ex. root,ubuntu   principals -    Signed certificates with principal, ex. example_role1,example_role2   extensions -    Signed certificates with extensions, ex. permit-port-forwarding=\"\"   ttl -    The requested Time To Live for the certificate, use second units   metadata -    A metadata about the issuer   token -    Access token
 *
 * name String SSH certificate issuer name
 * signerKeyName String A key to sign the certificate with
 * allowedUsers String Users allowed to fetch the certificate, ex. root,ubuntu
 * ttl String The requested Time To Live for the certificate, use second units
 * token String Access token
 * principals String Signed certificates with principal, ex. example_role1,example_role2 (optional)
 * extensions String Signed certificates with extensions, ex. permit-port-forwarding=\"\" (optional)
 * metadata String A metadata about the issuer (optional)
 * returns ReplyObj
 **/
exports.createSshCertIssuer = function(name,signerKeyName,allowedUsers,ttl,token,principals,extensions,metadata) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Decrypts ciphertext into plaintext by using an AES key
 * Decrypts ciphertext into plaintext by using an AES key Options:   key-name -    The name of the key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token
 *
 * keyName String The name of the key to use in the decryption process
 * ciphertext String Ciphertext to be decrypted in base64 encoded format
 * token String Access token
 * encryptionContext String The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail (optional)
 * returns ReplyObj
 **/
exports.decrypt = function(keyName,ciphertext,token,encryptionContext) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Decrypts a file by using an AES key
 * Decrypts a file by using an AES key Options:   key-name -    The name of the key to use in the decryption process   in -    Path to the file to be decrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token
 *
 * keyName String The name of the key to use in the decryption process
 * _in String Path to the file to be decrypted. If not provided, the content will be taken from stdin
 * token String Access token
 * out String Path to the output file. If not provided, the output will be sent to stdout (optional)
 * encryptionContext String The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail (optional)
 * returns ReplyObj
 **/
exports.decryptFile = function(keyName,_in,token,out,encryptionContext) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
 * Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   token -    Access token
 *
 * keyName String The name of the RSA key to use in the decryption process
 * ciphertext String Ciphertext to be decrypted in base64 encoded format
 * token String Access token
 * returns ReplyObj
 **/
exports.decryptPkcs1 = function(keyName,ciphertext,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Delete an association between role and auth method
 * Delete an association between role and auth method Options:   assoc-id -    The association id to be deleted   token -    Access token
 *
 * assocId String The association id to be deleted
 * token String Access token
 * returns ReplyObj
 **/
exports.deleteAssoc = function(assocId,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Delete the Auth Method
 * Delete the Auth Method Options:   name -    Auth Method name   token -    Access token
 *
 * name String Auth Method name
 * token String Access token
 * returns ReplyObj
 **/
exports.deleteAuthMethod = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Delete an item or an item version
 * Delete an item or an item version Options:   name -    Item name   token -    Access token
 *
 * name String Item name
 * token String Access token
 * returns ReplyObj
 **/
exports.deleteItem = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Delete a role
 * Delete a role Options:   name -    Role name   token -    Access token
 *
 * name String Role name
 * token String Access token
 * returns ReplyObj
 **/
exports.deleteRole = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Delete a rule from a role
 * Delete a rule from a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   token -    Access token
 *
 * roleName String The role name to be updated
 * path String The path the rule refers to
 * token String Access token
 * returns ReplyObj
 **/
exports.deleteRoleRule = function(roleName,path,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Returns the item details
 * Returns the item details Options:   name -    Item name   token -    Access token
 *
 * name String Item name
 * token String Access token
 * returns ReplyObj
 **/
exports.describeItem = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Encrypts plaintext into ciphertext by using an AES key
 * Encrypts plaintext into ciphertext by using an AES key Options:   key-name -    The name of the key to use in the encryption process   plaintext -    Data to be encrypted   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token
 *
 * keyName String The name of the key to use in the encryption process
 * plaintext String Data to be encrypted
 * token String Access token
 * encryptionContext String name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail (optional)
 * returns ReplyObj
 **/
exports.encrypt = function(keyName,plaintext,token,encryptionContext) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Encrypts a file by using an AES key
 * Encrypts a file by using an AES key Options:   key-name -    The name of the key to use in the encryption process   in -    Path to the file to be encrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token
 *
 * keyName String The name of the key to use in the encryption process
 * _in String Path to the file to be encrypted. If not provided, the content will be taken from stdin
 * token String Access token
 * out String Path to the output file. If not provided, the output will be sent to stdout (optional)
 * encryptionContext String name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail (optional)
 * returns ReplyObj
 **/
exports.encryptFile = function(keyName,_in,token,out,encryptionContext) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
 * Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the encryption process   plaintext -    Data to be encrypted   token -    Access token
 *
 * keyName String The name of the RSA key to use in the encryption process
 * plaintext String Data to be encrypted
 * token String Access token
 * returns ReplyObj
 **/
exports.encryptPkcs1 = function(keyName,plaintext,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Returns an information about the Auth Method
 * Returns an information about the Auth Method Options:   name -    Auth Method name   token -    Access token
 *
 * name String Auth Method name
 * token String Access token
 * returns ReplyObj
 **/
exports.getAuthMethod = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam)
 * Get Cloud Identity Token (relevant only for access-type=azure_ad,aws_iam) Options:   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)   url_safe -    escapes the token so it can be safely placed inside a URL query   token -    Access token
 *
 * token String Access token
 * azure_ad_object_id String Azure Active Directory ObjectId (relevant only for access-type=azure_ad) (optional)
 * url_safe String escapes the token so it can be safely placed inside a URL query (optional)
 * returns ReplyObj
 **/
exports.getCloudIdentity = function(token,azure_ad_object_id,url_safe) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Get dynamic secret value
 * Get dynamic secret value Options:   name -    Dynamic secret name   token -    Access token
 *
 * name String Dynamic secret name
 * token String Access token
 * returns ReplyObj
 **/
exports.getDynamicSecretValue = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer
 * Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token
 *
 * certIssuerName String The name of the PKI certificate issuer
 * keyFilePath String The client public or private key file path (in case of a private key, it will be use to extract the public key)
 * token String Access token
 * commonName String The common name to be included in the PKI certificate (optional)
 * altNames String The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) (optional)
 * uriSans String The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) (optional)
 * outfile String Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension (optional)
 * returns ReplyObj
 **/
exports.getKubeExecCreds = function(certIssuerName,keyFilePath,token,commonName,altNames,uriSans,outfile) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Generates PKI certificate
 * Generates PKI certificate Options:   cert-issuer-name -    The name of the PKI certificate issuer   key-file-path -    The client public or private key file path (in case of a private key, it will be use to extract the public key)   common-name -    The common name to be included in the PKI certificate   alt-names -    The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   uri-sans -    The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token
 *
 * certIssuerName String The name of the PKI certificate issuer
 * keyFilePath String The client public or private key file path (in case of a private key, it will be use to extract the public key)
 * token String Access token
 * commonName String The common name to be included in the PKI certificate (optional)
 * altNames String The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) (optional)
 * uriSans String The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list) (optional)
 * outfile String Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension (optional)
 * returns ReplyObj
 **/
exports.getPkiCertificate = function(certIssuerName,keyFilePath,token,commonName,altNames,uriSans,outfile) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Get role details
 * Get role details Options:   name -    Role name   token -    Access token
 *
 * name String Role name
 * token String Access token
 * returns ReplyObj
 **/
exports.getRole = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Obtain the public key from a specific RSA private key
 * Obtain the public key from a specific RSA private key Options:   name -    Name of key to be created   token -    Access token
 *
 * name String Name of key to be created
 * token String Access token
 * returns ReplyObj
 **/
exports.getRsaPublic = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Get static secret value
 * Get static secret value Options:   name -    Secret name   token -    Access token
 *
 * name String Secret name
 * token String Access token
 * returns ReplyObj
 **/
exports.getSecretValue = function(name,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Generates SSH certificate
 * Generates SSH certificate Options:   cert-username -    The username to sign in the SSH certificate   cert-issuer-name -    The name of the SSH certificate issuer   public-key-file-path -    SSH public key   outfile -    Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension   token -    Access token
 *
 * certUsername String The username to sign in the SSH certificate
 * certIssuerName String The name of the SSH certificate issuer
 * publicKeyFilePath String SSH public key
 * token String Access token
 * outfile String Output file path with the certificate. If not provided, the file with the certificate will be created in the same location of the provided public key with the -cert extension (optional)
 * returns ReplyObj
 **/
exports.getSshCertificate = function(certUsername,certIssuerName,publicKeyFilePath,token,outfile) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * help text
 * help text
 *
 * returns ReplyObj
 **/
exports.help = function() {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Returns a list of all the Auth Methods in the account
 * Returns a list of all the Auth Methods in the account Options:   pagination-token -    Next page reference   token -    Access token
 *
 * token String Access token
 * paginationToken String Next page reference (optional)
 * returns ReplyObj
 **/
exports.listAuthMethods = function(token,paginationToken) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Returns a list of all accessible items
 * Returns a list of all accessible items Options:   type -    The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]   ItemsTypes -    ItemsTypes   filter -    Filter by item name or part of it   path -    Path to folder   pagination-token -    Next page reference   token -    Access token
 *
 * token String Access token
 * type String The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret] (optional)
 * itemsTypes String ItemsTypes (optional)
 * filter String Filter by item name or part of it (optional)
 * path String Path to folder (optional)
 * paginationToken String Next page reference (optional)
 * returns ReplyObj
 **/
exports.listItems = function(token,type,itemsTypes,filter,path,paginationToken) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Returns a list of all roles in the account
 * Returns a list of all roles in the account Options:   pagination-token -    Next page reference   token -    Access token
 *
 * token String Access token
 * paginationToken String Next page reference (optional)
 * returns ReplyObj
 **/
exports.listRoles = function(token,paginationToken) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Set a rule to a role
 * Set a rule to a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   capability -    List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]   token -    Access token
 *
 * roleName String The role name to be updated
 * path String The path the rule refers to
 * capability String List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]
 * token String Access token
 * returns ReplyObj
 **/
exports.setRoleRule = function(roleName,path,capability,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
 * Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the signing process   message -    The message to be signed   token -    Access token
 *
 * keyName String The name of the RSA key to use in the signing process
 * message String The message to be signed
 * token String Access token
 * returns ReplyObj
 **/
exports.signPkcs1 = function(keyName,message,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Remove Configuration of client profile.
 * Remove Configuration of client profile. Options:   token -    Access token
 *
 * token String Access token
 * returns ReplyObj
 **/
exports.unconfigure = function(token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Update a new AKEYLESS CLI version
 * Update a new AKEYLESS CLI version Options:   token -    Access token
 *
 * token String Access token
 * returns ReplyObj
 **/
exports.update = function(token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Update item name and metadata
 * Update item name and metadata Options:   name -    Current item name   new-name -    New item name   new-metadata -    New item metadata   token -    Access token
 *
 * name String Current item name
 * token String Access token
 * newName String New item name (optional)
 * newMetadata String New item metadata (optional)
 * returns ReplyObj
 **/
exports.updateItem = function(name,token,newName,newMetadata) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Update role details
 * Update role details Options:   name -    Role name   new-name -    New Role name   new-comment -    New comment about the role   token -    Access token
 *
 * name String Role name
 * token String Access token
 * newName String New Role name (optional)
 * newComment String New comment about the role (optional)
 * returns ReplyObj
 **/
exports.updateRole = function(name,token,newName,newComment) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Update static secret value
 * Update static secret value Options:   name -    Secret name   value -    The new secret value   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token
 *
 * name String Secret name
 * value String The new secret value
 * token String Access token
 * key String The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) (optional)
 * multiline Boolean The provided value is a multiline value (separated by '\\n') (optional)
 * returns ReplyObj
 **/
exports.updateSecretVal = function(name,value,token,key,multiline) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Upload a PKCS#12 key and certificates
 * Upload a PKCS#12 key and certificates Options:   name -    Name of key to be created   in -    PKCS#12 input file (private key and certificate only)   passphrase -    Passphrase to unlock the pkcs#12 bundle   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   cert -    Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file   token -    Access token
 *
 * name String Name of key to be created
 * _in String PKCS#12 input file (private key and certificate only)
 * passphrase String Passphrase to unlock the pkcs#12 bundle
 * token String Access token
 * metadata String A metadata about the key (optional)
 * splitLevel String The number of fragments that the item will be split into (optional)
 * customerFrgId String The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) (optional)
 * cert String Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file (optional)
 * returns ReplyObj
 **/
exports.uploadPkcs12 = function(name,_in,passphrase,token,metadata,splitLevel,customerFrgId,cert) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Upload RSA key
 * Upload RSA key Options:   name -    Name of key to be created   alg -    Key type. options- [RSA1024, RSA2048]   rsa-key-file-path -    RSA private key file path   cert -    Path to a file that contain the certificate in a PEM format.   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   token -    Access token
 *
 * name String Name of key to be created
 * alg String Key type. options- [RSA1024, RSA2048]
 * rsaKeyFilePath String RSA private key file path
 * token String Access token
 * cert String Path to a file that contain the certificate in a PEM format. (optional)
 * metadata String A metadata about the key (optional)
 * splitLevel String The number of fragments that the item will be split into (optional)
 * customerFrgId String The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) (optional)
 * returns ReplyObj
 **/
exports.uploadRsa = function(name,alg,rsaKeyFilePath,token,cert,metadata,splitLevel,customerFrgId) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Verifies an RSA PKCS#1 v1.5 signature
 * Verifies an RSA PKCS#1 v1.5 signature Options:   key-name -    The name of the RSA key to use in the verification process   message -    The message to be verified   signature -    The message's signature   token -    Access token
 *
 * keyName String The name of the RSA key to use in the verification process
 * message String The message to be verified
 * signature String The message's signature
 * token String Access token
 * returns ReplyObj
 **/
exports.verifyPkcs1 = function(keyName,message,signature,token) {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = {
  "response" : "{}",
  "command" : "command",
  "status" : "status",
  "token" : "token"
};
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}

