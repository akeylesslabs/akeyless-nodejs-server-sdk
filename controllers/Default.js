'use strict';

var utils = require('../utils/writer.js');
var Default = require('../service/DefaultService');

module.exports.assocRoleAm = function assocRoleAm (req, res, next) {
  var roleName = req.swagger.params['role-name'].value;
  var amName = req.swagger.params['am-name'].value;
  var token = req.swagger.params['token'].value;
  var subClaims = req.swagger.params['sub-claims'].value;
  Default.assocRoleAm(roleName,amName,token,subClaims)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.auth = function auth (req, res, next) {
  var accessId = req.swagger.params['access-id'].value;
  var accessType = req.swagger.params['access-type'].value;
  var accessKey = req.swagger.params['access-key'].value;
  var cloudId = req.swagger.params['cloud-id'].value;
  var ldap_proxy_url = req.swagger.params['ldap_proxy_url'].value;
  Default.auth(accessId,accessType,accessKey,cloudId,ldap_proxy_url)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.configure = function configure (req, res, next) {
  var accessId = req.swagger.params['access-id'].value;
  var accessKey = req.swagger.params['access-key'].value;
  var accessType = req.swagger.params['access-type'].value;
  var ldap_proxy_url = req.swagger.params['ldap_proxy_url'].value;
  var azure_ad_object_id = req.swagger.params['azure_ad_object_id'].value;
  Default.configure(accessId,accessKey,accessType,ldap_proxy_url,azure_ad_object_id)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethod = function createAuthMethod (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  Default.createAuthMethod(name,token,accessExpires,boundIps)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethodAwsIam = function createAuthMethodAwsIam (req, res, next) {
  var name = req.swagger.params['name'].value;
  var boundAWSAccountId = req.swagger.params['bound-AWS-account-id'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  var stsUrl = req.swagger.params['sts-url'].value;
  var boundArn = req.swagger.params['bound-arn'].value;
  var boundRoleName = req.swagger.params['bound-role-name'].value;
  var boundRoleId = req.swagger.params['bound-role-id'].value;
  var boundResourceId = req.swagger.params['bound-resource-id'].value;
  var boundUserName = req.swagger.params['bound-user-name'].value;
  var boundUserId = req.swagger.params['bound-user-id'].value;
  Default.createAuthMethodAwsIam(name,boundAWSAccountId,token,accessExpires,boundIps,stsUrl,boundArn,boundRoleName,boundRoleId,boundResourceId,boundUserName,boundUserId)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethodAzureAd = function createAuthMethodAzureAd (req, res, next) {
  var name = req.swagger.params['name'].value;
  var boundTenantId = req.swagger.params['bound-tenant-id'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  var issuer = req.swagger.params['issuer'].value;
  var jwksUri = req.swagger.params['jwks-uri'].value;
  var audience = req.swagger.params['audience'].value;
  var boundSpid = req.swagger.params['bound-spid'].value;
  var boundGroupId = req.swagger.params['bound-group-id'].value;
  var boundSubId = req.swagger.params['bound-sub-id'].value;
  var boundRgId = req.swagger.params['bound-rg-id'].value;
  var boundProviders = req.swagger.params['bound-providers'].value;
  var boundResourceTypes = req.swagger.params['bound-resource-types'].value;
  var boundResourceNames = req.swagger.params['bound-resource-names'].value;
  var boundResourceId = req.swagger.params['bound-resource-id'].value;
  Default.createAuthMethodAzureAd(name,boundTenantId,token,accessExpires,boundIps,issuer,jwksUri,audience,boundSpid,boundGroupId,boundSubId,boundRgId,boundProviders,boundResourceTypes,boundResourceNames,boundResourceId)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethodLdap = function createAuthMethodLdap (req, res, next) {
  var name = req.swagger.params['name'].value;
  var publicKeyFilePath = req.swagger.params['public-key-file-path'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  Default.createAuthMethodLdap(name,publicKeyFilePath,token,accessExpires,boundIps)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethodOauth2 = function createAuthMethodOauth2 (req, res, next) {
  var name = req.swagger.params['name'].value;
  var boundClientsIds = req.swagger.params['bound-clients-ids'].value;
  var issuer = req.swagger.params['issuer'].value;
  var jwksUri = req.swagger.params['jwks-uri'].value;
  var audience = req.swagger.params['audience'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  Default.createAuthMethodOauth2(name,boundClientsIds,issuer,jwksUri,audience,token,accessExpires,boundIps)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createAuthMethodSaml = function createAuthMethodSaml (req, res, next) {
  var name = req.swagger.params['name'].value;
  var idpMetadataUrl = req.swagger.params['idp-metadata-url'].value;
  var token = req.swagger.params['token'].value;
  var accessExpires = req.swagger.params['access-expires'].value;
  var boundIps = req.swagger.params['bound-ips'].value;
  Default.createAuthMethodSaml(name,idpMetadataUrl,token,accessExpires,boundIps)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createDynamicSecret = function createDynamicSecret (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  var metadata = req.swagger.params['metadata'].value;
  var key = req.swagger.params['key'].value;
  Default.createDynamicSecret(name,token,metadata,key)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createKey = function createKey (req, res, next) {
  var name = req.swagger.params['name'].value;
  var alg = req.swagger.params['alg'].value;
  var token = req.swagger.params['token'].value;
  var metadata = req.swagger.params['metadata'].value;
  var splitLevel = req.swagger.params['split-level'].value;
  var customerFrgId = req.swagger.params['customer-frg-id'].value;
  Default.createKey(name,alg,token,metadata,splitLevel,customerFrgId)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createPkiCertIssuer = function createPkiCertIssuer (req, res, next) {
  var name = req.swagger.params['name'].value;
  var signerKeyName = req.swagger.params['signer-key-name'].value;
  var ttl = req.swagger.params['ttl'].value;
  var token = req.swagger.params['token'].value;
  var allowedDomains = req.swagger.params['allowed-domains'].value;
  var allowedUriSans = req.swagger.params['allowed-uri-sans'].value;
  var allowSubdomains = req.swagger.params['allow-subdomains'].value;
  var notEnforceHostnames = req.swagger.params['not-enforce-hostnames'].value;
  var allowAnyName = req.swagger.params['allow-any-name'].value;
  var notRequireCn = req.swagger.params['not-require-cn'].value;
  var serverFlag = req.swagger.params['server-flag'].value;
  var clientFlag = req.swagger.params['client-flag'].value;
  var codeSigningFlag = req.swagger.params['code-signing-flag'].value;
  var keyUsage = req.swagger.params['key-usage'].value;
  var organizationUnits = req.swagger.params['organization-units'].value;
  var organizations = req.swagger.params['organizations'].value;
  var country = req.swagger.params['country'].value;
  var locality = req.swagger.params['locality'].value;
  var province = req.swagger.params['province'].value;
  var streetAddress = req.swagger.params['street-address'].value;
  var postalCode = req.swagger.params['postal-code'].value;
  var metadata = req.swagger.params['metadata'].value;
  Default.createPkiCertIssuer(name,signerKeyName,ttl,token,allowedDomains,allowedUriSans,allowSubdomains,notEnforceHostnames,allowAnyName,notRequireCn,serverFlag,clientFlag,codeSigningFlag,keyUsage,organizationUnits,organizations,country,locality,province,streetAddress,postalCode,metadata)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createRole = function createRole (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  var comment = req.swagger.params['comment'].value;
  Default.createRole(name,token,comment)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createSecret = function createSecret (req, res, next) {
  var name = req.swagger.params['name'].value;
  var value = req.swagger.params['value'].value;
  var token = req.swagger.params['token'].value;
  var metadata = req.swagger.params['metadata'].value;
  var key = req.swagger.params['key'].value;
  var multiline = req.swagger.params['multiline'].value;
  Default.createSecret(name,value,token,metadata,key,multiline)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.createSshCertIssuer = function createSshCertIssuer (req, res, next) {
  var name = req.swagger.params['name'].value;
  var signerKeyName = req.swagger.params['signer-key-name'].value;
  var allowedUsers = req.swagger.params['allowed-users'].value;
  var ttl = req.swagger.params['ttl'].value;
  var token = req.swagger.params['token'].value;
  var principals = req.swagger.params['principals'].value;
  var extensions = req.swagger.params['extensions'].value;
  var metadata = req.swagger.params['metadata'].value;
  Default.createSshCertIssuer(name,signerKeyName,allowedUsers,ttl,token,principals,extensions,metadata)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.decrypt = function decrypt (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var ciphertext = req.swagger.params['ciphertext'].value;
  var token = req.swagger.params['token'].value;
  var encryptionContext = req.swagger.params['encryption-context'].value;
  Default.decrypt(keyName,ciphertext,token,encryptionContext)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.decryptFile = function decryptFile (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var _in = req.swagger.params['in'].value;
  var token = req.swagger.params['token'].value;
  var out = req.swagger.params['out'].value;
  var encryptionContext = req.swagger.params['encryption-context'].value;
  Default.decryptFile(keyName,_in,token,out,encryptionContext)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.decryptPkcs1 = function decryptPkcs1 (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var ciphertext = req.swagger.params['ciphertext'].value;
  var token = req.swagger.params['token'].value;
  Default.decryptPkcs1(keyName,ciphertext,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.deleteAssoc = function deleteAssoc (req, res, next) {
  var assocId = req.swagger.params['assoc-id'].value;
  var token = req.swagger.params['token'].value;
  Default.deleteAssoc(assocId,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.deleteAuthMethod = function deleteAuthMethod (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.deleteAuthMethod(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.deleteItem = function deleteItem (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.deleteItem(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.deleteRole = function deleteRole (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.deleteRole(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.deleteRoleRule = function deleteRoleRule (req, res, next) {
  var roleName = req.swagger.params['role-name'].value;
  var path = req.swagger.params['path'].value;
  var token = req.swagger.params['token'].value;
  Default.deleteRoleRule(roleName,path,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.describeItem = function describeItem (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.describeItem(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.encrypt = function encrypt (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var plaintext = req.swagger.params['plaintext'].value;
  var token = req.swagger.params['token'].value;
  var encryptionContext = req.swagger.params['encryption-context'].value;
  Default.encrypt(keyName,plaintext,token,encryptionContext)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.encryptFile = function encryptFile (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var _in = req.swagger.params['in'].value;
  var token = req.swagger.params['token'].value;
  var out = req.swagger.params['out'].value;
  var encryptionContext = req.swagger.params['encryption-context'].value;
  Default.encryptFile(keyName,_in,token,out,encryptionContext)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.encryptPkcs1 = function encryptPkcs1 (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var plaintext = req.swagger.params['plaintext'].value;
  var token = req.swagger.params['token'].value;
  Default.encryptPkcs1(keyName,plaintext,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getAuthMethod = function getAuthMethod (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.getAuthMethod(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getCloudIdentity = function getCloudIdentity (req, res, next) {
  var token = req.swagger.params['token'].value;
  var azure_ad_object_id = req.swagger.params['azure_ad_object_id'].value;
  var url_safe = req.swagger.params['url_safe'].value;
  Default.getCloudIdentity(token,azure_ad_object_id,url_safe)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getDynamicSecretValue = function getDynamicSecretValue (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.getDynamicSecretValue(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getKubeExecCreds = function getKubeExecCreds (req, res, next) {
  var certIssuerName = req.swagger.params['cert-issuer-name'].value;
  var keyFilePath = req.swagger.params['key-file-path'].value;
  var token = req.swagger.params['token'].value;
  var commonName = req.swagger.params['common-name'].value;
  var altNames = req.swagger.params['alt-names'].value;
  var uriSans = req.swagger.params['uri-sans'].value;
  var outfile = req.swagger.params['outfile'].value;
  Default.getKubeExecCreds(certIssuerName,keyFilePath,token,commonName,altNames,uriSans,outfile)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getPkiCertificate = function getPkiCertificate (req, res, next) {
  var certIssuerName = req.swagger.params['cert-issuer-name'].value;
  var keyFilePath = req.swagger.params['key-file-path'].value;
  var token = req.swagger.params['token'].value;
  var commonName = req.swagger.params['common-name'].value;
  var altNames = req.swagger.params['alt-names'].value;
  var uriSans = req.swagger.params['uri-sans'].value;
  var outfile = req.swagger.params['outfile'].value;
  Default.getPkiCertificate(certIssuerName,keyFilePath,token,commonName,altNames,uriSans,outfile)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getRole = function getRole (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.getRole(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getRsaPublic = function getRsaPublic (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.getRsaPublic(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getSecretValue = function getSecretValue (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  Default.getSecretValue(name,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.getSshCertificate = function getSshCertificate (req, res, next) {
  var certUsername = req.swagger.params['cert-username'].value;
  var certIssuerName = req.swagger.params['cert-issuer-name'].value;
  var publicKeyFilePath = req.swagger.params['public-key-file-path'].value;
  var token = req.swagger.params['token'].value;
  var outfile = req.swagger.params['outfile'].value;
  Default.getSshCertificate(certUsername,certIssuerName,publicKeyFilePath,token,outfile)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.help = function help (req, res, next) {
  Default.help()
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.listAuthMethods = function listAuthMethods (req, res, next) {
  var token = req.swagger.params['token'].value;
  var paginationToken = req.swagger.params['pagination-token'].value;
  Default.listAuthMethods(token,paginationToken)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.listItems = function listItems (req, res, next) {
  var token = req.swagger.params['token'].value;
  var type = req.swagger.params['type'].value;
  var itemsTypes = req.swagger.params['ItemsTypes'].value;
  var filter = req.swagger.params['filter'].value;
  var path = req.swagger.params['path'].value;
  var paginationToken = req.swagger.params['pagination-token'].value;
  Default.listItems(token,type,itemsTypes,filter,path,paginationToken)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.listRoles = function listRoles (req, res, next) {
  var token = req.swagger.params['token'].value;
  var paginationToken = req.swagger.params['pagination-token'].value;
  Default.listRoles(token,paginationToken)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.setRoleRule = function setRoleRule (req, res, next) {
  var roleName = req.swagger.params['role-name'].value;
  var path = req.swagger.params['path'].value;
  var capability = req.swagger.params['capability'].value;
  var token = req.swagger.params['token'].value;
  Default.setRoleRule(roleName,path,capability,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.signPkcs1 = function signPkcs1 (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var message = req.swagger.params['message'].value;
  var token = req.swagger.params['token'].value;
  Default.signPkcs1(keyName,message,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.unconfigure = function unconfigure (req, res, next) {
  var token = req.swagger.params['token'].value;
  Default.unconfigure(token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.update = function update (req, res, next) {
  var token = req.swagger.params['token'].value;
  Default.update(token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.updateItem = function updateItem (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  var newName = req.swagger.params['new-name'].value;
  var newMetadata = req.swagger.params['new-metadata'].value;
  Default.updateItem(name,token,newName,newMetadata)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.updateRole = function updateRole (req, res, next) {
  var name = req.swagger.params['name'].value;
  var token = req.swagger.params['token'].value;
  var newName = req.swagger.params['new-name'].value;
  var newComment = req.swagger.params['new-comment'].value;
  Default.updateRole(name,token,newName,newComment)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.updateSecretVal = function updateSecretVal (req, res, next) {
  var name = req.swagger.params['name'].value;
  var value = req.swagger.params['value'].value;
  var token = req.swagger.params['token'].value;
  var key = req.swagger.params['key'].value;
  var multiline = req.swagger.params['multiline'].value;
  Default.updateSecretVal(name,value,token,key,multiline)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.uploadPkcs12 = function uploadPkcs12 (req, res, next) {
  var name = req.swagger.params['name'].value;
  var _in = req.swagger.params['in'].value;
  var passphrase = req.swagger.params['passphrase'].value;
  var token = req.swagger.params['token'].value;
  var metadata = req.swagger.params['metadata'].value;
  var splitLevel = req.swagger.params['split-level'].value;
  var customerFrgId = req.swagger.params['customer-frg-id'].value;
  var cert = req.swagger.params['cert'].value;
  Default.uploadPkcs12(name,_in,passphrase,token,metadata,splitLevel,customerFrgId,cert)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.uploadRsa = function uploadRsa (req, res, next) {
  var name = req.swagger.params['name'].value;
  var alg = req.swagger.params['alg'].value;
  var rsaKeyFilePath = req.swagger.params['rsa-key-file-path'].value;
  var token = req.swagger.params['token'].value;
  var cert = req.swagger.params['cert'].value;
  var metadata = req.swagger.params['metadata'].value;
  var splitLevel = req.swagger.params['split-level'].value;
  var customerFrgId = req.swagger.params['customer-frg-id'].value;
  Default.uploadRsa(name,alg,rsaKeyFilePath,token,cert,metadata,splitLevel,customerFrgId)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};

module.exports.verifyPkcs1 = function verifyPkcs1 (req, res, next) {
  var keyName = req.swagger.params['key-name'].value;
  var message = req.swagger.params['message'].value;
  var signature = req.swagger.params['signature'].value;
  var token = req.swagger.params['token'].value;
  Default.verifyPkcs1(keyName,message,signature,token)
    .then(function (response) {
      utils.writeJson(res, response);
    })
    .catch(function (response) {
      utils.writeJson(res, response);
    });
};
